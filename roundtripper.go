package fastls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/FastTLS/fastls/internal/compiler"
	"github.com/FastTLS/fastls/profile"
	"github.com/FastTLS/ftransport"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

type duplexKey struct{}

type roundTripper struct {
	KeepAlive            bool
	Lifetime             context.Context
	VerifyTLS            bool
	TLSRootCAs           *x509.CertPool
	Profile              *profile.Spec
	FingerprintUserAgent string
	Fingerprint          Fingerprint
	UserAgent            string
	Cookies              []Cookie
	headerOrder          []string
	pseudoHeaderOrder    []string
	http2Settings        *ftransport.HTTP2Config
	dialer               proxy.ContextDialer

	mu                sync.Mutex
	cachedTransports  map[string]http.RoundTripper
	cachedProtocols   map[string]ftransport.Protocol
	pendingConnection map[string]ftransport.DialResult
	transportGate     chan struct{}
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("fastls: nil request or URL")
	}
	req = req.Clone(req.Context())
	for _, properties := range rt.Cookies {
		req.AddCookie(&http.Cookie{
			Name: properties.Name, Value: properties.Value,
			Path: properties.Path, Domain: properties.Domain,
			Expires: properties.JSONExpires.Time, RawExpires: properties.RawExpires,
			MaxAge: properties.MaxAge, HttpOnly: properties.HTTPOnly,
			Secure: properties.Secure, Raw: properties.Raw, Unparsed: properties.Unparsed,
		})
	}
	if _, exists := req.Header["User-Agent"]; !exists && rt.UserAgent != "" {
		req.Header.Set("User-Agent", rt.UserAgent)
	}
	if rt.Profile != nil && req.Header.Get("User-Agent") == "" {
		req.Header["User-Agent"] = []string{}
	}

	key := req.URL.Scheme + "://" + rt.dialAddress(req)
	transport, protocol, err := rt.getTransport(req, key)
	if err != nil {
		return nil, err
	}
	if req.Context().Value(duplexKey{}) == true && protocol != ftransport.ProtocolHTTP2 {
		return nil, errors.New("duplex requires HTTP/2; negotiated protocol is unsupported")
	}
	response, err := transport.RoundTrip(req)
	if err != nil && req.Context().Err() != nil {
		// net/http may keep a dial running after its initiating request is
		// cancelled so another request can use the result. A session-level
		// connect deadline must instead release a stalled proxy handshake.
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
	return response, err
}

func (rt *roundTripper) getTransport(req *http.Request, key string) (http.RoundTripper, ftransport.Protocol, error) {
	rt.mu.Lock()
	transport, protocol := rt.cachedTransports[key], rt.cachedProtocols[key]
	gate := rt.transportGate
	rt.mu.Unlock()
	if transport != nil {
		return transport, protocol, nil
	}
	select {
	case gate <- struct{}{}:
	case <-req.Context().Done():
		return nil, 0, req.Context().Err()
	}
	defer func() { <-gate }()

	rt.mu.Lock()
	transport, protocol = rt.cachedTransports[key], rt.cachedProtocols[key]
	origins := len(rt.cachedTransports)
	rt.mu.Unlock()
	if transport != nil {
		return transport, protocol, nil
	}
	if rt.KeepAlive && origins >= 128 {
		return nil, 0, errors.New("session origin limit exceeded (128)")
	}

	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		protocol = ftransport.ProtocolHTTP1
	case "https":
		if rt.Fingerprint != nil && !rt.Fingerprint.IsEmpty() && strings.HasPrefix(rt.Fingerprint.Value(), "q") {
			h3 := newHTTP3Transport(rt.Fingerprint, rt.UserAgent, rt.Cookies, rt.dialer)
			rt.cacheTransport(key, h3, 0)
			return h3, 0, nil
		}
		result, err := rt.openTLS(req.Context(), "tcp", rt.dialAddress(req), nil)
		if err != nil {
			return nil, 0, err
		}
		switch result.NegotiatedProtocol {
		case "h2":
			protocol = ftransport.ProtocolHTTP2
		case "", "http/1.1":
			protocol = ftransport.ProtocolHTTP1
		default:
			_ = result.Conn.Close()
			return nil, 0, fmt.Errorf("negotiated unsupported application protocol %q", result.NegotiatedProtocol)
		}
		rt.mu.Lock()
		rt.pendingConnection[key] = result
		rt.mu.Unlock()
	default:
		return nil, 0, fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	config := rt.transportConfig(protocol)
	config.DialContext = func(ctx context.Context, request ftransport.DialRequest) (ftransport.DialResult, error) {
		return rt.dialForTransport(ctx, key, protocol, request)
	}
	created, err := ftransport.NewTransport(config)
	if err != nil {
		rt.mu.Lock()
		pending := rt.pendingConnection[key]
		delete(rt.pendingConnection, key)
		rt.mu.Unlock()
		if pending.Conn != nil {
			_ = pending.Conn.Close()
		}
		return nil, 0, err
	}
	rt.cacheTransport(key, created, protocol)
	return created, protocol, nil
}

func (rt *roundTripper) transportConfig(protocol ftransport.Protocol) ftransport.Config {
	config := ftransport.Config{
		Protocols: []ftransport.Protocol{protocol},
		Pool: ftransport.PoolConfig{
			MaxConnectionsPerHost: 8,
			IdleConnectionTimeout: 90 * time.Second,
		},
	}
	if protocol == ftransport.ProtocolHTTP1 {
		config.HTTP1.HeaderOrder = slices.Clone(rt.headerOrder)
		return config
	}
	if rt.http2Settings != nil {
		config.HTTP2 = *rt.http2Settings
		config.HTTP2.InitialSettings.Values = slices.Clone(rt.http2Settings.InitialSettings.Values)
		config.HTTP2.PriorityFrames = slices.Clone(rt.http2Settings.PriorityFrames)
		if rt.http2Settings.HeaderPriority != nil {
			priority := *rt.http2Settings.HeaderPriority
			config.HTTP2.HeaderPriority = &priority
		}
	}
	config.HTTP2.HeaderOrder = slices.Clone(rt.headerOrder)
	config.HTTP2.PseudoHeaderOrder = make([]ftransport.PseudoHeader, len(rt.pseudoHeaderOrder))
	for i, name := range rt.pseudoHeaderOrder {
		config.HTTP2.PseudoHeaderOrder[i] = ftransport.PseudoHeader(name)
	}
	return config
}

func (rt *roundTripper) dialForTransport(ctx context.Context, key string, protocol ftransport.Protocol, request ftransport.DialRequest) (ftransport.DialResult, error) {
	rt.mu.Lock()
	if pending, ok := rt.pendingConnection[key]; ok {
		delete(rt.pendingConnection, key)
		rt.mu.Unlock()
		return pending, nil
	}
	rt.mu.Unlock()
	if !request.TLS {
		conn, err := rt.dialer.DialContext(ctx, request.Network, request.Address)
		return ftransport.DialResult{Conn: conn}, err
	}
	return rt.openTLS(ctx, request.Network, request.Address, []string{protocol.String()})
}

func (rt *roundTripper) openTLS(ctx context.Context, network, address string, alpn []string) (ftransport.DialResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if rt.Lifetime != nil {
		stop := context.AfterFunc(rt.Lifetime, cancel)
		defer stop()
	}
	rawConn, err := rt.dialer.DialContext(ctx, network, address)
	if err != nil {
		return ftransport.DialResult{}, err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}

	if rt.Profile == nil && (rt.Fingerprint == nil || rt.Fingerprint.IsEmpty()) {
		if len(alpn) == 0 {
			alpn = []string{"h2", "http/1.1"}
		}
		conn := tls.Client(rawConn, &tls.Config{
			ServerName: host, RootCAs: rt.TLSRootCAs,
			InsecureSkipVerify: !rt.VerifyTLS, NextProtos: slices.Clone(alpn),
		})
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return ftransport.DialResult{}, err
		}
		state := conn.ConnectionState()
		return ftransport.DialResult{Conn: conn, NegotiatedProtocol: state.NegotiatedProtocol, TLSState: &state}, nil
	}

	var spec *utls.ClientHelloSpec
	if rt.Profile != nil {
		spec, err = compiler.TLS(*rt.Profile)
	} else {
		spec, err = StringToSpec(rt.Fingerprint.Value(), rt.protocolUserAgent())
	}
	if err != nil {
		_ = rawConn.Close()
		return ftransport.DialResult{}, err
	}
	conn := utls.UClient(rawConn, &utls.Config{
		ServerName: host, OmitEmptyPsk: true,
		InsecureSkipVerify: !rt.VerifyTLS, RootCAs: rt.TLSRootCAs,
	}, utls.HelloCustom)
	if err := conn.ApplyPreset(spec); err != nil {
		_ = conn.Close()
		return ftransport.DialResult{}, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return ftransport.DialResult{}, fmt.Errorf("uTLS handshake: %w", err)
	}
	state := normalizeUTLSState(conn.ConnectionState())
	return ftransport.DialResult{Conn: conn, NegotiatedProtocol: state.NegotiatedProtocol, TLSState: &state}, nil
}

func normalizeUTLSState(state utls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version: state.Version, HandshakeComplete: state.HandshakeComplete,
		DidResume: state.DidResume, CipherSuite: state.CipherSuite,
		NegotiatedProtocol:         state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual: state.NegotiatedProtocolIsMutual,
		ServerName:                 state.ServerName, PeerCertificates: state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse, TLSUnique: state.TLSUnique,
		ECHAccepted: state.ECHAccepted,
	}
}

func (rt *roundTripper) cacheTransport(key string, transport http.RoundTripper, protocol ftransport.Protocol) {
	rt.mu.Lock()
	rt.cachedTransports[key] = transport
	rt.cachedProtocols[key] = protocol
	rt.mu.Unlock()
}

func (rt *roundTripper) dialAddress(req *http.Request) string {
	if host, port, err := net.SplitHostPort(req.URL.Host); err == nil {
		return net.JoinHostPort(host, port)
	}
	port := "443"
	if req.URL.Scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(req.URL.Hostname(), port)
}

// stdlibTransportAdapter remains as a compatibility seam for internal tests
// and callers that supplied a standard transport before the migration.
type stdlibTransportAdapter struct{ transport *http.Transport }

func (a *stdlibTransportAdapter) RoundTrip(req *http.Request) (*http.Response, error) {
	return a.transport.RoundTrip(req)
}

func (rt *roundTripper) CloseIdleConnections() {
	rt.mu.Lock()
	pending := rt.pendingConnection
	rt.pendingConnection = make(map[string]ftransport.DialResult)
	transports := make([]http.RoundTripper, 0, len(rt.cachedTransports))
	for key, transport := range rt.cachedTransports {
		transports = append(transports, transport)
		stats, tracked := transport.(interface{ Stats() ftransport.Stats })
		if !tracked || stats.Stats().Active == 0 {
			delete(rt.cachedTransports, key)
			delete(rt.cachedProtocols, key)
		}
	}
	rt.mu.Unlock()
	for _, result := range pending {
		if result.Conn != nil {
			_ = result.Conn.Close()
		}
	}
	for _, transport := range transports {
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func newRoundTripper(browser browser, dialers ...proxy.ContextDialer) http.RoundTripper {
	dialer := proxy.ContextDialer(proxy.Direct)
	if len(dialers) > 0 && dialers[0] != nil {
		dialer = dialers[0]
	}
	return &roundTripper{
		KeepAlive: browser.KeepAlive, Lifetime: browser.Lifetime,
		VerifyTLS: browser.VerifyTLS, TLSRootCAs: browser.TLSRootCAs,
		Profile: browser.Profile, Fingerprint: browser.Fingerprint,
		UserAgent: browser.UserAgent, FingerprintUserAgent: browser.FingerprintUserAgent,
		Cookies: browser.Cookies, headerOrder: slices.Clone(browser.HeaderOrderKeys),
		pseudoHeaderOrder: slices.Clone(browser.PHeaderOrderKeys),
		http2Settings:     browser.HTTP2Settings, dialer: dialer,
		cachedTransports:  make(map[string]http.RoundTripper),
		cachedProtocols:   make(map[string]ftransport.Protocol),
		pendingConnection: make(map[string]ftransport.DialResult),
		transportGate:     make(chan struct{}, 1),
	}
}

func (rt *roundTripper) protocolUserAgent() string {
	if rt.FingerprintUserAgent != "" {
		return rt.FingerprintUserAgent
	}
	return rt.UserAgent
}

var _ http.RoundTripper = (*roundTripper)(nil)
