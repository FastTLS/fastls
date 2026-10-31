package fastls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
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
	HTTPVersion                    HTTPVersion
	HTTP3                          *HTTP3EffectiveConfig
	AddressPolicy                  *AddressPolicy
	KeepAlive                      bool
	Lifetime                       context.Context
	ProxyConfigured                bool
	VerifyTLS                      bool
	TLSRootCAs                     *x509.CertPool
	Profile                        *profile.Spec
	FingerprintUserAgent           string
	FingerprintSignatureAlgorithms []uint16
	Fingerprint                    Fingerprint
	UserAgent                      string
	Cookies                        []Cookie
	headerOrder                    []string
	pseudoHeaderOrder              []string
	http2Settings                  *ftransport.HTTP2Config
	dialer                         proxy.ContextDialer

	mu                sync.Mutex
	cachedTransports  map[string]http.RoundTripper
	cachedProtocols   map[string]ftransport.Protocol
	pendingConnection map[string]ftransport.DialResult
	transportGate     chan struct{}
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	dispatched := false
	defer func() {
		// A failure before handing the request to ftransport still owns the
		// upload body and must unblock a streaming producer.
		if !dispatched && req != nil && req.Body != nil {
			req.Body.Close()
		}
	}()
	if req == nil || req.URL == nil {
		return nil, errors.New("fastls: nil request or URL")
	}
	if rt.HTTPVersion == HTTPVersion3 && req.URL.Scheme != "https" {
		return nil, errors.New("fastls: forced HTTP/3 requires an https URL on every redirect hop")
	}
	if rt.AddressPolicy != nil {
		if rt.ProxyConfigured {
			return nil, addressDenied("proxy_unsupported")
		}
		if rt.Fingerprint != nil && !rt.Fingerprint.IsEmpty() && strings.HasPrefix(rt.Fingerprint.Value(), "q") {
			return nil, addressDenied("http3_unsupported")
		}
		if err := rt.AddressPolicy.checkRequest(req); err != nil {
			return nil, err
		}
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
	if rt.Profile != nil {
		req, err = applyProtocolHeaders(req, rt.Profile.Headers, protocol)
		if err != nil {
			return nil, err
		}
	}
	dispatched = true
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
		if rt.HTTPVersion == HTTPVersion3 || (rt.Fingerprint != nil && !rt.Fingerprint.IsEmpty() && strings.HasPrefix(rt.Fingerprint.Value(), "q")) {
			if rt.ProxyConfigured {
				return nil, 0, errors.New("fastls: HTTP/3 does not support configured proxies")
			}
			h3, err := newHTTP3Transport(rt.Fingerprint, rt.UserAgent, rt.VerifyTLS, rt.TLSRootCAs)
			if err != nil {
				return nil, 0, err
			}
			h3.KeepAlive, h3.Lifetime = rt.KeepAlive, rt.Lifetime
			h3.AddressPolicy = rt.AddressPolicy
			h3.config = rt.HTTP3
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
		spec, err = StringToSpecWithSignatureAlgorithms(rt.Fingerprint.Value(), rt.protocolUserAgent(), rt.FingerprintSignatureAlgorithms)
	}
	if err != nil {
		_ = rawConn.Close()
		return ftransport.DialResult{}, err
	}
	noTickets := rt.Profile != nil && rt.Profile.TLS.SessionPolicy == "disabled"
	conn := utls.UClient(rawConn, &utls.Config{
		ServerName: host, OmitEmptyPsk: true,
		SessionTicketsDisabled: noTickets,
		InsecureSkipVerify:     !rt.VerifyTLS, RootCAs: rt.TLSRootCAs,
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
	if browser.AddressPolicy != nil {
		dialer = browser.AddressPolicy
	}
	return &roundTripper{
		HTTPVersion: browser.HTTPVersion,
		HTTP3:       browser.HTTP3,
		KeepAlive:   browser.KeepAlive, Lifetime: browser.Lifetime, ProxyConfigured: browser.ProxyConfigured,
		AddressPolicy: browser.AddressPolicy,
		VerifyTLS:     browser.VerifyTLS, TLSRootCAs: browser.TLSRootCAs,
		Profile: browser.Profile, Fingerprint: browser.Fingerprint,
		UserAgent: browser.UserAgent, FingerprintUserAgent: browser.FingerprintUserAgent,
		FingerprintSignatureAlgorithms: append([]uint16(nil), browser.FingerprintSignatureAlgorithms...),
		Cookies:                        browser.Cookies, headerOrder: slices.Clone(browser.HeaderOrderKeys),
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

// applyProtocolHeaders applies protocol-specific defaults only after ALPN is
// known. Caller values, including explicit empty values, take precedence.
func applyProtocolHeaders(req *http.Request, headers profile.HeaderConfig, protocol ftransport.Protocol) (*http.Request, error) {
	var defaults []profile.Header
	switch protocol {
	case ftransport.ProtocolHTTP1:
		defaults = headers.HTTP1Defaults
	case ftransport.ProtocolHTTP2:
		defaults = headers.HTTP2Defaults
	default:
		return req, nil
	}
	for _, header := range defaults {
		present := false
		for name := range req.Header {
			if strings.EqualFold(name, header.Name) {
				present = true
				break
			}
		}
		if !present {
			req.Header[textproto.CanonicalMIMEHeaderKey(header.Name)] = slices.Clone(header.Values)
		}
	}
	if protocol != ftransport.ProtocolHTTP1 || len(headers.HTTP1Order) == 0 {
		return req, nil
	}
	order := slices.Clone(headers.HTTP1Order)
	for _, wireName := range order {
		for name, values := range req.Header {
			if name != wireName && strings.EqualFold(name, wireName) {
				delete(req.Header, name)
				req.Header[wireName] = values
				break
			}
		}
	}
	return ftransport.WithRequestOptions(req, ftransport.RequestOptions{HeaderOrder: order})
}

var _ http.RoundTripper = (*roundTripper)(nil)
