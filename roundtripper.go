package fastls

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/FastTLS/fastls/internal/compiler"
	"github.com/FastTLS/fastls/profile"
	"net"

	"strings"
	"sync"

	stdhttp "net/http"

	http "github.com/FastTLS/fhttp"
	http2 "github.com/FastTLS/fhttp/http2"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type roundTripper struct {
	VerifyTLS            bool
	TLSRootCAs           *x509.CertPool
	Profile              *profile.Spec
	FingerprintUserAgent string
	sync.Mutex
	// fix typing
	Fingerprint Fingerprint
	UserAgent   string

	Cookies           []Cookie
	cachedConnections map[string]net.Conn
	cachedTransports  map[string]http.RoundTripper
	http2Settings     *http2.HTTP2Settings

	dialer          proxy.ContextDialer
	transportMu     sync.Mutex
	stdlibMu        sync.Mutex
	stdlibTransport *stdhttp.Transport
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Requests without a fingerprint use the standard-library transport.
	if rt.Profile == nil && (rt.Fingerprint == nil || rt.Fingerprint.IsEmpty()) {
		return rt.roundTripWithStdlib(req)
	}

	// Fix this later for proper cookie parsing
	for _, properties := range rt.Cookies {
		req.AddCookie(&http.Cookie{
			Name:       properties.Name,
			Value:      properties.Value,
			Path:       properties.Path,
			Domain:     properties.Domain,
			Expires:    properties.JSONExpires.Time, //TODO: scuffed af
			RawExpires: properties.RawExpires,
			MaxAge:     properties.MaxAge,
			HttpOnly:   properties.HTTPOnly,
			Secure:     properties.Secure,
			Raw:        properties.Raw,
			Unparsed:   properties.Unparsed,
		})
	}
	if _, exists := req.Header["User-Agent"]; !exists {
		req.Header.Set("User-Agent", rt.UserAgent)
	}
	if rt.Profile != nil && req.Header.Get("User-Agent") == "" {
		req.Header["User-Agent"] = []string{}
	}
	addr := rt.getDialTLSAddr(req)
	transport, err := rt.getTransport(req, addr)
	if err != nil {
		return nil, err
	}
	return transport.RoundTrip(req)
}

func (rt *roundTripper) getTransport(req *http.Request, addr string) (http.RoundTripper, error) {
	// Serialize protocol discovery while permitting requests to use an already
	// published transport concurrently. Map access shares dialTLS's mutex.
	rt.transportMu.Lock()
	defer rt.transportMu.Unlock()
	rt.Lock()
	transport := rt.cachedTransports[addr]
	rt.Unlock()
	if transport != nil {
		return transport, nil
	}
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		transport = &http.Transport{DialContext: rt.dialer.DialContext, DisableKeepAlives: true}
		rt.Lock()
		rt.cachedTransports[addr] = transport
		rt.Unlock()
		return transport, nil
	case "https":
	default:
		return nil, fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	// 检查是否应该使用 HTTP/3 (QUIC)
	// 如果指纹是 JA4R 格式且协议类型是 'q' (QUIC)，使用 HTTP/3
	if rt.Fingerprint != nil && !rt.Fingerprint.IsEmpty() {
		fpValue := rt.Fingerprint.Value()
		// 检查是否是 QUIC 协议（JA4R 格式以 'q' 开头）
		if strings.HasPrefix(fpValue, "q") {
			// 使用 HTTP/3 (QUIC)
			h3Transport := newHTTP3Transport(rt.Fingerprint, rt.UserAgent, rt.Cookies, rt.dialer)
			rt.Lock()
			rt.cachedTransports[addr] = h3Transport
			rt.Unlock()
			return h3Transport, nil
		}
	}

	_, err := rt.dialTLS(req.Context(), "tcp", addr)
	switch err {
	case errProtocolNegotiated:
	case nil:
		// Should never happen.
		panic("dialTLS returned no error when determining cachedTransports")
	default:
		return nil, err
	}

	rt.Lock()
	transport = rt.cachedTransports[addr]
	rt.Unlock()
	return transport, nil
}

func (rt *roundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rt.Lock()
	defer rt.Unlock()

	// If we have the connection from when we determined the HTTPS
	// cachedTransports to use, return that.
	if conn := rt.cachedConnections[addr]; conn != nil {
		// This is a one-time handoff of the ALPN discovery connection. Once
		// handed over, only the HTTP transport owns its lifetime and reuse.
		delete(rt.cachedConnections, addr)
		return conn, nil
	}
	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	var spec *utls.ClientHelloSpec
	if rt.Profile != nil {
		spec, err = compiler.TLS(*rt.Profile)
	} else {
		spec, err = StringToSpec(rt.Fingerprint.Value(), rt.protocolUserAgent())
	}
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	conn := utls.UClient(rawConn, &utls.Config{ServerName: host, OmitEmptyPsk: true, InsecureSkipVerify: !rt.VerifyTLS, RootCAs: rt.TLSRootCAs}, // MinVersion:         tls.VersionTLS10,
		// MaxVersion:         tls.VersionTLS13,

		utls.HelloCustom)

	if err := conn.ApplyPreset(spec); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()

		if err.Error() == "tls: CurvePreferences includes unsupported curve" {
			//fix this
			return nil, fmt.Errorf("conn.Handshake() error for tls 1.3 (please retry request): %+v", err)
		}
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	//////////
	if rt.cachedTransports[addr] != nil {
		return conn, nil
	}

	// No http.Transport constructed yet, create one based on the results
	// of ALPN.
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		browserType := "chrome"
		if rt.Profile == nil {
			browserType = parseUserAgent(rt.protocolUserAgent())
		}
		t2 := http2.Transport{
			DialTLS:       rt.dialTLSHTTP2,
			PushHandler:   &http2.DefaultPushHandler{},
			Navigator:     browserType,
			HTTP2Settings: rt.http2Settings,
		}
		rt.cachedTransports[addr] = &t2
	default:
		// Assume the remote peer is speaking HTTP 1.x + TLS.
		rt.cachedTransports[addr] = &http.Transport{DialTLSContext: rt.dialTLS, DisableKeepAlives: true}
	}

	// Stash the connection just established for use servicing the
	// actual request (should be near-immediate).
	rt.cachedConnections[addr] = conn

	return nil, errProtocolNegotiated
}

func (rt *roundTripper) dialTLSHTTP2(network, addr string, _ *utls.Config) (net.Conn, error) {
	return rt.dialTLS(context.Background(), network, addr)
}

// stdlibTransportAdapter 将标准库的 http.Transport 适配为 fhttp.RoundTripper
type stdlibTransportAdapter struct {
	transport *stdhttp.Transport
}

func (a *stdlibTransportAdapter) RoundTrip(req *http.Request) (*http.Response, error) {
	// 将 fhttp.Request 转换为标准库的 http.Request
	stdReq, err := stdhttp.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, err
	}
	stdReq.Host = req.Host
	stdReq.ContentLength = req.ContentLength
	stdReq.GetBody = req.GetBody
	stdReq.TransferEncoding = append([]string(nil), req.TransferEncoding...)
	stdReq.Close = req.Close

	// Preserve explicit empty headers, including suppression of the default UA.
	for key, values := range req.Header {
		if key != http.HeaderOrderKey && key != http.PHeaderOrderKey {
			stdReq.Header[key] = append([]string(nil), values...)
		}
	}
	stdReq.Trailer = stdhttp.Header(req.Trailer)

	// 发送请求
	stdResp, err := a.transport.RoundTrip(stdReq)
	if err != nil {
		return nil, err
	}

	// 创建 fhttp.Response
	fhttpResp := &http.Response{
		Status:           stdResp.Status,
		StatusCode:       stdResp.StatusCode,
		Proto:            stdResp.Proto,
		ProtoMajor:       stdResp.ProtoMajor,
		ProtoMinor:       stdResp.ProtoMinor,
		Header:           http.Header{},
		Body:             stdResp.Body,
		ContentLength:    stdResp.ContentLength,
		TransferEncoding: append([]string(nil), stdResp.TransferEncoding...),
		Close:            stdResp.Close,
		Uncompressed:     stdResp.Uncompressed,
		Trailer:          http.Header(stdResp.Trailer),
		Request:          req,
	}

	// 复制响应头
	for key, values := range stdResp.Header {
		for _, value := range values {
			fhttpResp.Header.Add(key, value)
		}
	}

	return fhttpResp, nil
}

// roundTripWithStdlib performs one exchange; the outer client owns redirects
// and timeouts. The caller owns the returned streaming response body.
func (rt *roundTripper) roundTripWithStdlib(req *http.Request) (*http.Response, error) {
	rt.stdlibMu.Lock()
	if rt.stdlibTransport == nil {
		rt.stdlibTransport = &stdhttp.Transport{DialContext: rt.dialer.DialContext}
	}
	transport := rt.stdlibTransport
	rt.stdlibMu.Unlock()
	// RoundTripper must not mutate the caller's headers.
	req = req.Clone(req.Context())
	if _, exists := req.Header["User-Agent"]; !exists && rt.UserAgent != "" {
		req.Header.Set("User-Agent", rt.UserAgent)
	}
	for _, properties := range rt.Cookies {
		req.AddCookie(&http.Cookie{
			Name: properties.Name, Value: properties.Value,
			Path: properties.Path, Domain: properties.Domain,
			Expires: properties.JSONExpires.Time, RawExpires: properties.RawExpires,
			MaxAge: properties.MaxAge, HttpOnly: properties.HTTPOnly,
			Secure: properties.Secure, Raw: properties.Raw, Unparsed: properties.Unparsed,
		})
	}
	return (&stdlibTransportAdapter{transport: transport}).RoundTrip(req)
}

func (rt *roundTripper) getDialTLSAddr(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(req.URL.Host, "443") // we can assume port is 443 at this point
}

func (rt *roundTripper) CloseIdleConnections() {
	rt.stdlibMu.Lock()
	transport := rt.stdlibTransport
	rt.stdlibMu.Unlock()
	if transport != nil {
		transport.CloseIdleConnections()
	}
	rt.Lock()
	connections := rt.cachedConnections
	rt.cachedConnections = make(map[string]net.Conn)
	transports := make([]http.RoundTripper, 0, len(rt.cachedTransports))
	for _, t := range rt.cachedTransports {
		transports = append(transports, t)
	}
	rt.Unlock()
	// Only discovery connections still awaiting handoff belong to this cache.
	for _, conn := range connections {
		_ = conn.Close()
	}
	for _, t := range transports {
		if closer, ok := t.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func newRoundTripper(browser browser, dialer ...proxy.ContextDialer) http.RoundTripper {
	if len(dialer) > 0 {
		return &roundTripper{
			VerifyTLS:  browser.VerifyTLS,
			TLSRootCAs: browser.TLSRootCAs,
			dialer:     dialer[0],

			Fingerprint:          browser.Fingerprint,
			Profile:              browser.Profile,
			UserAgent:            browser.UserAgent,
			FingerprintUserAgent: browser.FingerprintUserAgent,
			Cookies:              browser.Cookies,
			cachedTransports:     make(map[string]http.RoundTripper),
			cachedConnections:    make(map[string]net.Conn),
			http2Settings:        browser.HTTP2Settings,
		}
	}

	return &roundTripper{
		VerifyTLS:  browser.VerifyTLS,
		TLSRootCAs: browser.TLSRootCAs,
		dialer:     proxy.Direct,

		Fingerprint:          browser.Fingerprint,
		Profile:              browser.Profile,
		UserAgent:            browser.UserAgent,
		FingerprintUserAgent: browser.FingerprintUserAgent,
		Cookies:              browser.Cookies,
		cachedTransports:     make(map[string]http.RoundTripper),
		cachedConnections:    make(map[string]net.Conn),
		http2Settings:        browser.HTTP2Settings,
	}
}

func (rt *roundTripper) protocolUserAgent() string {
	if rt.FingerprintUserAgent != "" {
		return rt.FingerprintUserAgent
	}
	return rt.UserAgent
}
