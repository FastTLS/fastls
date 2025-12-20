package fastls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"

	"strings"
	"sync"

	stdhttp "net/http"

	http "github.com/Wuhan-Dongce/fhttp"
	http2 "github.com/Wuhan-Dongce/fhttp/http2"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type roundTripper struct {
	sync.Mutex
	// fix typing
	Fingerprint Fingerprint
	UserAgent   string

	Cookies           []Cookie
	cachedConnections map[string]net.Conn
	cachedTransports  map[string]http.RoundTripper
	http2Settings     *http2.HTTP2Settings

	dialer proxy.ContextDialer
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 如果 Fingerprint 为空，使用 Go 标准库的 http.Client
	if rt.Fingerprint == nil || rt.Fingerprint.IsEmpty() {
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
	req.Header.Set("User-Agent", rt.UserAgent)
	addr := rt.getDialTLSAddr(req)
	if _, ok := rt.cachedTransports[addr]; !ok {
		if err := rt.getTransport(req, addr); err != nil {
			return nil, err
		}
	}
	return rt.cachedTransports[addr].RoundTrip(req)
}

func (rt *roundTripper) getTransport(req *http.Request, addr string) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		rt.cachedTransports[addr] = &http.Transport{DialContext: rt.dialer.DialContext, DisableKeepAlives: true}
		return nil
	case "https":
	default:
		return fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	// 检查是否应该使用 HTTP/3 (QUIC)
	// 如果指纹是 JA4R 格式且协议类型是 'q' (QUIC)，使用 HTTP/3
	if rt.Fingerprint != nil && !rt.Fingerprint.IsEmpty() {
		fpValue := rt.Fingerprint.Value()
		// 检查是否是 QUIC 协议（JA4R 格式以 'q' 开头）
		if strings.HasPrefix(fpValue, "q") {
			// 使用 HTTP/3 (QUIC)
			h3Transport := newHTTP3Transport(rt.Fingerprint, rt.UserAgent, rt.Cookies, rt.dialer)
			rt.cachedTransports[addr] = h3Transport
			return nil
		}
	}

	// 如果 Fingerprint 为空，使用 Go 标准库的默认 TLS 配置
	if rt.Fingerprint == nil || rt.Fingerprint.IsEmpty() {
		// 创建一个适配器，将标准库的 Transport 包装成 fhttp.RoundTripper
		stdTransport := &stdhttp.Transport{
			DialContext:       rt.dialer.DialContext,
			DisableKeepAlives: true,
		}
		rt.cachedTransports[addr] = &stdlibTransportAdapter{transport: stdTransport}
		return nil
	}

	_, err := rt.dialTLS(req.Context(), "tcp", addr)
	switch err {
	case errProtocolNegotiated:
	case nil:
		// Should never happen.
		panic("dialTLS returned no error when determining cachedTransports")
	default:
		return err
	}

	return nil
}

func (rt *roundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rt.Lock()
	defer rt.Unlock()

	// If we have the connection from when we determined the HTTPS
	// cachedTransports to use, return that.
	if conn := rt.cachedConnections[addr]; conn != nil {
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

	// 如果 Fingerprint 为空，使用 Go 标准库的 TLS（这种情况不应该到达这里，因为 getTransport 已经处理了）
	// 但为了安全起见，这里也做检查
	if rt.Fingerprint == nil || rt.Fingerprint.IsEmpty() {
		// 使用 Go 标准库的 TLS
		conn := tls.Client(rawConn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err = conn.Handshake(); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("标准库 TLS Handshake() 错误: %+v", err)
		}
		rt.cachedConnections[addr] = conn
		return conn, nil
	}

	spec, err := StringToSpec(rt.Fingerprint.Value(), rt.UserAgent)
	if err != nil {
		return nil, err
	}

	conn := utls.UClient(rawConn, &utls.Config{ServerName: host, OmitEmptyPsk: true, InsecureSkipVerify: true}, // MinVersion:         tls.VersionTLS10,
		// MaxVersion:         tls.VersionTLS13,

		utls.HelloCustom)

	if err := conn.ApplyPreset(spec); err != nil {
		return nil, err
	}

	if err = conn.Handshake(); err != nil {
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
		browserType := parseUserAgent(rt.UserAgent)
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
	stdReq, err := stdhttp.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, err
	}

	// 复制请求头
	for key, values := range req.Header {
		for _, value := range values {
			// 跳过 fhttp 特定的头
			if key == http.HeaderOrderKey || key == http.PHeaderOrderKey {
				continue
			}
			stdReq.Header.Add(key, value)
		}
	}

	// 发送请求
	stdResp, err := a.transport.RoundTrip(stdReq)
	if err != nil {
		return nil, err
	}

	// 将标准库的 Response 转换为 fhttp.Response
	// 读取响应体
	bodyBytes, err := io.ReadAll(stdResp.Body)
	stdResp.Body.Close()
	if err != nil {
		return nil, err
	}

	// 创建 fhttp.Response
	fhttpResp := &http.Response{
		Status:     stdResp.Status,
		StatusCode: stdResp.StatusCode,
		Proto:      stdResp.Proto,
		ProtoMajor: stdResp.ProtoMajor,
		ProtoMinor: stdResp.ProtoMinor,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
		Request:    req,
	}

	// 复制响应头
	for key, values := range stdResp.Header {
		for _, value := range values {
			fhttpResp.Header.Add(key, value)
		}
	}

	return fhttpResp, nil
}

// roundTripWithStdlib 使用 Go 标准库的 http.Client 发送请求
func (rt *roundTripper) roundTripWithStdlib(req *http.Request) (*http.Response, error) {
	// 将 fhttp.Request 转换为标准库的 http.Request
	stdReq, err := stdhttp.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, err
	}

	// 复制请求头
	for key, values := range req.Header {
		for _, value := range values {
			// 跳过 fhttp 特定的头
			if key == http.HeaderOrderKey || key == http.PHeaderOrderKey {
				continue
			}
			stdReq.Header.Add(key, value)
		}
	}

	// 设置 User-Agent
	if rt.UserAgent != "" {
		stdReq.Header.Set("User-Agent", rt.UserAgent)
	}

	// 添加 Cookies
	for _, properties := range rt.Cookies {
		stdReq.AddCookie(&stdhttp.Cookie{
			Name:       properties.Name,
			Value:      properties.Value,
			Path:       properties.Path,
			Domain:     properties.Domain,
			Expires:    properties.JSONExpires.Time,
			RawExpires: properties.RawExpires,
			MaxAge:     properties.MaxAge,
			HttpOnly:   properties.HTTPOnly,
			Secure:     properties.Secure,
			Raw:        properties.Raw,
			Unparsed:   properties.Unparsed,
		})
	}

	// 创建标准库的 http.Client
	client := &stdhttp.Client{
		Transport: &stdhttp.Transport{
			DialContext: rt.dialer.DialContext,
		},
	}

	// 发送请求
	stdResp, err := client.Do(stdReq)
	if err != nil {
		return nil, err
	}

	// 将标准库的 Response 转换为 fhttp.Response
	// 由于类型不兼容，我们需要手动创建 fhttp.Response
	// 读取响应体
	bodyBytes, err := io.ReadAll(stdResp.Body)
	stdResp.Body.Close()
	if err != nil {
		return nil, err
	}

	// 创建 fhttp.Response
	fhttpResp := &http.Response{
		Status:     stdResp.Status,
		StatusCode: stdResp.StatusCode,
		Proto:      stdResp.Proto,
		ProtoMajor: stdResp.ProtoMajor,
		ProtoMinor: stdResp.ProtoMinor,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
		Request:    req,
	}

	// 复制响应头
	for key, values := range stdResp.Header {
		for _, value := range values {
			fhttpResp.Header.Add(key, value)
		}
	}

	return fhttpResp, nil
}

func (rt *roundTripper) getDialTLSAddr(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(req.URL.Host, "443") // we can assume port is 443 at this point
}

func (rt *roundTripper) CloseIdleConnections() {
	for addr, conn := range rt.cachedConnections {
		_ = conn.Close()
		delete(rt.cachedConnections, addr)
	}
}

func newRoundTripper(browser browser, dialer ...proxy.ContextDialer) http.RoundTripper {
	if len(dialer) > 0 {
		return &roundTripper{
			dialer: dialer[0],

			Fingerprint:       browser.Fingerprint,
			UserAgent:         browser.UserAgent,
			Cookies:           browser.Cookies,
			cachedTransports:  make(map[string]http.RoundTripper),
			cachedConnections: make(map[string]net.Conn),
			http2Settings:     browser.HTTP2Settings,
		}
	}

	return &roundTripper{
		dialer: proxy.Direct,

		Fingerprint:       browser.Fingerprint,
		UserAgent:         browser.UserAgent,
		Cookies:           browser.Cookies,
		cachedTransports:  make(map[string]http.RoundTripper),
		cachedConnections: make(map[string]net.Conn),
		http2Settings:     browser.HTTP2Settings,
	}
}
