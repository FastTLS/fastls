package fastls

import (
	"context"
	"crypto/tls"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/FastTLS/fastls/internal/compiler"
	"github.com/FastTLS/fastls/profile"
	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

// WebSocketClient represents a client for WebSocket connections
type WebSocketClient struct {
	setupError error
	// Dialer is the websocket dialer
	Dialer *websocket.Dialer

	// HTTP client for WebSocket handshake
	HTTPClient *http.Client

	// Headers to be included in the WebSocket handshake
	Headers http.Header

	// Fingerprint for TLS fingerprinting
	Fingerprint Fingerprint

	// UserAgent for TLS fingerprinting
	UserAgent string
}

// NewWebSocketClientWithOptions creates a new WebSocket client from Options
// Prepare options with imitate.Use and an explicit provider, or supply a custom fingerprint.
func NewWebSocketClientWithOptions(options Options) *WebSocketClient {
	if options.HTTPVersion != HTTPVersionAuto {
		return &WebSocketClient{setupError: fmt.Errorf("fastls: WebSocket uses HTTP/1.1 Upgrade and does not support explicit HTTPVersion selection")}
	}
	options.Headers = maps.Clone(options.Headers)
	options.UserAgent = options.requestUserAgent()
	for k := range options.Headers {
		if strings.EqualFold(k, "User-Agent") {
			options.Headers[k] = options.UserAgent
		}
	}
	if options.Profile != nil {
		return newProfileWebSocket(options)
	}
	headers := http.Header{}
	for k, v := range options.Headers {
		headers.Set(k, v)
	}
	for k, values := range options.HeaderValues {
		headers[http.CanonicalHeaderKey(k)] = append([]string(nil), values...)
	}
	if _, exists := headers["User-Agent"]; !exists {
		headers.Set("User-Agent", options.UserAgent)
	}
	protocolUA := options.FingerprintUserAgent
	if protocolUA == "" {
		protocolUA = options.UserAgent
	}
	return NewWebSocketClient(options.Fingerprint, protocolUA, headers)
}

// NewWebSocketClient creates a new WebSocket client with TLS fingerprinting support
// If fingerprint is nil or empty, it will use standard TLS
func NewWebSocketClient(fingerprint Fingerprint, userAgent string, headers http.Header) *WebSocketClient {
	// Create custom dialer for TLS fingerprinting
	var dialTLS func(network, addr string) (net.Conn, error)
	if fingerprint != nil && !fingerprint.IsEmpty() {
		// Use uTLS for fingerprinting
		dialTLS = func(network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}

			rawConn, err := net.DialTimeout(network, addr, 30*time.Second)
			if err != nil {
				return nil, err
			}

			spec, err := StringToSpec(fingerprint.Value(), userAgent)
			if err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("create TLS spec failed: %w", err)
			}

			// 修改 spec 中的 ALPN 扩展，确保只包含 http/1.1（WebSocket 不支持 HTTP/2）
			// 遍历扩展列表，找到并替换 ALPN 扩展
			for i, ext := range spec.Extensions {
				if _, ok := ext.(*utls.ALPNExtension); ok {
					// 替换为只包含 http/1.1 的 ALPN 扩展
					spec.Extensions[i] = &utls.ALPNExtension{
						AlpnProtocols: []string{"http/1.1"},
					}
					break
				}
			}

			conn := utls.UClient(rawConn, &utls.Config{
				ServerName:         host,
				OmitEmptyPsk:       true,
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"}, // WebSocket requires HTTP/1.1
			}, utls.HelloCustom)

			if err := conn.ApplyPreset(spec); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("apply TLS preset failed: %w", err)
			}

			// 确保 ALPN 协议只包含 http/1.1
			// 直接修改 HandshakeState 中的 ALPN 协议列表
			if conn.HandshakeState.Hello != nil {
				conn.HandshakeState.Hello.AlpnProtocols = []string{"http/1.1"}
			}

			if err := conn.Handshake(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS handshake failed: %w", err)
			}

			// 验证协商的协议是 HTTP/1.1（WebSocket 不支持 HTTP/2）
			negotiatedProto := conn.ConnectionState().NegotiatedProtocol
			if negotiatedProto != "" && negotiatedProto != "http/1.1" {
				conn.Close()
				return nil, fmt.Errorf("TLS negotiated protocol is %s, but WebSocket requires http/1.1", negotiatedProto)
			}

			return conn, nil
		}
	} else {
		// Use standard TLS
		dialTLS = func(network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}

			rawConn, err := net.DialTimeout(network, addr, 30*time.Second)
			if err != nil {
				return nil, err
			}

			conn := tls.Client(rawConn, &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"}, // WebSocket requires HTTP/1.1
			})

			if err := conn.Handshake(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS handshake failed: %w", err)
			}

			// 验证协商的协议是 HTTP/1.1（WebSocket 不支持 HTTP/2）
			negotiatedProto := conn.ConnectionState().NegotiatedProtocol
			if negotiatedProto != "" && negotiatedProto != "http/1.1" {
				conn.Close()
				return nil, fmt.Errorf("TLS negotiated protocol is %s, but WebSocket requires http/1.1", negotiatedProto)
			}

			return conn, nil
		}
	}

	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLS(network, addr)
		},
	}

	// Create HTTP client for WebSocket handshake
	// 禁用 HTTP/2，WebSocket 只支持 HTTP/1.1
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false, // 禁用 HTTP/2
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLS(network, addr)
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	return &WebSocketClient{
		Dialer:      dialer,
		HTTPClient:  client,
		Headers:     headers,
		Fingerprint: fingerprint,
		UserAgent:   userAgent,
	}
}

// Connect establishes a WebSocket connection
func (wsc *WebSocketClient) Connect(urlStr string) (*websocket.Conn, *http.Response, error) {
	if wsc.setupError != nil {
		return nil, nil, wsc.setupError
	}
	// Parse the URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, nil, err
	}

	// Determine the scheme for WebSocket
	var scheme string
	switch u.Scheme {
	case "http":
		scheme = "ws"
	case "https":
		scheme = "wss"
	case "ws", "wss":
		scheme = u.Scheme
	default:
		// Default to ws
		scheme = "ws"
	}

	// Create a new URL with the WebSocket scheme
	wsURL := url.URL{
		Scheme:   scheme,
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}

	// Connect to the WebSocket server
	conn, resp, err := wsc.Dialer.Dial(wsURL.String(), wsc.Headers)
	if err != nil {
		return nil, resp, err
	}

	return conn, resp, nil
}

// newProfileWebSocket preserves the supplied TLS parameters. Gorilla controls
// the HTTP Upgrade header order; explicit order and H2/H3 are rejected.
func newProfileWebSocket(options Options) *WebSocketClient {
	bad := func(err error) *WebSocketClient { return &WebSocketClient{setupError: err} }
	if err := ApplyProfile(&options, *options.Profile); err != nil {
		return bad(err)
	}
	s := profile.Clone(*options.Profile)
	if len(s.Headers.Order) > 0 || len(options.HeaderOrderKeys) > 0 {
		return bad(&profile.UnsupportedFeature{Field: "websocket.headers.order", Feature: "ordered-upgrade.v1"})
	}
	for _, e := range s.TLS.Extensions {
		if e.ID == 16 {
			for _, p := range e.ALPN {
				if p != "http/1.1" {
					return bad(&profile.UnsupportedFeature{Field: "websocket.alpn", Feature: p})
				}
			}
		}
	}
	headers := http.Header{}
	for k, v := range options.Headers {
		headers.Set(k, v)
	}
	for k, v := range options.HeaderValues {
		headers[k] = append([]string(nil), v...)
	}
	if _, exists := headers["User-Agent"]; !exists {
		headers.Set("User-Agent", options.UserAgent)
	}
	c := NewWebSocketClient(nil, options.UserAgent, headers)
	if options.UserAgent == "" {
		c.Headers.Set("User-Agent", "")
	}
	c.Dialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		spec, err := compiler.TLS(s)
		if err != nil {
			return nil, err
		}
		raw, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			raw.Close()
			return nil, err
		}
		conn := utls.UClient(raw, &utls.Config{ServerName: host, InsecureSkipVerify: true}, utls.HelloCustom)
		if err = conn.ApplyPreset(spec); err != nil {
			conn.Close()
			return nil, err
		}
		if err = conn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	return c
}

// WebSocketResponse represents a response from a WebSocket connection
type WebSocketResponse struct {
	// Conn is the WebSocket connection
	Conn *websocket.Conn

	// Response is the HTTP response from the WebSocket handshake
	Response *http.Response
}

// Close closes the WebSocket connection
func (wsr *WebSocketResponse) Close() error {
	if wsr.Conn != nil {
		// Send close message
		err := wsr.Conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		if err != nil {
			return err
		}

		// Close the connection
		return wsr.Conn.Close()
	}
	return nil
}

// Send sends a message over the WebSocket connection
func (wsr *WebSocketResponse) Send(messageType int, data []byte) error {
	return wsr.Conn.WriteMessage(messageType, data)
}

// Receive receives a message from the WebSocket connection
func (wsr *WebSocketResponse) Receive() (int, []byte, error) {
	return wsr.Conn.ReadMessage()
}
