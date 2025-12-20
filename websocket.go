package fastls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

// WebSocketClient represents a client for WebSocket connections
type WebSocketClient struct {
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
// This allows using imitate functions (e.g., imitate.Firefox, imitate.Chrome)
func NewWebSocketClientWithOptions(options Options) *WebSocketClient {
	headers := http.Header{}
	for k, v := range options.Headers {
		headers.Set(k, v)
	}
	if options.UserAgent != "" {
		headers.Set("User-Agent", options.UserAgent)
	}
	return NewWebSocketClient(options.Fingerprint, options.UserAgent, headers)
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
