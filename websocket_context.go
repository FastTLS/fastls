package fastls

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/FastTLS/fastls/internal/compiler"
	"github.com/FastTLS/fastls/profile"
	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// DialWebSocketContext performs a verified, cancellable RFC6455 handshake.
// It adapts the selected TLS profile to HTTP/1.1 ALPN. Gorilla owns Upgrade
// header order; this is deliberately not an exact HTTP/2/browser fingerprint.
// Compression, redirects, HTTP/2 CONNECT and environment proxies are disabled.
func DialWebSocketContext(ctx context.Context, endpoint string, options Options, protocols []string) (*websocket.Conn, *http.Response, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil WebSocket context")
	}
	if options.HTTPVersion != HTTPVersionAuto {
		return nil, nil, errors.New("fastls: WebSocket uses HTTP/1.1 Upgrade and does not support explicit HTTPVersion selection")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "ws" && u.Scheme != "wss") {
		return nil, nil, errors.New("WebSocket requires an absolute ws/wss URL without credentials or fragment")
	}
	if options.Profile == nil && (options.Fingerprint == nil || options.Fingerprint.IsEmpty()) {
		return nil, nil, errors.New("WebSocket requires a resolved TLS profile")
	}
	if options.Profile != nil {
		s := profile.Clone(*options.Profile)
		s.Headers.Order, s.Headers.PseudoOrder = nil, nil
		if err := ApplyProfile(&options, s); err != nil {
			return nil, nil, err
		}
	}
	var dialer proxy.ContextDialer = &net.Dialer{}
	if options.Proxy != "" {
		p, err := parseTunnelProxy(options.Proxy)
		if err != nil {
			return nil, nil, err
		}
		dialer = &tunnelProxyDialer{endpoint: p, roots: options.ProxyTLSRootCAs}
	}
	headers := http.Header{}
	for name, value := range options.Headers {
		lower := strings.ToLower(name)
		if lower == "connection" || lower == "upgrade" || lower == "content-length" || lower == "transfer-encoding" || lower == "proxy-authorization" || lower == "proxy-connection" || strings.HasPrefix(lower, "sec-websocket-") {
			return nil, nil, errors.New("WebSocket manages handshake and proxy protocol headers")
		}
		headers.Set(name, value)
	}
	if headers.Get("User-Agent") == "" {
		headers.Set("User-Agent", options.UserAgent)
	}
	var bounded *wsHandshakeConn
	var stopHandshake func() bool
	defer func() {
		if stopHandshake != nil {
			stopHandshake()
		}
	}()
	wrap := func(conn net.Conn) net.Conn {
		bounded = &wsHandshakeConn{Conn: conn, left: 65536}
		bounded.limited.Store(true)
		stopHandshake = context.AfterFunc(ctx, func() { conn.Close() })
		return bounded
	}
	d := websocket.Dialer{Proxy: nil, EnableCompression: false, ReadBufferSize: 4096, WriteBufferSize: 16384,
		Subprotocols: append([]string(nil), protocols...)}
	d.NetDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return wrap(c), nil
	}
	d.NetDialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		raw, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { raw.Close() })
		defer stop()
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			raw.Close()
			return nil, err
		}
		var spec *utls.ClientHelloSpec
		if options.Profile != nil {
			spec, err = compiler.TLS(*options.Profile)
		} else {
			spec, err = StringToSpec(options.Fingerprint.Value(), options.FingerprintUserAgent)
		}
		if err != nil {
			raw.Close()
			return nil, err
		}
		extensions := spec.Extensions[:0]
		for _, extension := range spec.Extensions {
			switch ext := extension.(type) {
			case *utls.ALPNExtension:
				ext.AlpnProtocols = []string{"http/1.1"}
			case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
				continue // ALPS for h2 does not apply to a classic Upgrade.
			}
			extensions = append(extensions, extension)
		}
		spec.Extensions = extensions
		conn := utls.UClient(raw, &utls.Config{ServerName: host, RootCAs: options.TLSRootCAs, OmitEmptyPsk: true}, utls.HelloCustom)
		if err = conn.ApplyPreset(spec); err == nil {
			err = conn.HandshakeContext(ctx)
		}
		if err != nil || (conn.ConnectionState().NegotiatedProtocol != "" && conn.ConnectionState().NegotiatedProtocol != "http/1.1") {
			conn.Close()
			if err == nil {
				err = errors.New("WebSocket server negotiated unsupported ALPN")
			}
			return nil, err
		}
		return wrap(conn), nil
	}
	c, resp, err := d.DialContext(ctx, endpoint, headers)
	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if bounded != nil {
		bounded.limited.Store(false)
	}
	if err == nil && (len(resp.Header.Values("Sec-WebSocket-Accept")) != 1 || len(resp.Header.Values("Sec-WebSocket-Protocol")) > 1 || (c.Subprotocol() != "" && !slices.Contains(protocols, c.Subprotocol())) || len(resp.Header.Values("Sec-WebSocket-Extensions")) != 0) {
		c.Close()
		return nil, resp, errors.New("WebSocket server selected an unoffered subprotocol or extension")
	}
	return c, resp, err
}

type wsHandshakeConn struct {
	net.Conn
	limited atomic.Bool
	left    int
}

func (c *wsHandshakeConn) Read(p []byte) (int, error) {
	if !c.limited.Load() {
		return c.Conn.Read(p)
	}
	if c.left == 0 {
		return 0, errors.New("WebSocket handshake exceeds 64KiB")
	}
	if len(p) > c.left {
		p = p[:c.left]
	}
	n, err := c.Conn.Read(p)
	c.left -= n
	return n, err
}
