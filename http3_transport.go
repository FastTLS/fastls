package fastls

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	stdhttp "net/http"

	http "github.com/FastTLS/fhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/proxy"
)

// http3Transport 实现 HTTP/3 传输层
type http3Transport struct {
	sync.Mutex
	Fingerprint Fingerprint
	UserAgent   string
	Cookies     []Cookie
	dialer      proxy.ContextDialer

	// QUIC 连接缓存
	cachedQuicConnections map[string]*quic.Conn
}

// RoundTrip 实现 http.RoundTripper 接口
func (t *http3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 将 fhttp.Request 转换为标准库的 http.Request
	stdReq, err := stdhttp.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, fmt.Errorf("创建标准库请求失败: %w", err)
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
	if t.UserAgent != "" {
		stdReq.Header.Set("User-Agent", t.UserAgent)
	}

	// 添加 Cookies
	for _, cookie := range t.Cookies {
		stdReq.AddCookie(&stdhttp.Cookie{
			Name:       cookie.Name,
			Value:      cookie.Value,
			Path:       cookie.Path,
			Domain:     cookie.Domain,
			Expires:    cookie.JSONExpires.Time,
			RawExpires: cookie.RawExpires,
			MaxAge:     cookie.MaxAge,
			HttpOnly:   cookie.HTTPOnly,
			Secure:     cookie.Secure,
			Raw:        cookie.Raw,
			Unparsed:   cookie.Unparsed,
		})
	}

	// 创建 HTTP/3 Transport
	// Transport 会通过 Dial 函数自动建立连接
	transport := &http3.Transport{
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			// 建立 QUIC 连接（使用 DialEarly 支持 0-RTT）
			return t.dialQUICEarly(ctx, addr, tlsCfg, cfg)
		},
	}
	defer transport.Close()

	// 发送请求
	stdResp, err := transport.RoundTrip(stdReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP/3 请求失败: %w", err)
	}

	// 将标准库的 Response 转换为 fhttp.Response
	bodyBytes, err := io.ReadAll(stdResp.Body)
	stdResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
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

// dialQUIC 建立 QUIC 连接
func (t *http3Transport) dialQUIC(ctx context.Context, addr string) (*quic.Conn, error) {
	t.Lock()
	defer t.Unlock()

	// 检查缓存
	if conn := t.cachedQuicConnections[addr]; conn != nil {
		// 检查连接是否仍然有效（简单检查，实际应该检查连接状态）
		return conn, nil
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	// 建立 UDP 连接（QUIC 基于 UDP）
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("解析 UDP 地址失败: %w", err)
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("建立 UDP 连接失败: %w", err)
	}

	// 配置 TLS
	var tlsConfig *tls.Config
	if t.Fingerprint != nil && !t.Fingerprint.IsEmpty() {
		// 解析指纹并转换为标准 TLS 配置
		// 注意：quic-go 使用标准库的 tls.Config，不支持 uTLS
		// 我们只能尽量匹配 TLS 配置
		fpValue := t.Fingerprint.Value()

		// 如果是 JA4R 格式且是 QUIC 协议，解析它
		if strings.HasPrefix(fpValue, "q") {
			// 解析 JA4R 获取 TLS 配置信息
			spec, err := ParseJA4R(fpValue, t.UserAgent)
			if err != nil {
				udpConn.Close()
				return nil, fmt.Errorf("解析 JA4R 指纹失败: %w", err)
			}

			// 从 spec 中提取 TLS 配置
			tlsConfig = &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
				NextProtos:         []string{"h3"}, // HTTP/3 ALPN
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
			}

			// 设置密码套件
			if len(spec.CipherSuites) > 0 {
				tlsConfig.CipherSuites = spec.CipherSuites
			}
		} else {
			// 尝试解析 JA3 或其他格式
			spec, err := StringToSpec(fpValue, t.UserAgent)
			if err != nil {
				udpConn.Close()
				return nil, fmt.Errorf("解析指纹失败: %w", err)
			}

			tlsConfig = &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
				NextProtos:         []string{"h3"},
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
			}

			if len(spec.CipherSuites) > 0 {
				tlsConfig.CipherSuites = spec.CipherSuites
			}
		}
	} else {
		tlsConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}
	}

	// 建立 QUIC 连接
	quicConn, err := quic.Dial(ctx, udpConn, udpAddr, tlsConfig, &quic.Config{})
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("建立 QUIC 连接失败: %w", err)
	}

	// 缓存连接
	if t.cachedQuicConnections == nil {
		t.cachedQuicConnections = make(map[string]*quic.Conn)
	}
	t.cachedQuicConnections[addr] = quicConn

	return quicConn, nil
}

// dialQUICEarly 建立 QUIC 连接（用于 HTTP/3）
func (t *http3Transport) dialQUICEarly(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	// 建立 UDP 连接（QUIC 基于 UDP）
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("解析 UDP 地址失败: %w", err)
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("建立 UDP 连接失败: %w", err)
	}

	// 如果没有提供 tlsCfg，使用默认配置
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}

		// 如果有指纹，尝试应用
		if t.Fingerprint != nil && !t.Fingerprint.IsEmpty() {
			fpValue := t.Fingerprint.Value()
			if strings.HasPrefix(fpValue, "q") {
				spec, err := ParseJA4R(fpValue, t.UserAgent)
				if err == nil && len(spec.CipherSuites) > 0 {
					tlsCfg.CipherSuites = spec.CipherSuites
				}
			}
		}
	}

	// 如果没有提供 cfg，使用默认配置
	if cfg == nil {
		cfg = &quic.Config{}
	}

	// 建立 QUIC 连接（使用 DialEarly 支持 0-RTT）
	quicConn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("建立 QUIC 连接失败: %w", err)
	}

	return quicConn, nil
}

// newHTTP3Transport 创建 HTTP/3 传输层
func newHTTP3Transport(fingerprint Fingerprint, userAgent string, cookies []Cookie, dialer proxy.ContextDialer) *http3Transport {
	return &http3Transport{
		Fingerprint:           fingerprint,
		UserAgent:             userAgent,
		Cookies:               cookies,
		dialer:                dialer,
		cachedQuicConnections: make(map[string]*quic.Conn),
	}
}
