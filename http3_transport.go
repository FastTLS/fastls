package fastls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// http3Transport 实现 HTTP/3 传输层
type http3Transport struct {
	sync.Mutex
	Fingerprint Fingerprint // Validated selector; crypto/tls cannot reproduce arbitrary QUIC ClientHello order.
	UserAgent   string
	VerifyTLS   bool
	TLSRootCAs  *x509.CertPool
	transport   *http3.Transport
}

// RoundTrip 实现 http.RoundTripper 接口
func (t *http3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	stdReq := req.Clone(req.Context())

	// 设置 User-Agent
	if t.UserAgent != "" {
		stdReq.Header.Set("User-Agent", t.UserAgent)
	}

	t.Lock()
	if t.transport == nil {
		tlsConfig := &tls.Config{
			RootCAs:            t.TLSRootCAs,
			InsecureSkipVerify: !t.VerifyTLS,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h3"},
		}
		t.transport = &http3.Transport{
			TLSClientConfig: tlsConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return t.dialQUICEarly(ctx, addr, tlsCfg, cfg)
			},
		}
	}
	transport := t.transport
	t.Unlock()

	// 发送请求
	stdResp, err := transport.RoundTrip(stdReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP/3 请求失败: %w", err)
	}

	stdResp.Request = req
	return stdResp, nil
}

func (t *http3Transport) CloseIdleConnections() {
	t.Lock()
	transport := t.transport
	t.Unlock()
	if transport != nil {
		transport.CloseIdleConnections()
	}
}

// dialQUICEarly 建立 QUIC 连接（用于 HTTP/3）
func (t *http3Transport) dialQUICEarly(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}

	// 如果没有提供 tlsCfg，使用默认配置
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			ServerName:         host,
			RootCAs:            t.TLSRootCAs,
			InsecureSkipVerify: !t.VerifyTLS,
			NextProtos:         []string{"h3"},
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}
	}

	// 如果没有提供 cfg，使用默认配置
	if cfg == nil {
		cfg = &quic.Config{}
	}

	// 建立 QUIC 连接（使用 DialEarly 支持 0-RTT）
	quicConn, err := quic.DialAddrEarly(ctx, net.JoinHostPort(host, port), tlsCfg, cfg)
	if err != nil {
		return nil, fmt.Errorf("建立 QUIC 连接失败: %w", err)
	}

	return quicConn, nil
}

// newHTTP3Transport 创建 HTTP/3 传输层
func newHTTP3Transport(fingerprint Fingerprint, userAgent string, verifyTLS bool, roots *x509.CertPool) (*http3Transport, error) {
	if fingerprint == nil || fingerprint.IsEmpty() || !strings.HasPrefix(strings.ToLower(fingerprint.Value()), "q") {
		return nil, errors.New("fastls: HTTP/3 requires a q-prefixed JA4R selector")
	}
	if _, err := ParseJA4R(fingerprint.Value(), userAgent); err != nil {
		return nil, fmt.Errorf("fastls: invalid HTTP/3 JA4R selector: %w", err)
	}
	return &http3Transport{Fingerprint: fingerprint, UserAgent: userAgent, VerifyTLS: verifyTLS, TLSRootCAs: roots}, nil
}
