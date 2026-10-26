package fastls

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxyCancellationAtEachHandshakePhase(t *testing.T) {
	certificate := httptest.NewTLSServer(http.NotFoundHandler())
	tlsConfig := certificate.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	certificate.Close()
	for _, phase := range []string{
		"https-tls", "http-status", "http-headers", "https-status",
		"socks-method", "socks-auth", "socks-connect", "socks-bound-address",
	} {
		t.Run(phase, func(t *testing.T) {
			ready, closed := make(chan struct{}), make(chan struct{})
			address := proxyWire(t, func(raw net.Conn) {
				c := raw
				if phase == "https-status" {
					secure := tls.Server(raw, tlsConfig)
					if err := secure.Handshake(); err != nil {
						t.Error(err)
						return
					}
					c = secure
				}
				if strings.HasPrefix(phase, "http") && phase != "https-tls" {
					if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
						t.Error(err)
						return
					}
					if phase == "http-headers" {
						io.WriteString(c, "HTTP/1.1 200 OK\r\nX-Incomplete: ")
					}
				} else if strings.HasPrefix(phase, "socks") {
					greeting := make([]byte, 3)
					if _, err := io.ReadFull(c, greeting); err != nil {
						t.Error(err)
						return
					}
					if phase != "socks-method" {
						if phase == "socks-auth" {
							c.Write([]byte{5, 2})
							// RFC1929 user and password sent by this test are both one byte.
							if _, err := io.CopyN(io.Discard, c, 5); err != nil {
								t.Error(err)
								return
							}
						} else {
							c.Write([]byte{5, 0})
							// IPv4 destination + port (10 bytes including the header).
							if _, err := io.CopyN(io.Discard, c, 10); err != nil {
								t.Error(err)
								return
							}
							if phase == "socks-bound-address" {
								c.Write([]byte{5, 0, 0, 1, 127})
							}
						}
					}
				}
				close(ready)
				io.Copy(io.Discard, c)
				close(closed)
			})
			scheme := "http"
			if strings.HasPrefix(phase, "https") {
				scheme = "https"
			}
			if strings.HasPrefix(phase, "socks") {
				scheme = "socks5h"
			}
			proxyURL := scheme + "://" + address
			if phase == "socks-auth" {
				proxyURL = scheme + "://u:p@" + address
			}
			endpoint, err := parseTunnelProxy(proxyURL)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				c, err := (&tunnelProxyDialer{endpoint: endpoint, roots: roots}).DialContext(ctx, "tcp", "127.0.0.1:443")
				if c != nil {
					c.Close()
				}
				result <- err
			}()
			p02Await(t, ready, "proxy reached "+phase)
			cancel()
			select {
			case err = <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("%s: %v", phase, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("proxy dial did not stop")
			}
			p02Await(t, closed, "proxy socket close")
		})
	}
}

func TestTLSSetupCancellationDuringDNS(t *testing.T) {
	started, stopped := make(chan struct{}, 2), make(chan struct{}, 2)
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		select {
		case stopped <- struct{}{}:
		default:
		}
		return nil, ctx.Err()
	}}
	rt := newRoundTripper(browser{}, &net.Dialer{Resolver: resolver}).(*roundTripper)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := rt.openTLS(ctx, "tcp", "cancel-dns.invalid:443", nil); result <- err }()
	p02Await(t, started, "DNS request")
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DNS lookup did not stop")
	}
	p02Await(t, stopped, "DNS query cancellation")
}

func FuzzTunnelProxyValidation(f *testing.F) {
	for _, raw := range []string{"http://localhost", "https://u:p@[::1]:443", "socks5://host:1080", "socks5h://host", "http://u:p@host/path", "http://[::1]:0"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		endpoint, err := parseTunnelProxy(raw)
		if err != nil {
			return
		}
		if endpoint == nil {
			t.Fatal("successful validation returned no endpoint")
		}
		if endpoint.Scheme != "http" && endpoint.Scheme != "https" && endpoint.Scheme != "socks5" && endpoint.Scheme != "socks5h" {
			t.Fatal("unsupported proxy accepted")
		}
		if _, _, err = net.SplitHostPort(endpoint.Host); err != nil {
			t.Fatalf("invalid normalized authority: %v", err)
		}
		// Normalization must be idempotent: credentials and escaped IPv6 zones
		// must not turn a valid endpoint into a different destination on reuse.
		again, err := parseTunnelProxy(endpoint.String())
		if err != nil || again.String() != endpoint.String() {
			t.Fatal("proxy normalization is not stable")
		}
		if strings.ContainsAny(endpoint.Host, "\r\n") {
			t.Fatal("unsafe proxy host")
		}
	})
}
