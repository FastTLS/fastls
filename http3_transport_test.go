package fastls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fhttp "github.com/FastTLS/fhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3LocalRequest(t *testing.T) {
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certServer.Close()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: certServer.TLS.Certificates},
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.Proto) }),
	}
	defer server.Close()
	go func() { _ = server.Serve(packetConn) }()
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	for _, trusted := range []bool{true, false} {
		t.Run(fmt.Sprintf("trusted=%t", trusted), func(t *testing.T) {
			cfg := &tls.Config{RootCAs: x509.NewCertPool()}
			if trusted {
				cfg.RootCAs = roots
			}
			transport := &http3.Transport{
				TLSClientConfig: cfg,
				Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
					return (&http3Transport{}).dialQUICEarly(ctx, addr, tlsCfg, quicCfg)
				},
			}
			defer transport.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "GET", "https://"+packetConn.LocalAddr().String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := transport.RoundTrip(req)
			if !trusted {
				if err == nil {
					resp.Body.Close()
					t.Fatal("untrusted certificate was accepted")
				}
				var certErr *tls.CertificateVerificationError
				if !errors.As(err, &certErr) {
					t.Fatalf("expected certificate verification error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 || string(body) != "HTTP/3.0" {
				t.Fatalf("status=%d body=%q", resp.StatusCode, body)
			}
		})
	}
}

func TestHTTP3RequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := fhttp.NewRequestWithContext(ctx, "GET", "https://127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&http3Transport{}).RoundTrip(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled request, got %v", err)
	}
}
