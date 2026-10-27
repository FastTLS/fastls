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
	"strings"
	"testing"
	"time"

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
	req, err := http.NewRequestWithContext(ctx, "GET", "https://127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&http3Transport{}).RoundTrip(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled request, got %v", err)
	}
}

func TestFastlsHTTP3HighLevelTLSAndCookie(t *testing.T) {
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certServer.Close()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: certServer.TLS.Certificates},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s|%d|%s", r.Proto, len(r.Cookies()), r.Header.Get("Cookie"))
		}),
	}
	defer server.Close()
	go func() { _ = server.Serve(packetConn) }()

	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	fingerprint := Ja4Fingerprint{FingerprintValue: "q" + regressionJA4R[1:]}
	options := Options{
		Fingerprint: fingerprint,
		UserAgent:   regressionUA,
		VerifyTLS:   true,
		TLSRootCAs:  roots,
		Cookies:     []Cookie{{Name: "once", Value: "1"}},
		Timeout:     5,
	}
	response, err := NewClient().Do("https://"+packetConn.LocalAddr().String(), options, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Client.CloseIdleConnections()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "HTTP/3.0|1|once=1"; got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
	if response.Protocol != "HTTP/3.0" || response.FinalURL != "https://"+packetConn.LocalAddr().String() {
		t.Fatalf("protocol/final URL = %q/%q", response.Protocol, response.FinalURL)
	}

	options.TLSRootCAs = nil
	untrusted, err := NewClient().Do("https://"+packetConn.LocalAddr().String(), options, "GET")
	if untrusted.Body != nil {
		untrusted.Body.Close()
	}
	untrusted.Client.CloseIdleConnections()
	if err == nil {
		t.Fatal("HTTP/3 accepted an untrusted certificate with VerifyTLS enabled")
	}
}

func TestFastlsHTTP3RejectsProxyAndInvalidSelector(t *testing.T) {
	valid := Ja4Fingerprint{FingerprintValue: "q" + regressionJA4R[1:]}
	response, err := NewClient().Do("https://127.0.0.1:1", Options{
		Fingerprint: valid,
		Proxy:       "http://127.0.0.1:2",
		Timeout:     1,
	}, "GET")
	if response.Body != nil {
		response.Body.Close()
	}
	response.Client.CloseIdleConnections()
	if err == nil || !strings.Contains(err.Error(), "HTTP/3 does not support configured proxies") {
		t.Fatalf("proxy error = %v", err)
	}

	response, err = NewClient().Do("https://127.0.0.1:1", Options{
		Fingerprint: Ja4Fingerprint{FingerprintValue: "q-invalid"},
		Timeout:     1,
	}, "GET")
	if response.Body != nil {
		response.Body.Close()
	}
	response.Client.CloseIdleConnections()
	if err == nil || !strings.Contains(err.Error(), "invalid HTTP/3 JA4R selector") {
		t.Fatalf("selector error = %v", err)
	}
}
