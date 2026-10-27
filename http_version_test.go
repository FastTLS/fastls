package fastls

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FastTLS/fastls/profile"
)

func TestH3ExplicitVersionWithoutFingerprint(t *testing.T) {
	fixture, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Proto) }))
	options := Options{HTTPVersion: HTTPVersion3, VerifyTLS: true, TLSRootCAs: fixture.options.TLSRootCAs}
	session, err := NewSession(options)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for i := 0; i < 2; i++ {
		response, err := session.DoContext(context.Background(), url, RequestOptions{}, "GET")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "HTTP/3.0" || response.Protocol != "HTTP/3.0" {
			t.Fatalf("body=%q protocol=%q error=%v", body, response.Protocol, err)
		}
	}
	response, err := NewClient().Do(url, options, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	if response.Protocol != "HTTP/3.0" {
		t.Fatalf("one-shot protocol = %q", response.Protocol)
	}
}

func TestH3ExplicitVersionRejectsIncompatibleOptions(t *testing.T) {
	cases := []struct {
		name    string
		options Options
	}{
		{"unknown version", Options{HTTPVersion: "h4"}},
		{"proxy", Options{HTTPVersion: HTTPVersion3, Proxy: "http://127.0.0.1:1"}},
		{"profile", Options{HTTPVersion: HTTPVersion3, Profile: &profile.Spec{}}},
		{"JA3", Options{HTTPVersion: HTTPVersion3, Fingerprint: Ja3Fingerprint{FingerprintValue: "771,4865,0,29,0"}}},
		{"TCP JA4R", Options{HTTPVersion: HTTPVersion3, Fingerprint: Ja4Fingerprint{FingerprintValue: regressionJA4R}}},
		{"bad QUIC selector", Options{HTTPVersion: HTTPVersion3, Fingerprint: Ja4Fingerprint{FingerprintValue: "q-invalid"}}},
		{"H2 settings", Options{HTTPVersion: HTTPVersion3, HTTP2SettingsString: "invalid"}},
		{"TLS extensions", Options{HTTPVersion: HTTPVersion3, TLSExtensions: &TLSExtensions{}}},
		{"signature algorithms", Options{HTTPVersion: HTTPVersion3, FingerprintSignatureAlgorithms: []uint16{0x0403}}},
		{"header order", Options{HTTPVersion: HTTPVersion3, HeaderOrderKeys: []string{"accept"}}},
		{"pseudo order", Options{HTTPVersion: HTTPVersion3, PHeaderOrderKeys: []string{":method"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if session, err := NewSession(tc.options); err == nil {
				session.Close()
				t.Fatal("unsupported configuration was accepted")
			}
		})
	}
}

func TestH3ForcedVersionDoesNotDowngrade(t *testing.T) {
	var requests atomic.Int32
	tcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer tcp.Close()
	fixture, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, tcp.URL, http.StatusFound) }))
	session, err := NewSession(Options{HTTPVersion: HTTPVersion3, VerifyTLS: true, TLSRootCAs: fixture.options.TLSRootCAs})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, target := range []string{tcp.URL, url} {
		response, err := session.DoContext(context.Background(), target, RequestOptions{}, "GET")
		if response.Body != nil {
			response.Body.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "requires an https URL") {
			t.Fatalf("target=%s error=%v", target, err)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("made %d forbidden TCP requests", got)
	}
}

func TestH3ForcedVersionDoesNotFallbackToTCP(t *testing.T) {
	var requests atomic.Int32
	tcp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer tcp.Close()
	session, err := NewSession(Options{HTTPVersion: HTTPVersion3, VerifyTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	response, err := session.DoContext(ctx, tcp.URL, RequestOptions{}, "GET")
	if response.Body != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("H3 unexpectedly succeeded against a TCP-only server")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("made %d fallback requests", got)
	}
}

func TestH3ConcurrentFirstUseAndClose(t *testing.T) {
	fixture, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		transport, err := newHTTP3Transport(nil, "", true, fixture.options.TLSRootCAs)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			response, _ := transport.RoundTrip(request)
			if response != nil {
				response.Body.Close()
			}
		}()
		go func() { defer group.Done(); _ = transport.Close(); cancel() }()
		group.Wait()
		cancel()
		if active := transport.Stats().Active; active != 0 {
			t.Fatalf("active requests = %d", active)
		}
	}
}

func TestH3ForcedVersionIsNotSilentlyUsedForWebSocket(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	options := Options{HTTPVersion: HTTPVersion3, Fingerprint: Ja4Fingerprint{FingerprintValue: "q" + regressionJA4R[1:]}}
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	if _, _, err := DialWebSocketContext(context.Background(), endpoint, options, nil); err == nil || !strings.Contains(err.Error(), "HTTPVersion") {
		t.Fatalf("context dial error = %v", err)
	}
	if _, _, err := NewWebSocketClientWithOptions(options).Connect(endpoint); err == nil || !strings.Contains(err.Error(), "HTTPVersion") {
		t.Fatalf("legacy dial error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("forced H3 WebSocket fell back to TCP")
	}
}
