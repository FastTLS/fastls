package fastls

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionConnectionReuseAndClose(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint(h2), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.RemoteAddr) }))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			s, err := NewSession(Options{Fingerprint: Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			read := func() string {
				r, err := s.DoContext(context.Background(), server.URL, RequestOptions{}, "GET")
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(r.Body)
				r.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				return string(data)
			}
			first := read()
			for i := 0; i < 4; i++ {
				if next := read(); next != first {
					t.Fatalf("connection not reused: %s -> %s", first, next)
				}
			}
			s.CloseIdleConnections()
			if next := read(); next == first {
				t.Fatal("idle connection was not closed")
			}
			s.Close()
			s.Close()
			if _, err := s.DoContext(context.Background(), server.URL, RequestOptions{}, "GET"); err == nil {
				t.Fatal("closed session accepted request")
			}
		})
	}
}
