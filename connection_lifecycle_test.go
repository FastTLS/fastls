package fastls

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	fhttp "github.com/FastTLS/fhttp"
)

func fingerprintTestClient(t *testing.T, handler http.Handler, h2 bool) (*fhttp.Client, *httptest.Server) {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.EnableHTTP2 = h2
	s.StartTLS()
	t.Cleanup(s.Close)
	// ALPN advertises H2 and HTTP/1.1; the server controls the selected protocol.
	rt := newRoundTripper(browser{Fingerprint: Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}})
	c := &fhttp.Client{Transport: rt, Timeout: 3 * time.Second}
	t.Cleanup(c.CloseIdleConnections)
	return c, s
}

func readFingerprintResponse(c *fhttp.Client, url string) error {
	r, err := c.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err == nil && string(body) != "ok" {
		return fmt.Errorf("unexpected response %q", body)
	}
	return err
}

func TestFingerprintConnectionSequential(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%t", h2), func(t *testing.T) {
			c, s := fingerprintTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }), h2)
			for i := 0; i < 3; i++ {
				if err := readFingerprintResponse(c, s.URL); err != nil {
					t.Fatalf("request %d: %v", i+1, err)
				}
			}
		})
	}
}

func TestFingerprintConnectionRedirect(t *testing.T) {
	c, s := fingerprintTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}), false)
	if err := readFingerprintResponse(c, s.URL+"/start"); err != nil {
		t.Fatal(err)
	}
}

func TestFingerprintConnectionCloseIdle(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%t", h2), func(t *testing.T) {
			c, s := fingerprintTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }), h2)
			if err := readFingerprintResponse(c, s.URL); err != nil {
				t.Fatal(err)
			}
			c.CloseIdleConnections()
			if err := readFingerprintResponse(c, s.URL); err != nil {
				t.Fatalf("request after idle close: %v", err)
			}
		})
	}
}

func TestFingerprintConnectionCloseIdlePreservesActiveBody(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%t", h2), func(t *testing.T) {
			release := make(chan struct{}, 1)
			c, s := fingerprintTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "first")
				w.(http.Flusher).Flush()
				select {
				case <-release:
					fmt.Fprint(w, "last")
				case <-r.Context().Done():
				}
			}), h2)
			defer close(release)
			r, err := c.Get(s.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Body.Close()
			first := make([]byte, 5)
			if _, err := io.ReadFull(r.Body, first); err != nil {
				t.Fatal(err)
			}
			c.CloseIdleConnections()
			// Keep the handler alive through CloseIdleConnections, then finish it.
			release <- struct{}{}
			body, err := io.ReadAll(r.Body)
			if err != nil || string(body) != "last" {
				t.Fatalf("active body=%q, err=%v", body, err)
			}
		})
	}
}

func TestFingerprintConnectionConcurrent(t *testing.T) {
	c, s := fingerprintTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }), false)
	var wg sync.WaitGroup
	errors := make(chan error, 12)
	for i := 0; i < cap(errors); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- readFingerprintResponse(c, s.URL)
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}
