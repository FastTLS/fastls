package fastls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FastTLS/ftransport"
)

func TestRequestLifecycleRedirect(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		for _, disabled := range []bool{true, false} {
			t.Run(fmt.Sprintf("%d/disabled=%t", code, disabled), func(t *testing.T) {
				var hits atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/start" {
						http.Redirect(w, r, "/end", code)
						return
					}
					hits.Add(1)
					body, _ := io.ReadAll(r.Body)
					fmt.Fprintf(w, "%s:%s", r.Method, body)
				}))
				defer server.Close()
				resp, err := NewClient().Do(server.URL+"/start", Options{DisableRedirect: disabled, Body: "payload", Timeout: 3}, "POST")
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Client.CloseIdleConnections()
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if disabled {
					if resp.Status != code || hits.Load() != 0 {
						t.Fatalf("status=%d, target hits=%d; want %d, 0", resp.Status, hits.Load(), code)
					}
				} else {
					want := "GET:"
					if code == 307 || code == 308 {
						want = "POST:payload"
					}
					if resp.Status != 200 || hits.Load() != 1 || string(body) != want {
						t.Fatalf("status=%d, target hits=%d, body=%q; want 200, 1, %q", resp.Status, hits.Load(), body, want)
					}
				}
			})
		}
	}
}

func TestRequestLifecycleCanceledRoundTrip(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "unexpected")
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := newRoundTripper(browser{})
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	rt.(interface{ CloseIdleConnections() }).CloseIdleConnections()
	if !errors.Is(err, context.Canceled) || hits.Load() != 0 {
		t.Fatalf("err=%v, hits=%d; want context.Canceled, 0", err, hits.Load())
	}
}

func TestRequestLifecycleCancelBeforeHeaders(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		resp, err := NewClient().DoContext(ctx, server.URL, Options{Timeout: 3}, "GET")
		if resp.Body != nil {
			resp.Body.Close()
		}
		resp.Client.CloseIdleConnections()
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach server")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt response header wait")
	}
}

func TestRequestLifecycleStreamingCancel(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		resp Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := NewClient().DoContext(ctx, server.URL, Options{Timeout: 3}, "GET")
		done <- result{resp, err}
	}()
	var res result
	select {
	case res = <-done:
	case <-time.After(time.Second):
		// Release the server and collect the result so a failing old implementation
		// cannot leave a background request or an unclosed response behind.
		cancel()
		select {
		case res = <-done:
		case <-time.After(4 * time.Second):
			t.Fatal("request failed to stop")
		}
		if res.resp.Body != nil {
			res.resp.Body.Close()
		}
		res.resp.Client.CloseIdleConnections()
		t.Fatal("DoContext buffered the response instead of returning after headers")
	}
	if res.err != nil {
		t.Fatal(res.err)
	}
	defer res.resp.Client.CloseIdleConnections()
	defer res.resp.Body.Close()
	first := make([]byte, 5)
	if _, err := io.ReadFull(res.resp.Body, first); err != nil || string(first) != "first" {
		t.Fatalf("first chunk=%q, err=%v", first, err)
	}
	cancel()
	_, err := io.ReadAll(res.resp.Body)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("body read returned %v, want context.Canceled", err)
	}
}

func TestRequestLifecycleStdlibAdapterMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s|%d|%s|%s", r.Host, r.ContentLength, r.Header.Get("User-Agent"), body)
	}))
	defer server.Close()
	req, err := http.NewRequest("POST", server.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "virtual.example"
	req.Header["User-Agent"] = []string{""}
	req, err = ftransport.WithRequestOptions(req, ftransport.RequestOptions{HeaderOrder: []string{"user-agent"}})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	resp, err := (&stdlibTransportAdapter{transport: transport}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "virtual.example|7||payload" {
		t.Fatalf("body=%q, err=%v", body, err)
	}
	if resp.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength=%d, want %d", resp.ContentLength, len(body))
	}
}

func TestRequestLifecycleTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		case <-time.After(3 * time.Second):
		}
	}))
	defer server.Close()
	defer close(release)
	started := time.Now()
	resp, err := NewClient().Do(server.URL, Options{Timeout: 1}, "GET")
	if resp.Body != nil {
		resp.Body.Close()
	}
	resp.Client.CloseIdleConnections()
	elapsed := time.Since(started)
	var timeout net.Error
	timedOut := errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout())
	if !timedOut || elapsed < 750*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Fatalf("err=%v, elapsed=%v; want request timeout near 1s", err, elapsed)
	}
}

func TestRequestLifecycleCloseBody(t *testing.T) {
	disconnected := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(disconnected)
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	resp, err := NewClient().Do(server.URL, Options{Timeout: 2}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Client.CloseIdleConnections()
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("closing the response body did not release the connection")
	}
}

func TestRequestLifecycleCloseIdleConnections(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	rt := newRoundTripper(browser{})
	closer := rt.(interface{ CloseIdleConnections() })
	defer closer.CloseIdleConnections()
	// Closing before first use must permit future requests.
	closer.CloseIdleConnections()
	for i := 0; i < 3; i++ {
		if i == 2 {
			closer.CloseIdleConnections()
		}
		req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := int32(1)
		if i == 2 {
			want = 2
		}
		if connections.Load() != want {
			t.Fatalf("request %d opened %d connections; want %d", i, connections.Load(), want)
		}
	}
}

func TestRequestLifecycleBodyTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	resp, err := NewClient().Do(server.URL, Options{Timeout: 1}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Client.CloseIdleConnections()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	var timeout net.Error
	if string(body) != "first" || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("body=%q, err=%v; want first chunk and timeout during read", body, err)
	}
}

func TestRequestLifecycleResponseTrailers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Checksum")
		fmt.Fprint(w, "payload")
		w.Header().Set("X-Checksum", "verified")
	}))
	defer server.Close()
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	resp, err := (&stdlibTransportAdapter{transport: transport}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if got := resp.Trailer.Get("X-Checksum"); got != "verified" {
		t.Fatalf("trailer=%q, want verified after EOF", got)
	}
}
