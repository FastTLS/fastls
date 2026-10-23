package fastls

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDoContextStreamsAndCancels(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		w.Write([]byte("first"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// HTTP does not parse this fingerprint; it exercises the fingerprint transport.
	options := Options{Fingerprint: Ja3Fingerprint{FingerprintValue: "http-test"}}
	resp, err := NewClient().DoContext(ctx, server.URL, options, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Client.CloseIdleConnections()
	defer resp.Body.Close()
	b := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, b); err != nil || string(b) != "first" {
		t.Fatalf("first chunk: %q %v", b, err)
	}
	cancel()
	if _, err := resp.Body.Read(b); err == nil {
		t.Fatal("read after cancel succeeded")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe cancellation")
	}
}

func TestDoContextRejectsCanceledOrNilContext(t *testing.T) {
	c := NewClient()
	if _, err := c.DoContext(nil, "http://unused.invalid", Options{}, "GET"); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.DoContext(ctx, "http://unused.invalid", Options{}, "GET"); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
