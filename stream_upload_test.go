package fastls

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStreamingUploadWriteTimeoutClosesBlockedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body) }))
	defer server.Close()
	session, err := NewSession(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = session.DoContext(ctx, server.URL, RequestOptions{BodyReader: reader, Timeouts: Timeouts{Write: 50 * time.Millisecond}}, "POST")
	var phase *TimeoutError
	if !errors.As(err, &phase) || phase.Phase != "write" {
		t.Fatalf("expected write timeout, got %v", err)
	}
	if _, err := writer.Write([]byte("late")); err != io.ErrClosedPipe {
		t.Fatalf("reader wasn't closed: %v", err)
	}
}

func TestStreamingUploadRedirectReportsFinalBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", 302)
			return
		}
		io.Copy(io.Discard, r.Body)
	}))
	defer server.Close()
	session, err := NewSession(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, path := range []string{"/redirect", "/final"} {
		response, err := session.DoContext(context.Background(), server.URL+path, RequestOptions{BodyReader: io.NopCloser(strings.NewReader("data"))}, "POST")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.RequestHasBody != (path == "/final") {
			t.Fatalf("wrong final request body state for %s", path)
		}
	}
}
