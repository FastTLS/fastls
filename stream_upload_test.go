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
