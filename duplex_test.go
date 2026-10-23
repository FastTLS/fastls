package fastls

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type observedDuplexUpload struct {
	io.ReadCloser
	closed chan struct{}
	once   sync.Once
}

func (b *observedDuplexUpload) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { close(b.closed) })
	return err
}

// The server sends headers before reading the request. A blocked producer must
// still be closed by the write deadline, response Close, or session Close.
func TestDuplexEarlyHeadersUploadLifetime(t *testing.T) {
	for _, mode := range []string{"write-timeout", "response-close", "session-close"} {
		t.Run(mode, func(t *testing.T) {
			done := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				io.WriteString(w, "ready")
				w.(http.Flusher).Flush()
				io.Copy(io.Discard, r.Body)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			session, err := NewSession(Options{Fingerprint: Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			reader, writer := io.Pipe()
			upload := &observedDuplexUpload{ReadCloser: reader, closed: make(chan struct{})}
			defer writer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			options := RequestOptions{BodyReader: upload, Duplex: true}
			if mode == "write-timeout" {
				options.Timeouts.Write = 150 * time.Millisecond
			}
			response, err := session.DoContext(ctx, server.URL, options, "POST")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			marker := make([]byte, 5)
			if _, err := io.ReadFull(response.Body, marker); err != nil || string(marker) != "ready" {
				t.Fatalf("response wasn't available before upload: %q, %v", marker, err)
			}
			switch mode {
			case "write-timeout":
				_, err = io.ReadAll(response.Body)
				var phase *TimeoutError
				if !errors.As(err, &phase) || phase.Phase != "write" {
					t.Fatalf("expected write timeout after headers, got %v", err)
				}
			case "response-close":
				response.Body.Close()
			case "session-close":
				session.Close()
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("server did not observe cancellation")
			}
			// RST_STREAM and context.AfterFunc upload cleanup run independently.
			// Observing server cancellation does not order the local Close callback.
			select {
			case <-upload.closed:
			case <-ctx.Done():
				t.Fatal("producer body was not closed after cancellation")
			}
			if _, err := writer.Write([]byte("late")); err != io.ErrClosedPipe {
				t.Fatalf("producer wasn't unblocked: %v", err)
			}
		})
	}
}
