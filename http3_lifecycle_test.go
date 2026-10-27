package fastls

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func localH3Session(t *testing.T, handler http.Handler) (*Session, string) {
	t.Helper()
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(cert.Close)
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: cert.TLS.Certificates}, Handler: handler}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(packet) }()
	t.Cleanup(func() { _ = server.Close(); _ = packet.Close(); <-done })
	roots := x509.NewCertPool()
	roots.AddCert(cert.Certificate())
	session, err := NewSession(Options{Fingerprint: Ja4Fingerprint{FingerprintValue: "q" + regressionJA4R[1:]}, UserAgent: regressionUA, VerifyTLS: true, TLSRootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	return session, "https://" + packet.LocalAddr().String()
}

func TestH3RequestHeaderOverride(t *testing.T) {
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.UserAgent()) }))
	for _, ua := range []string{"per-request-agent", ""} {
		response, err := session.DoContext(context.Background(), url, RequestOptions{Headers: map[string]string{"User-Agent": ua}}, "GET")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != ua {
			t.Fatalf("User-Agent = %q, want %q (read: %v)", body, ua, err)
		}
	}
}

func TestH3ExplicitResponseDecoding(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = zw.Write([]byte("encoded h3 response"))
	_ = zw.Close()
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))
	for _, decode := range []bool{false, true} {
		response, err := session.DoContext(context.Background(), url, RequestOptions{DecodeContent: decode}, "GET")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		want := compressed.Bytes()
		if decode {
			want = []byte("encoded h3 response")
		}
		if err != nil || !bytes.Equal(body, want) {
			t.Fatalf("decode=%t body=%q, want %q (read: %v)", decode, body, want, err)
		}
	}
}

func TestH3CloseIdlePreservesActiveBody(t *testing.T) {
	finish := make(chan struct{})
	var finishOnce sync.Once
	release := func() { finishOnce.Do(func() { close(finish) }) }
	defer release()
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		select {
		case <-finish:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "second")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := session.DoContext(ctx, url, RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	first := make([]byte, 5)
	if _, err := io.ReadFull(response.Body, first); err != nil {
		t.Fatal(err)
	}
	session.CloseIdleConnections()
	// An active response must retain its transport and connection.
	if got := len(session.client.Transport.(*roundTripper).cachedTransports); got != 1 {
		t.Errorf("active transports = %d, want 1", got)
	}
	release()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "second" {
		t.Fatalf("active body after CloseIdleConnections: %q, %v", body, err)
	}
	response.Body.Close()
	session.CloseIdleConnections()
	if got := len(session.client.Transport.(*roundTripper).cachedTransports); got != 0 {
		t.Fatalf("idle transports = %d, want 0", got)
	}
}

func TestH3PhaseTimeouts(t *testing.T) {
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/headers":
			<-r.Context().Done()
		case "/body":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/upload":
			_, _ = io.Copy(io.Discard, r.Body)
		}
	}))
	for _, phase := range []string{"headers", "read", "write"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			options := RequestOptions{}
			path, method := "/headers", "GET"
			switch phase {
			case "headers":
				options.Timeouts.Headers = 50 * time.Millisecond
			case "read":
				options.Timeouts.Read = 50 * time.Millisecond
				path = "/body"
			case "write":
				reader, writer := io.Pipe()
				defer writer.Close()
				options.BodyReader = reader
				options.Timeouts.Write = 50 * time.Millisecond
				path, method = "/upload", "POST"
			}
			response, err := session.DoContext(ctx, url+path, options, method)
			if response.Body != nil {
				defer response.Body.Close()
			}
			if err == nil && phase == "read" {
				_, err = io.ReadAll(response.Body)
			}
			var timeout *TimeoutError
			if !errors.As(err, &timeout) || timeout.Phase != phase {
				t.Fatalf("want %s timeout, got %v", phase, err)
			}
		})
	}
}

func TestH3ConnectTimeout(t *testing.T) {
	// Accept UDP packets but never complete QUIC. No external server or DNS.
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	session, err := NewSession(Options{Fingerprint: Ja4Fingerprint{FingerprintValue: "q" + regressionJA4R[1:]}, VerifyTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = session.DoContext(ctx, "https://"+packet.LocalAddr().String(), RequestOptions{Timeouts: Timeouts{Connect: 50 * time.Millisecond}}, "GET")
	var timeout *TimeoutError
	if !errors.As(err, &timeout) || timeout.Phase != "connect" {
		t.Fatalf("want connect timeout, got %v", err)
	}
}

func currentH3(t *testing.T, session *Session) *http3Transport {
	t.Helper()
	rt := session.client.Transport.(*roundTripper)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, transport := range rt.cachedTransports {
		if h3, ok := transport.(*http3Transport); ok {
			return h3
		}
	}
	t.Fatal("no H3 transport")
	return nil
}

func TestH3IdleCloseReleasesTransportAndReconnects(t *testing.T) {
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	response, err := session.DoContext(context.Background(), url, RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	h3 := currentH3(t, session)
	h3.Lock()
	owned := h3.transport
	h3.Unlock()
	session.CloseIdleConnections()
	req, _ := http.NewRequest("GET", url, nil)
	if _, err := owned.RoundTrip(req); !errors.Is(err, http3.ErrTransportClosed) {
		t.Fatalf("discarded transport not closed: %v", err)
	}
	response, err = session.DoContext(context.Background(), url, RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("reconnected response = %q, %v", body, err)
	}
}

func TestH3SessionCloseCancelsUnreadBody(t *testing.T) {
	stopped := make(chan struct{})
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(stopped)
	}))
	response, err := session.DoContext(context.Background(), url, RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	h3 := currentH3(t, session)
	session.Close()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("session close did not terminate the peer stream")
	}
	if _, err := io.ReadAll(response.Body); err == nil {
		t.Fatal("session close became a successful EOF")
	}
	// Terminal reads and repeated Close must return the active lease only once.
	response.Body.Close()
	response.Body.Close()
	if active := h3.Stats().Active; active != 0 {
		t.Fatalf("active responses after close = %d", active)
	}
	if _, err := session.DoContext(context.Background(), url, RequestOptions{}, "GET"); err == nil {
		t.Fatal("closed session accepted a request")
	}
}

func TestH3CancellationPreservesSiblingStream(t *testing.T) {
	finish := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(finish) }) }
	defer release()
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-finish:
			_, _ = io.WriteString(w, "sibling survived")
		case <-r.Context().Done():
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, err := session.DoContext(ctx, url, RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	secondCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	second, err := session.DoContext(secondCtx, url, RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	cancel()
	if _, err := io.ReadAll(first.Body); err == nil {
		t.Fatal("cancelled response returned EOF")
	}
	release()
	body, err := io.ReadAll(second.Body)
	if err != nil || string(body) != "sibling survived" {
		t.Fatalf("sibling stream: %q, %v", body, err)
	}
}

// Generates deterministic bytes without retaining the large body in memory.
type h3PatternReader struct{ offset int64 }

func (r *h3PatternReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte((r.offset + int64(i)) % 251)
	}
	r.offset += int64(len(p))
	return len(p), nil
}

func TestH3LargeStreamingUploadAndDownload(t *testing.T) {
	const size int64 = 64 << 20
	want := sha256.New()
	_, _ = io.CopyN(want, &h3PatternReader{}, size)
	wantDigest := fmt.Sprintf("%x", want.Sum(nil))
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		digest := sha256.New()
		n, err := io.Copy(digest, r.Body)
		if err != nil || n != size {
			http.Error(w, "incomplete upload", 400)
			return
		}
		w.Header().Set("X-Upload-SHA256", fmt.Sprintf("%x", digest.Sum(nil)))
		w.Header().Set("Content-Length", fmt.Sprint(size))
		w.Header().Add("Set-Cookie", "a=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Path=/")
		_, _ = io.CopyN(w, &h3PatternReader{}, size)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	response, err := session.DoContext(ctx, url, RequestOptions{BodyReader: io.NopCloser(io.LimitReader(&h3PatternReader{}, size))}, "POST")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	digest := sha256.New()
	n, err := io.Copy(digest, response.Body)
	if err != nil || n != size || fmt.Sprintf("%x", digest.Sum(nil)) != wantDigest {
		t.Fatalf("download size=%d digest=%x error=%v", n, digest.Sum(nil), err)
	}
	if response.Status != 200 || response.Protocol != "HTTP/3.0" {
		t.Fatalf("status/protocol = %d/%s", response.Status, response.Protocol)
	}
	if got := http.Header(response.HeaderValues).Get("X-Upload-SHA256"); got != wantDigest {
		t.Fatalf("upload digest = %s, want %s", got, wantDigest)
	}
	if got := len(http.Header(response.HeaderValues).Values("Set-Cookie")); got != 2 {
		t.Fatalf("Set-Cookie count = %d", got)
	}
}

func TestH3OneShotClosesOwnedTransport(t *testing.T) {
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "once") }))
	transport, err := newHTTP3Transport(session.options.Fingerprint, regressionUA, true, session.options.TLSRootCAs)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	req, _ := http.NewRequest("GET", url, nil)
	response, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	transport.Lock()
	owned := transport.transport
	transport.Unlock()
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "once" {
		t.Fatalf("body = %q, %v", body, err)
	}
	if _, err := owned.RoundTrip(req); !errors.Is(err, http3.ErrTransportClosed) {
		t.Fatalf("one-shot transport not closed at EOF: %v", err)
	}
}

func TestH3DecodedSizeLimit(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(bytes.Repeat([]byte("x"), 4096))
	_ = writer.Close()
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))
	response, err := session.DoContext(context.Background(), url, RequestOptions{DecodeContent: true, MaxDecodedBytes: 1024}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err == nil || len(body) > 1024 {
		t.Fatalf("decoded limit bypassed: bytes=%d error=%v", len(body), err)
	}
}

type h3BlockedUpload struct {
	started, closed      chan struct{}
	startOnce, closeOnce sync.Once
}

func (b *h3BlockedUpload) Read([]byte) (int, error) {
	b.startOnce.Do(func() { close(b.started) })
	<-b.closed
	return 0, io.ErrClosedPipe
}
func (b *h3BlockedUpload) Close() error { b.closeOnce.Do(func() { close(b.closed) }); return nil }

func TestH3EarlyResponseReleasesBlockedUpload(t *testing.T) {
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "early") }))
	source := &h3BlockedUpload{started: make(chan struct{}), closed: make(chan struct{})}
	defer source.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := session.DoContext(ctx, url, RequestOptions{BodyReader: source}, "POST")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("upload producer was not started")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "early" {
		t.Fatalf("early response = %q, %v", body, err)
	}
	select {
	case <-source.closed:
	case <-time.After(time.Second):
		t.Fatal("response EOF left upload producer blocked")
	}
}
