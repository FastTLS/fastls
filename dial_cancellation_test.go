package fastls

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type p02DialFunc func(context.Context, string, string) (net.Conn, error)

func (f p02DialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type p02Body struct {
	once   sync.Once
	closed chan struct{}
}

type p02ObservedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *p02ObservedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func (b *p02Body) Read([]byte) (int, error) { <-b.closed; return 0, io.EOF }
func (b *p02Body) Close() error             { b.once.Do(func() { close(b.closed) }); return nil }

func TestTransportSetupFailureClosesUpload(t *testing.T) {
	for _, scheme := range []string{"https", "unsupported"} {
		t.Run(scheme, func(t *testing.T) {
			body := &p02Body{closed: make(chan struct{})}
			defer body.Close()
			want := errors.New("dial refused")
			rt := newRoundTripper(browser{}, p02DialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, want }))
			request, _ := http.NewRequest("POST", scheme+"://example.invalid/", body)
			if _, err := rt.RoundTrip(request); err == nil {
				t.Fatal("expected setup failure")
			}
			select {
			case <-body.closed:
			case <-time.After(time.Second):
				t.Fatal("setup failure retained upload body")
			}
		})
	}
}

func TestSessionCloseErrorDuringDialAndBody(t *testing.T) {
	t.Run("dial", func(t *testing.T) {
		s, err := NewSession(Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		started, stopped := make(chan struct{}), make(chan struct{})
		rt := s.client.Transport.(*roundTripper)
		rt.dialer = p02DialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			close(stopped)
			return nil, ctx.Err()
		})
		result := make(chan error, 1)
		go func() {
			_, err := s.DoContext(context.Background(), "https://unused.invalid", RequestOptions{}, "GET")
			result <- err
		}()
		p02Await(t, started, "dial start")
		s.Close()
		p02Await(t, stopped, "dial stop")
		select {
		case err := <-result:
			if !errors.Is(err, ErrSessionClosed) || !errors.Is(err, context.Canceled) {
				t.Fatalf("close error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("session request did not stop")
		}
		if _, err := s.DoContext(context.Background(), "https://unused.invalid", RequestOptions{}, "GET"); !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("new request close error = %v", err)
		}
	})
	t.Run("body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "first")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}))
		defer server.Close()
		s, err := NewSession(Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		response, err := s.DoContext(context.Background(), server.URL, RequestOptions{}, "GET")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		first := make([]byte, 5)
		if _, err = io.ReadFull(response.Body, first); err != nil {
			t.Fatal(err)
		}
		s.Close()
		_, err = io.ReadAll(response.Body)
		if !errors.Is(err, ErrSessionClosed) || !errors.Is(err, context.Canceled) {
			t.Fatalf("body close error = %v", err)
		}
	})
}

func p02Await(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s timed out", name)
	}
}

// Retain the cached transport while closing only its idle H2 connection. A
// second request must exercise the transport's redial, not the ALPN probe.
func TestHTTP2SubsequentTLSDialCancellationAndRecovery(t *testing.T) {
	for _, fingerprinted := range []bool{false, true} {
		name := "standard-tls"
		if fingerprinted {
			name = "fingerprinted-tls"
		}
		t.Run(name, func(t *testing.T) { testHTTP2RedialCancellation(t, fingerprinted) })
	}
}

func testHTTP2RedialCancellation(t *testing.T, fingerprinted bool) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("expected H2")
		}
		io.WriteString(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	options := Options{}
	if fingerprinted {
		options.Fingerprint = Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}
	}
	s, err := NewSession(options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rt := s.client.Transport.(*roundTripper)
	firstClosed := make(chan struct{})
	rt.dialer = p02DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &p02ObservedConn{Conn: conn, closed: firstClosed}, nil
	})
	read := func(ctx context.Context) error {
		response, err := s.DoContext(ctx, server.URL, RequestOptions{}, "GET")
		if err == nil {
			_, err = io.ReadAll(response.Body)
			response.Body.Close()
		}
		return err
	}
	if err = read(context.Background()); err != nil {
		t.Fatal(err)
	}
	// EOF can reach the caller just before H2 retires the stream. Wait for
	// the idle close to actually reach the socket instead of assuming a
	// single CloseIdleConnections call has already closed an idle stream.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
closeFirst:
	for {
		rt.mu.Lock()
		for _, transport := range rt.cachedTransports {
			transport.(interface{ CloseIdleConnections() }).CloseIdleConnections()
		}
		rt.mu.Unlock()
		select {
		case <-firstClosed:
			break closeFirst
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("first H2 connection did not become idle")
		}
	}
	stalled, peer := net.Pipe()
	defer stalled.Close()
	defer peer.Close()
	started, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		buffer := make([]byte, 1)
		if _, err := peer.Read(buffer); err == nil {
			close(started)
			io.Copy(io.Discard, peer)
		}
	}()
	var once sync.Once
	rt.dialer = p02DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		var selected bool
		once.Do(func() { selected = true })
		if selected {
			return stalled, nil
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- read(ctx) }()
	p02Await(t, started, "second TLS ClientHello")
	cancel()
	select {
	case err = <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("redial did not cancel")
	}
	p02Await(t, stopped, "cancelled TLS socket close")
	ctx, recoverCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer recoverCancel()
	if err = read(ctx); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
}
