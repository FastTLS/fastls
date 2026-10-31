package fastls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"

	"github.com/FastTLS/ftransport"
	"github.com/quic-go/quic-go/http3"
)

// http3Transport owns its QUIC transport, including the UDP socket. Active
// responses remain active until their bodies finish, not just until headers.
type http3Transport struct {
	sync.Mutex
	Fingerprint   Fingerprint // A selector, not arbitrary QUIC ClientHello ordering.
	UserAgent     string
	VerifyTLS     bool
	TLSRootCAs    *x509.CertPool
	KeepAlive     bool
	Lifetime      context.Context
	AddressPolicy *AddressPolicy
	config        *HTTP3EffectiveConfig

	transport    *http3TransportState
	stopLifetime func() bool
	active       uint64
	retireIdle   bool
	closed       bool
}

func (t *http3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		if req != nil && req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errors.New("fastls: nil HTTP/3 request or URL")
	}
	if len(req.Trailer) > 0 || req.Header.Get("Trailer") != "" {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errors.New("fastls: HTTP/3 request trailers are not supported by the current backend")
	}
	stdReq := req.Clone(req.Context())
	// An explicit empty value also suppresses the default User-Agent.
	if _, exists := stdReq.Header["User-Agent"]; !exists && t.UserAgent != "" {
		if stdReq.Header == nil {
			stdReq.Header = make(http.Header)
		}
		stdReq.Header.Set("User-Agent", t.UserAgent)
	}

	t.Lock()
	if t.closed || (t.Lifetime != nil && t.Lifetime.Err() != nil) {
		t.Unlock()
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, http3.ErrTransportClosed
	}
	if t.transport == nil {
		t.transport = &http3TransportState{initialized: make(chan struct{}), Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            t.TLSRootCAs,
				InsecureSkipVerify: !t.VerifyTLS,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
				NextProtos:         []string{"h3"},
			},
			// Fastls owns content decoding and its decompression budgets.
			DisableCompression: true,
		}}
		if t.config != nil {
			t.transport.QUICConfig = t.config.quicConfig()
			t.transport.MaxResponseHeaderBytes = int(t.config.MaxResponseHeaderBytes)
		}
		if t.AddressPolicy != nil {
			t.transport.policyDialer = &http3PolicyDialer{policy: t.AddressPolicy}
			// The owner below tracks policy and direct connections alike.
		}
		t.transport.connections = &http3Connections{policy: t.transport.policyDialer}
		t.transport.Dial = t.transport.connections.Dial
		// Keep the upstream context-aware DNS, dial and httptrace handling.
		// Close releases both QUIC connections and the transport-owned UDP socket.
		if t.Lifetime != nil {
			t.stopLifetime = context.AfterFunc(t.Lifetime, func() { _ = t.Close() })
		}
	}
	t.active++
	transport := t.transport
	t.Unlock()

	release := t.release
	if stdReq.Body != nil {
		// QUIC stream cancellation cannot interrupt a producer blocked in Read.
		// Keep this ownership past response headers, including early responses.
		source := &http3UploadBody{ReadCloser: stdReq.Body}
		stdReq.Body = source
		stop := context.AfterFunc(stdReq.Context(), func() { _ = source.Close() })
		release = func() {
			stop()
			_ = source.Close()
			t.release()
		}
	}
	response, err := transport.RoundTrip(stdReq)
	if err != nil {
		t.Lock()
		t.retireIdle = true // Retire evicted backend connections once sibling bodies finish.
		t.Unlock()
		release()
		return nil, fmt.Errorf("HTTP/3 request failed: %w", err)
	}
	// The backend replaces Response.Trailer when it reads the final HEADERS.
	// Keep a stable map for the public Response that dispatcher returns.
	result := new(http.Response)
	*result = *response
	result.Request = req
	result.Trailer = response.Trailer.Clone()
	if result.Trailer == nil {
		result.Trailer = make(http.Header)
	}
	expected := response.ContentLength
	if req.Method == http.MethodHead || response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusNotModified {
		expected = -1
	}
	result.Body = &http3Body{
		ReadCloser: response.Body, release: release, expected: expected,
		syncTrailers: func() {
			for name, values := range response.Trailer {
				result.Trailer[name] = append([]string(nil), values...)
			}
		},
	}
	return result, nil
}

// Stats participates in the parent pool's active-response ownership check.
func (t *http3Transport) Stats() ftransport.Stats {
	t.Lock()
	defer t.Unlock()
	return ftransport.Stats{Active: t.active}
}

// detachLocked transfers ownership to the caller, which closes outside the lock.
func (t *http3Transport) detachLocked() *http3TransportState {
	transport := t.transport
	t.transport = nil
	if t.stopLifetime != nil {
		t.stopLifetime()
		t.stopLifetime = nil
	}
	return transport
}

func (t *http3Transport) release() {
	t.Lock()
	t.active--
	var transport *http3TransportState
	if t.active == 0 && (!t.KeepAlive || t.retireIdle) {
		transport = t.detachLocked()
		t.retireIdle = false
	}
	t.Unlock()
	if transport != nil {
		_ = transport.Close()
	}
}

func (t *http3Transport) CloseIdleConnections() {
	t.Lock()
	// quic-go v0.57.1's idle accounting stops at response headers. Do not call
	// its CloseIdleConnections while a Fastls response body is still active.
	t.retireIdle = true
	var transport *http3TransportState
	if t.active == 0 {
		transport = t.detachLocked()
		t.retireIdle = false
	}
	t.Unlock()
	if transport != nil {
		_ = transport.Close()
	}
}

func (t *http3Transport) Close() error {
	t.Lock()
	t.closed = true
	transport := t.detachLocked()
	t.Unlock()
	if transport != nil {
		return transport.Close()
	}
	return nil
}

type http3Body struct {
	io.ReadCloser
	once               sync.Once
	release            func()
	syncTrailers       func()
	expected, received int64
}

// quic-go v0.57.1 initializes its UDP transport in RoundTrip without taking
// the mutex used by Close. GetConn runs after that initialization and before
// network dialing. Close waits only for initialization, never for a handshake.
type http3TransportState struct {
	*http3.Transport
	initialized  chan struct{}
	initOnce     sync.Once
	policyDialer *http3PolicyDialer
	connections  *http3Connections
}

func (s *http3TransportState) markInitialized() {
	s.initOnce.Do(func() { close(s.initialized) })
}

func (s *http3TransportState) RoundTrip(req *http.Request) (*http.Response, error) {
	defer s.markInitialized() // Includes validation / initialization errors.
	trace := &httptrace.ClientTrace{GetConn: func(string) { s.markInitialized() }}
	return s.Transport.RoundTrip(req.Clone(httptrace.WithClientTrace(req.Context(), trace)))
}

func (s *http3TransportState) Close() error {
	<-s.initialized
	if s.connections != nil {
		s.connections.closeConnections()
	}
	err := s.Transport.Close()
	if s.connections != nil {
		s.connections.closeSockets()
	} else if s.policyDialer != nil {
		s.policyDialer.Close()
	}
	return err
}

type http3UploadBody struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (b *http3UploadBody) Close() error {
	b.once.Do(func() { b.err = b.ReadCloser.Close() })
	return b.err
}

func (b *http3Body) finish() {
	b.once.Do(func() { _ = b.ReadCloser.Close(); b.release() })
}
func (b *http3Body) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.received += int64(n)
	if err == io.EOF && b.expected >= 0 && b.received < b.expected {
		err = io.ErrUnexpectedEOF
	}
	if b.syncTrailers != nil {
		b.syncTrailers()
	}
	if err != nil {
		b.finish()
	}
	return n, err
}
func (b *http3Body) Close() error {
	var err error
	b.once.Do(func() { err = b.ReadCloser.Close(); b.release() })
	return err
}

func newHTTP3Transport(fingerprint Fingerprint, userAgent string, verifyTLS bool, roots *x509.CertPool) (*http3Transport, error) {
	if fingerprint != nil && !fingerprint.IsEmpty() {
		if !strings.HasPrefix(fingerprint.Value(), "q") {
			return nil, errors.New("fastls: HTTP/3 requires a q-prefixed JA4R selector")
		}
		if _, err := ParseJA4R(fingerprint.Value(), userAgent); err != nil {
			return nil, fmt.Errorf("fastls: invalid HTTP/3 JA4R selector: %w", err)
		}
	}
	return &http3Transport{Fingerprint: fingerprint, UserAgent: userAgent, VerifyTLS: verifyTLS, TLSRootCAs: roots}, nil
}
