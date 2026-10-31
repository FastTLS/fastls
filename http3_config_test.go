package fastls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

func durationPointer(d time.Duration) *time.Duration { return &d }

func TestHTTP3ConfigValidationBeforeDNS(t *testing.T) {
	var queries atomic.Int32
	p := mustPolicy(t, AddressPolicyConfig{AllowHosts: []string{"example.com"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		queries.Add(1)
		return nil, errors.New("unexpected DNS")
	})})
	cases := []HTTP3Config{
		{InitialStreamReceiveWindow: 1}, {InitialStreamReceiveWindow: 1 << 63}, {MaxStreamReceiveWindow: 1}, {MaxStreamReceiveWindow: ^uint64(0)},
		{InitialConnectionReceiveWindow: 1}, {InitialConnectionReceiveWindow: 1 << 63}, {MaxConnectionReceiveWindow: 1}, {MaxConnectionReceiveWindow: ^uint64(0)},
		{InitialStreamReceiveWindow: 8 << 20}, {InitialConnectionReceiveWindow: 16 << 20},
		{MaxIdleTimeout: -1}, {MaxIdleTimeout: time.Second + time.Nanosecond}, {MaxIdleTimeout: time.Millisecond}, {MaxIdleTimeout: 25 * time.Hour},
		{KeepAlivePeriod: durationPointer(-1)}, {KeepAlivePeriod: durationPointer(time.Millisecond)}, {KeepAlivePeriod: durationPointer(16 * time.Second)},
		{MaxResponseHeaderBytes: -1}, {MaxResponseHeaderBytes: 1023}, {MaxResponseHeaderBytes: 1 << 62},
	}
	for i, c := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			options := Options{HTTPVersion: HTTPVersion3, HTTP3: &c, AddressPolicy: p}
			if s, err := NewSession(options); err == nil {
				s.Close()
				t.Fatal("invalid configuration accepted")
			}
			if _, err := NewClient().Do("https://example.com/", options, "GET"); err == nil {
				t.Fatal("one-shot accepted invalid configuration")
			}
		})
	}
	for _, version := range []HTTPVersion{HTTPVersionAuto, "h2", "h4"} {
		if s, err := NewSession(Options{HTTPVersion: version, HTTP3: &HTTP3Config{}}); err == nil {
			s.Close()
			t.Fatal("implicit protocol accepted")
		}
	}
	if s, err := NewSession(Options{Fingerprint: Ja4Fingerprint{FingerprintValue: "q" + regressionJA4R[1:]}, HTTP3: &HTTP3Config{}}); err == nil {
		s.Close()
		t.Fatal("legacy selector enabled new config")
	}
	if queries.Load() != 0 {
		t.Fatal("validation reached DNS")
	}
	for _, window := range []uint64{4 << 10, 64 << 20} {
		_, err := normalizeHTTP3(&HTTP3Config{InitialStreamReceiveWindow: window, MaxStreamReceiveWindow: window, InitialConnectionReceiveWindow: window, MaxConnectionReceiveWindow: window})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, idle := range []time.Duration{100 * time.Millisecond, 24 * time.Hour} {
		if _, err := normalizeHTTP3(&HTTP3Config{MaxIdleTimeout: idle}); err != nil {
			t.Fatal(err)
		}
	}
	for _, header := range []int64{1024, 16 << 20} {
		if _, err := normalizeHTTP3(&HTTP3Config{MaxResponseHeaderBytes: header}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTP3ConfigDefaultsSnapshotsAndCapabilities(t *testing.T) {
	a, err := (Options{HTTPVersion: HTTPVersion3}).EffectiveHTTP3Config()
	if err != nil {
		t.Fatal(err)
	}
	b, err := (Options{HTTPVersion: HTTPVersion3, HTTP3: &HTTP3Config{}}).EffectiveHTTP3Config()
	if err != nil || a != b {
		t.Fatal(a, b, err)
	}
	if a.InitialStreamReceiveWindow != 512<<10 || a.MaxStreamReceiveWindow != 6<<20 || a.InitialConnectionReceiveWindow != 512<<10 || a.MaxConnectionReceiveWindow != 15<<20 || a.MaxIdleTimeout != 30*time.Second || a.KeepAlivePeriod != 10*time.Second || a.MaxResponseHeaderBytes != 10<<20 {
		t.Fatal(a)
	}
	if a.quicConfig().MaxIncomingStreams != -1 {
		t.Fatal("changed H3 defaults")
	}
	if _, err := (Options{}).EffectiveHTTP3Config(); err == nil {
		t.Fatal("auto has no explicit configuration")
	}
	caps := HTTP3Capabilities()
	if len(caps) != 7 {
		t.Fatal(caps)
	}
	caps[0].Name = "mutated"
	if HTTP3Capabilities()[0].Name == "mutated" {
		t.Fatal("shared discovery storage")
	}
	config := &HTTP3Config{KeepAlivePeriod: durationPointer(0), MaxResponseHeaderBytes: 2048}
	opts := Options{HTTPVersion: HTTPVersion3, HTTP3: config}
	s, err := NewSession(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	preparedOpts := opts
	preparedOpts.URL = "https://example.com"
	preparedOpts.Method = "GET"
	prepared, err := processRequest(&preparedOpts)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxResponseHeaderBytes = 4096
	*config.KeepAlivePeriod = time.Second
	e, ok := s.EffectiveHTTP3Config()
	if !ok || e.MaxResponseHeaderBytes != 2048 || e.KeepAlivePeriod != 0 {
		t.Fatal(e)
	}
	rt := prepared.client.Transport.(*roundTripper)
	if rt.HTTP3.MaxResponseHeaderBytes != 2048 || rt.HTTP3.KeepAlivePeriod != 0 {
		t.Fatal("one-shot retained caller pointer")
	}
	e.MaxResponseHeaderBytes = 0
	again, _ := s.EffectiveHTTP3Config()
	if again.MaxResponseHeaderBytes != 2048 {
		t.Fatal("returned config mutates session")
	}
	s2, err := NewSession(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	other, _ := s2.EffectiveHTTP3Config()
	if other.MaxResponseHeaderBytes != 4096 || s.client.Transport == s2.client.Transport {
		t.Fatal("owner/config shared")
	}
}

// peerTrace observes received wire events at the independent server, not the
// client configuration object. It retains scalar values only, never backend buffers.
type peerTrace struct {
	mu                                 sync.Mutex
	params                             []qlog.ParametersSet
	streamCredit, connectionCredit     uint64
	maxStreamGrant, maxConnectionGrant uint64
	pings                              int
	consumed                           atomic.Uint64
	exceeded                           bool
}

func (p *peerTrace) AddProducer() qlogwriter.Recorder { return p }
func (*peerTrace) SupportsSchemas(string) bool        { return true }
func (*peerTrace) Close() error                       { return nil }
func (p *peerTrace) RecordEvent(event qlogwriter.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch e := event.(type) {
	case qlog.ParametersSet:
		if e.Initiator == qlog.InitiatorRemote {
			p.params = append(p.params, e)
		}
	case qlog.PacketReceived:
		for _, frame := range e.Frames {
			switch f := frame.Frame.(type) {
			case *qlog.MaxStreamDataFrame:
				if f.StreamID == 0 {
					credit := uint64(f.MaximumStreamData)
					if credit > p.streamCredit {
						p.maxStreamGrant = max(p.maxStreamGrant, credit-p.streamCredit)
						p.streamCredit = credit
					}
					if credit > p.consumed.Load()+(64<<10)+(16<<10) {
						p.exceeded = true
					}
				}
			case *qlog.MaxDataFrame:
				credit := uint64(f.MaximumData)
				if credit > p.connectionCredit {
					p.maxConnectionGrant = max(p.maxConnectionGrant, credit-p.connectionCredit)
					p.connectionCredit = credit
				}
				if credit > p.consumed.Load()+(128<<10)+(16<<10) {
					p.exceeded = true
				}
			case *qlog.PingFrame:
				p.pings++
			}
		}
	}
}

func configH3Origin(t *testing.T, handler http.Handler, trace *peerTrace) (string, *x509.CertPool) {
	t.Helper()
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(cert.Close)
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	qc := &quic.Config{MaxIdleTimeout: 10 * time.Second}
	if trace != nil {
		qc.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }
	}
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: cert.TLS.Certificates}, QUICConfig: qc, Handler: handler}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(packet) }()
	t.Cleanup(func() { _ = server.Close(); _ = packet.Close(); <-done })
	roots := x509.NewCertPool()
	roots.AddCert(cert.Certificate())
	return "https://" + packet.LocalAddr().String(), roots
}

func TestHTTP3ConfigPeerFlowControl(t *testing.T) {
	trace := &peerTrace{streamCredit: 16 << 10, connectionCredit: 32 << 10}
	endpoint, roots := configH3Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		block := strings.Repeat("x", 4096)
		for range 512 {
			if _, err := io.WriteString(w, block); err != nil {
				return
			}
		}
	}), trace)
	config := &HTTP3Config{InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 64 << 10, InitialConnectionReceiveWindow: 32 << 10, MaxConnectionReceiveWindow: 128 << 10, KeepAlivePeriod: durationPointer(0)}
	s, err := NewSession(Options{HTTPVersion: HTTPVersion3, HTTP3: config, VerifyTLS: true, TLSRootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := s.DoContext(ctx, endpoint, RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	// Slow consumption exercises credit replenishment and a bounded unread window.
	buf := make([]byte, 4096)
	var total int
	for {
		n, err := response.Body.Read(buf)
		trace.consumed.Add(uint64(n))
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if total > 1<<20 {
			time.Sleep(time.Millisecond)
		}
	}
	response.Body.Close()
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if len(trace.params) != 1 {
		t.Fatal("missing peer transport parameters", trace.params)
	}
	p := trace.params[0]
	if uint64(p.InitialMaxStreamDataBidiLocal) != 16<<10 || uint64(p.InitialMaxData) != 32<<10 || p.MaxIdleTimeout != 30*time.Second {
		t.Fatal(p)
	}
	if total != 2<<20 || trace.streamCredit <= 16<<10 || trace.connectionCredit <= 32<<10 || trace.maxStreamGrant <= 16<<10 || trace.maxConnectionGrant <= 32<<10 || trace.maxStreamGrant > 64<<10 || trace.maxConnectionGrant > 128<<10 || trace.exceeded {
		t.Fatalf("body=%d stream=%d conn=%d grants=%d/%d exceeded=%t", total, trace.streamCredit, trace.connectionCredit, trace.maxStreamGrant, trace.maxConnectionGrant, trace.exceeded)
	}
	t.Logf("peer initial stream/conn=%d/%d; credit=%d/%d; largest grants=%d/%d; body=%d", p.InitialMaxStreamDataBidiLocal, p.InitialMaxData, trace.streamCredit, trace.connectionCredit, trace.maxStreamGrant, trace.maxConnectionGrant, total)
}

func TestHTTP3ConfigPeerIdleAndKeepAlive(t *testing.T) {
	for _, keep := range []time.Duration{0, 50 * time.Millisecond} {
		t.Run(keep.String(), func(t *testing.T) {
			trace := &peerTrace{}
			endpoint, roots := configH3Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
				case <-time.After(1500 * time.Millisecond):
					io.WriteString(w, "alive")
				}
			}), trace)
			s, err := NewSession(Options{HTTPVersion: HTTPVersion3, HTTP3: &HTTP3Config{MaxIdleTimeout: 400 * time.Millisecond, KeepAlivePeriod: durationPointer(keep)}, VerifyTLS: true, TLSRootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			response, err := s.DoContext(ctx, endpoint, RequestOptions{}, "GET")
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if keep == 0 {
				var idle *quic.IdleTimeoutError
				if !errors.As(err, &idle) || time.Since(started) > 1200*time.Millisecond {
					t.Fatalf("expected idle close, got %q %v", body, err)
				}
			} else if err != nil || string(body) != "alive" {
				t.Fatalf("keepalive=%q %v", body, err)
			}
			trace.mu.Lock()
			defer trace.mu.Unlock()
			if len(trace.params) != 1 || trace.params[0].MaxIdleTimeout != 5*time.Second {
				t.Fatal(trace.params)
			}
			if keep != 0 && trace.pings < 2 {
				t.Fatal("no keepalive packets", trace.pings)
			}
			t.Logf("peer idle=%s keepalive=%s pings=%d body=%q error=%v", trace.params[0].MaxIdleTimeout, keep, trace.pings, body, err)
		})
	}
}

func TestHTTP3ConfigHeadersIsolationPolicyAndDeadline(t *testing.T) {
	endpoint, roots := configH3Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/headers":
			w.Header().Set("X-Large", strings.Repeat("a", 4096))
			io.WriteString(w, "ok")
		case "/trailers":
			w.Header().Set("Trailer", "X-Large")
			io.WriteString(w, "ok")
			w.Header().Set("X-Large", strings.Repeat("z", 4096))
		case "/slow":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			io.WriteString(w, "ok")
		}
	}), nil)
	for _, policyOn := range []bool{false, true} {
		t.Run(fmt.Sprint(policyOn), func(t *testing.T) {
			var policy *AddressPolicy
			if policyOn {
				policy = mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"127.0.0.1/32"}})
			}
			small := &HTTP3Config{MaxResponseHeaderBytes: 1024, KeepAlivePeriod: durationPointer(20 * time.Millisecond)}
			a, err := NewSession(Options{HTTPVersion: HTTPVersion3, HTTP3: small, AddressPolicy: policy, VerifyTLS: true, TLSRootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := NewSession(Options{HTTPVersion: HTTPVersion3, HTTP3: &HTTP3Config{MaxResponseHeaderBytes: 8192}, AddressPolicy: policy, VerifyTLS: true, TLSRootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			for _, path := range []string{"/headers", "/trailers"} {
				for i, s := range []*Session{a, b} {
					response, err := s.DoContext(context.Background(), endpoint+path, RequestOptions{}, "GET")
					if err == nil {
						_, err = io.Copy(io.Discard, response.Body)
						response.Body.Close()
					}
					if i == 0 && err == nil {
						t.Fatal("small header limit accepted", path)
					}
					if i == 1 && err != nil {
						t.Fatal("isolated large limit rejected", path, err)
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			response, err := a.DoContext(ctx, endpoint+"/slow", RequestOptions{}, "GET")
			if err == nil {
				_, err = io.ReadAll(response.Body)
				response.Body.Close()
			}
			if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("keepalive extended deadline", err)
			}
			a.Close()
			response, err = b.DoContext(context.Background(), endpoint, RequestOptions{}, "GET")
			if err != nil {
				t.Fatal("sibling owner closed", err)
			}
			response.Body.Close()
			b.CloseIdleConnections()
			response, err = b.DoContext(context.Background(), endpoint, RequestOptions{}, "GET")
			if err != nil {
				t.Fatal("reconnect", err)
			}
			response.Body.Close()
		})
	}
}

func TestHTTP3ConfigActiveOwnershipAndUpload(t *testing.T) {
	finish := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(finish) }) }
	defer release()
	stopped := make(chan struct{}, 4)
	endpoint, roots := configH3Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upload" {
			io.WriteString(w, "early")
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-finish:
			io.WriteString(w, "complete")
		case <-r.Context().Done():
			stopped <- struct{}{}
		}
	}), nil)
	s, err := NewSession(Options{HTTPVersion: HTTPVersion3, HTTP3: &HTTP3Config{MaxStreamReceiveWindow: 1 << 20, MaxConnectionReceiveWindow: 2 << 20, MaxResponseHeaderBytes: 2048}, VerifyTLS: true, TLSRootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, err := s.DoContext(ctx, endpoint, RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	second, err := s.DoContext(context.Background(), endpoint, RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	h3 := currentH3(t, s)
	s.CloseIdleConnections()
	if h3.Stats().Active != 2 {
		t.Fatal("headers returned active ownership", h3.Stats())
	}
	cancel()
	if _, err := io.ReadAll(first.Body); err == nil {
		t.Fatal("cancelled stream returned EOF")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("peer not cancelled")
	}
	if h3.Stats().Active != 1 {
		t.Fatal("sibling lease lost", h3.Stats())
	}
	release()
	body, err := io.ReadAll(second.Body)
	second.Body.Close()
	if err != nil || string(body) != "complete" || h3.Stats().Active != 0 {
		t.Fatal(string(body), err, h3.Stats())
	}
	source := &h3BlockedUpload{started: make(chan struct{}), closed: make(chan struct{})}
	defer source.Close()
	response, err := s.DoContext(context.Background(), endpoint+"/upload", RequestOptions{BodyReader: source}, "POST")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	select {
	case <-source.closed:
	case <-time.After(time.Second):
		t.Fatal("upload source not released")
	}
	s.Close()
	if _, err := s.DoContext(context.Background(), endpoint, RequestOptions{}, "GET"); err == nil {
		t.Fatal("closed session accepted request")
	}
}

func TestHTTP3ConfigPolicyVerifiedSNIAndDenial(t *testing.T) {
	var hits atomic.Int32
	endpoint, roots := policyH3Origin(t, "udp4", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.TLS.ServerName != "example.com" {
			t.Error("lost SNI", r.TLS.ServerName)
		}
		io.WriteString(w, "verified")
	}))
	for _, denied := range []bool{false, true} {
		p := mustPolicy(t, AddressPolicyConfig{AllowHosts: []string{"example.com"}, AllowCIDRs: []string{"127.0.0.1/32"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			answers := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
			if denied {
				answers = append(answers, netip.MustParseAddr("192.0.2.1"))
			}
			return answers, nil
		})})
		options := Options{HTTPVersion: HTTPVersion3, HTTP3: &HTTP3Config{MaxResponseHeaderBytes: 2048}, VerifyTLS: true, TLSRootCAs: roots, AddressPolicy: p}
		response, err := NewClient().Do(endpoint, options, "GET")
		if denied {
			requirePolicyReason(t, err, "cidr_not_allowed")
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "verified" {
			t.Fatal(string(body), err)
		}
		options.TLSRootCAs = x509.NewCertPool()
		response, err = NewClient().Do(endpoint, options, "GET")
		if err == nil {
			response.Body.Close()
			t.Fatal("configured H3 bypassed trust")
		}
	}
	if hits.Load() != 1 {
		t.Fatal("denied/untrusted request reached handler", hits.Load())
	}
}
