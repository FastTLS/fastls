package fastls

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type policyResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f policyResolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func mustPolicy(t *testing.T, config AddressPolicyConfig) *AddressPolicy {
	t.Helper()
	p, err := NewAddressPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func requirePolicyReason(t *testing.T, err error, reason string) {
	t.Helper()
	var policy *AddressPolicyError
	if !errors.Is(err, ErrAddressDenied) || !errors.As(err, &policy) || policy.Reason != reason {
		t.Fatalf("want policy reason %s, got %v", reason, err)
	}
}

func TestAddressPolicyConfigAndCanonicalization(t *testing.T) {
	for _, config := range []AddressPolicyConfig{
		{AllowSchemes: []string{"ftp"}}, {AllowSchemes: []string{"HTTPS"}},
		{AllowPorts: []uint16{0}}, {AllowCIDRs: []string{"127.0.0.1"}},
		{DenyCIDRs: []string{"::ffff:127.0.0.0/80"}},
		{AllowHosts: []string{"*.example.test"}}, {AllowHosts: []string{"example.test:443"}},
		{AllowHosts: []string{"example..test"}}, {AllowHosts: []string{"fe80::1%eth0"}},
		{AllowHosts: []string{"[::1]"}}, {AllowHosts: []string{"user@example.test"}},
	} {
		if _, err := NewAddressPolicy(config); err == nil {
			t.Fatalf("accepted invalid config: %+v", config)
		}
	}
	config := AddressPolicyConfig{AllowSchemes: []string{"https"}, AllowHosts: []string{"EXAMPLE.TEST.", "bücher.test", "::ffff:127.0.0.1"}, AllowPorts: []uint16{443}, AllowCIDRs: []string{"127.0.0.0/8"}}
	p := mustPolicy(t, config)
	config.AllowSchemes[0], config.AllowHosts[0], config.AllowCIDRs[0], config.AllowPorts[0] = "http", "other.test", "0.0.0.0/0", 80
	for _, endpoint := range []string{"https://example.test/", "https://EXAMPLE.TEST./", "https://xn--bcher-kva.test/", "https://[::ffff:127.0.0.1]/"} {
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = p.checkRequest(req); err != nil {
			t.Fatalf("%s: %v", endpoint, err)
		}
	}
	if err := p.checkIP(netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Fatal("config mutation changed copied CIDR")
	}
}

func TestAddressPolicyRequestBoundaries(t *testing.T) {
	p := mustPolicy(t, AddressPolicyConfig{AllowSchemes: []string{"https"}, AllowHosts: []string{"allowed.test"}, AllowPorts: []uint16{443}})
	for _, test := range []struct{ endpoint, host, reason string }{
		{"https://allowed.test/", "", ""},
		{"https://allowed.test:443/", "ALLOWED.TEST.", ""},
		{"http://allowed.test/", "", "scheme_not_allowed"},
		{"https://allowed.test.evil/", "", "host_not_allowed"},
		{"https://allowed.test:444/", "", "port_not_allowed"},
		{"https://user:secret@allowed.test/", "", "invalid_url"},
		{"https://allowed.test/", "other.test", "host_override"},
		{"https://allowed.test/", "allowed.test:444", "host_override"},
		// net/http normalizes an empty explicit port to the default before RoundTrip.
		{"https://allowed.test:/", "", ""},
		{"https://allowed.test:0/", "", "invalid_port"},
		{"https://allowed.test:65536/", "", "invalid_port"},
		{"https:allowed.test/path", "", "invalid_url"},
	} {
		req, err := http.NewRequest("GET", test.endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.host != "" {
			req.Host = test.host
		}
		err = p.checkRequest(req)
		if test.reason == "" {
			if err != nil {
				t.Fatalf("%+v: %v", test, err)
			}
		} else {
			requirePolicyReason(t, err, test.reason)
		}
	}
	for _, authority := range []string{"allowed.test:", "[fe80::1%25eth0]", "allowed.test/path", "allowed.test?x", "allowed.test#x"} {
		if _, _, err := policyAuthority("https", authority); err == nil {
			t.Fatalf("accepted authority: %s", authority)
		}
	}
	zero := &AddressPolicy{}
	req, _ := http.NewRequest("GET", "https://allowed.test", nil)
	requirePolicyReason(t, zero.checkRequest(req), "uninitialized_policy")
}

func TestAddressPolicyValidatesAllAnswersBeforeAnyDial(t *testing.T) {
	for _, answers := range [][]netip.Addr{
		{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("::ffff:127.0.0.1"), netip.MustParseAddr("192.0.2.1")},
	} {
		p := mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"0.0.0.0/0"}, DenyCIDRs: []string{"::ffff:127.0.0.0/104"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return answers, nil })})
		var dials int
		_, err := p.dialContext(context.Background(), "tcp", "allowed.test:80", func(context.Context, string, string) (net.Conn, error) {
			dials++
			return nil, errors.New("must not dial")
		})
		requirePolicyReason(t, err, "cidr_denied")
		if dials != 0 {
			t.Fatal("partially allowed DNS set triggered a connection")
		}
	}
}

func TestAddressPolicyPinsDNSAnswersAndRetriesNumericOnly(t *testing.T) {
	var queries int
	p := mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"192.0.2.0/24"}, Resolver: policyResolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		queries++
		if network != "ip" || host != "allowed.test" {
			t.Fatalf("lookup %s %s", network, host)
		}
		if queries > 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, nil
	})})
	var dialed []string
	client, peer := net.Pipe()
	defer peer.Close()
	conn, err := p.dialContext(context.Background(), "tcp", "ALLOWED.TEST.:80", func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		if len(dialed) == 1 {
			return nil, errors.New("injected connection failure")
		}
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if queries != 1 || !reflect.DeepEqual(dialed, []string{"192.0.2.1:80", "192.0.2.2:80"}) {
		t.Fatalf("queries=%d dialed=%v", queries, dialed)
	}
}

func TestAddressPolicyDNSCancellationAndLiteralIP(t *testing.T) {
	started := make(chan struct{})
	p := mustPolicy(t, AddressPolicyConfig{Resolver: policyResolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := p.DialContext(ctx, "tcp", "slow.test:80"); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DNS not entered")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS cancellation not bounded")
	}
	_, err := p.DialContext(context.Background(), "tcp", "[fe80::1%eth0]:80")
	requirePolicyReason(t, err, "invalid_host")
	p = mustPolicy(t, AddressPolicyConfig{DenyCIDRs: []string{"127.0.0.0/8"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("literal IP reached DNS")
		return nil, nil
	})})
	_, err = p.DialContext(context.Background(), "tcp", "[::ffff:127.0.0.1]:80")
	requirePolicyReason(t, err, "cidr_denied")
}

func TestAddressPolicyRequestCancellationStopsDNS(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			started, stopped := make(chan struct{}), make(chan struct{})
			p := mustPolicy(t, AddressPolicyConfig{Resolver: policyResolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
				close(started)
				defer close(stopped)
				<-ctx.Done()
				return nil, ctx.Err()
			})})
			session, err := NewSession(Options{AddressPolicy: p})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := session.DoContext(ctx, scheme+"://slow.test", RequestOptions{}, "GET"); done <- err }()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("request DNS not entered")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("request did not return on cancellation")
			}
			select {
			case <-stopped:
			case <-time.After(2 * time.Second):
				t.Fatal("request left a pending DNS query")
			}
		})
	}
}

func TestAddressPolicyDialCancellation(t *testing.T) {
	p := mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"127.0.0.1/32"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := p.dialContext(ctx, "tcp", "127.0.0.1:80", func(ctx context.Context, _, _ string) (net.Conn, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	_, err = p.DialContext(deadline, "tcp", "127.0.0.1:80")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestAddressPolicyDNSAnswerAndNetworkBoundaries(t *testing.T) {
	for _, test := range []struct {
		answers []netip.Addr
		network string
		reason  string
	}{
		{nil, "tcp", "dns_answer_count"},
		{make([]netip.Addr, 257), "tcp", "dns_answer_count"},
		{[]netip.Addr{{}}, "tcp", "invalid_ip"},
		{[]netip.Addr{netip.MustParseAddr("fe80::1%eth0")}, "tcp", "invalid_ip"},
		{[]netip.Addr{netip.MustParseAddr("192.0.2.1")}, "tcp", "cidr_not_allowed"},
		{[]netip.Addr{netip.MustParseAddr("::1")}, "tcp4", "dns_address_family"},
		{[]netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}, "tcp6", "dns_address_family"},
		{nil, "udp", "network_unsupported"},
	} {
		p := mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"127.0.0.0/8", "::1/128"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return test.answers, nil })})
		_, err := p.dialContext(context.Background(), test.network, "allowed.test:80", func(context.Context, string, string) (net.Conn, error) { t.Fatal("unexpected dial"); return nil, nil })
		requirePolicyReason(t, err, test.reason)
	}
	_, err := (&AddressPolicy{}).DialContext(context.Background(), "tcp", "127.0.0.1:80")
	requirePolicyReason(t, err, "uninitialized_policy")
}

func TestAddressPolicyRedirectCannotRebindDNS(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://allowed.test:"+targetURL.Port()+"/", http.StatusFound)
	}))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	var queries atomic.Int32
	p := mustPolicy(t, AddressPolicyConfig{AllowHosts: []string{"allowed.test"}, AllowCIDRs: []string{"127.0.0.1/32"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		if queries.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
	})})
	response, err := NewClient().DoContext(context.Background(), "http://allowed.test:"+u.Port()+"/", Options{AddressPolicy: p}, "GET")
	if response.Body != nil {
		response.Body.Close()
	}
	response.Client.CloseIdleConnections()
	requirePolicyReason(t, err, "cidr_not_allowed")
	if queries.Load() != 2 || reached.Load() != 0 {
		t.Fatalf("queries=%d reached=%d", queries.Load(), reached.Load())
	}
}

type policyUpload struct{ closed atomic.Bool }

func (b *policyUpload) Read([]byte) (int, error) { return 0, io.EOF }
func (b *policyUpload) Close() error             { b.closed.Store(true); return nil }

func TestAddressPolicyRejectionClosesOwnedUpload(t *testing.T) {
	policy := mustPolicy(t, AddressPolicyConfig{AllowHosts: []string{"allowed.test"}})
	rt := newRoundTripper(browser{AddressPolicy: policy})
	body := &policyUpload{}
	req, _ := http.NewRequest("POST", "http://blocked.test", body)
	_, err := rt.RoundTrip(req)
	requirePolicyReason(t, err, "host_not_allowed")
	if !body.closed.Load() {
		t.Fatal("policy rejection retained upload")
	}
}

func FuzzAddressPolicyAuthority(f *testing.F) {
	for _, seed := range []string{"example.test:443", "bücher.test", "[::1]:80", "user:secret@example.test", "[fe80::1%25eth0]", "127.0.0.1", "example.test:", "example..test", "example.test/path"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, authority string) {
		if len(authority) > 4096 {
			t.Skip()
		}
		host, port, err := policyAuthority("https", authority)
		if err != nil {
			return
		}
		if host == "" || port == 0 {
			t.Fatal("accepted empty host/port")
		}
		canonical, err := policyHost(host)
		if err != nil || canonical != host {
			t.Fatalf("host normalization not idempotent: %q %q %v", host, canonical, err)
		}
		p := mustPolicy(t, AddressPolicyConfig{AllowHosts: []string{host}, AllowPorts: []uint16{port}})
		req := &http.Request{URL: &url.URL{Scheme: "https", Host: authority}}
		if err := p.checkRequest(req); err != nil {
			t.Fatalf("accepted authority rejected by matching policy: %v", err)
		}
	})
}

func policyReadResult(t *testing.T, response Response, err error) string {
	t.Helper()
	defer response.Client.CloseIdleConnections()
	if response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestAddressPolicyRedirectChecksEachHopAndHostOverride(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); io.WriteString(w, "target") }))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://blocked.test:"+targetURL.Port()+"/", http.StatusFound)
	}))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	var queries atomic.Int32
	p := mustPolicy(t, AddressPolicyConfig{AllowHosts: []string{"allowed.test"}, AllowCIDRs: []string{"127.0.0.0/8"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		queries.Add(1)
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})})
	endpoint := "http://allowed.test:" + u.Port() + "/"
	response, err := NewClient().DoContext(context.Background(), endpoint, Options{AddressPolicy: p}, "GET")
	if response.Body != nil {
		response.Body.Close()
	}
	response.Client.CloseIdleConnections()
	requirePolicyReason(t, err, "host_not_allowed")
	if reached.Load() != 0 || queries.Load() != 1 {
		t.Fatalf("denied redirect reached DNS/target: %d/%d", queries.Load(), reached.Load())
	}
	response, err = NewClient().DoContext(context.Background(), endpoint, Options{AddressPolicy: p, DisableRedirect: true}, "GET")
	policyReadResult(t, response, err)
	if response.Status != 302 {
		t.Fatal("DisableRedirect changed")
	}
	response, err = NewClient().DoContext(context.Background(), endpoint, Options{AddressPolicy: p, Headers: map[string]string{"Host": "blocked.test"}}, "GET")
	if response.Body != nil {
		response.Body.Close()
	}
	response.Client.CloseIdleConnections()
	requirePolicyReason(t, err, "host_override")
}

func TestAddressPolicyVerifiedTLSKeepsOriginalHostAndSessionIdentity(t *testing.T) {
	for _, mode := range []struct {
		name            string
		h2, fingerprint bool
	}{{"h1", false, false}, {"h2", true, false}, {"utls-h2", true, true}} {
		t.Run(mode.name, func(t *testing.T) {
			h2 := mode.h2
			var sni atomic.Value
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sni.Store(r.TLS.ServerName)
				if !strings.HasPrefix(r.Host, "example.com:") {
					t.Error("Host rewritten", r.Host)
				}
				io.WriteString(w, r.Proto)
			}))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			u, _ := url.Parse(server.URL)
			var queries atomic.Int32
			p := mustPolicy(t, AddressPolicyConfig{AllowSchemes: []string{"https"}, AllowHosts: []string{"example.com"}, AllowCIDRs: []string{"127.0.0.0/8"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				queries.Add(1)
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			})})
			options := Options{AddressPolicy: p, VerifyTLS: true, TLSRootCAs: roots}
			if mode.fingerprint {
				options.Fingerprint = Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}
				options.UserAgent = regressionUA
			}
			session, err := NewSession(options)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			for i := 0; i < 2; i++ {
				response, err := session.DoContext(context.Background(), "https://example.com:"+u.Port()+"/", RequestOptions{}, "GET")
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				want := map[bool]string{false: "HTTP/1.1", true: "HTTP/2.0"}[h2]
				if err != nil || string(body) != want || response.Protocol != want {
					t.Fatalf("protocol: %+v %s %v", response, body, err)
				}
			}
			if queries.Load() != 1 || sni.Load() != "example.com" {
				t.Fatalf("queries=%d SNI=%v", queries.Load(), sni.Load())
			}
		})
	}
}

func TestAddressPolicyRechecksEveryNewConnection(t *testing.T) {
	var reached atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.Header().Set("Connection", "close")
		io.WriteString(w, "ok")
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	var queries atomic.Int32
	p := mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"127.0.0.1/32"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		if queries.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
	})})
	session, err := NewSession(Options{AddressPolicy: p})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	response, err := session.DoContext(context.Background(), "http://allowed.test:"+u.Port(), RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	_, err = session.DoContext(context.Background(), "http://allowed.test:"+u.Port(), RequestOptions{}, "GET")
	requirePolicyReason(t, err, "cidr_not_allowed")
	if queries.Load() != 2 || reached.Load() != 1 {
		t.Fatalf("queries=%d reached=%d", queries.Load(), reached.Load())
	}
}

func TestAddressPolicyRejectsUnsupportedPathsBeforeNetwork(t *testing.T) {
	p := mustPolicy(t, AddressPolicyConfig{Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("unsupported path resolved DNS")
		return nil, nil
	})})
	for _, options := range []Options{
		{AddressPolicy: p, Proxy: "http://user:secret@proxy.test:8080"},
		{AddressPolicy: p, Fingerprint: Ja4Fingerprint{FingerprintValue: "q" + regressionJA4R[1:]}},
		{AddressPolicy: p, HTTPVersion: HTTPVersion3},
	} {
		reason := "proxy_unsupported"
		if options.Proxy == "" {
			reason = "http3_unsupported"
		}
		_, err := NewSession(options)
		requirePolicyReason(t, err, reason)
		_, err = NewClient().DoContext(context.Background(), "https://allowed.test", options, "GET")
		requirePolicyReason(t, err, reason)
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("credentials leaked")
		}
	}
	_, _, err := DialWebSocketContext(context.Background(), "ws://allowed.test", Options{AddressPolicy: p}, nil)
	requirePolicyReason(t, err, "websocket_unsupported")
	_, _, err = NewWebSocketClientWithOptions(Options{AddressPolicy: p}).Connect("ws://allowed.test")
	requirePolicyReason(t, err, "websocket_unsupported")
}

func TestAddressPolicyConcurrentSessions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer server.Close()
	p := mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"127.0.0.0/8"}})
	session, err := NewSession(Options{AddressPolicy: p})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := session.DoContext(context.Background(), server.URL, RequestOptions{}, "GET")
			if err != nil {
				t.Error(err)
				return
			}
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
