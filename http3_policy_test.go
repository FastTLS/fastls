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
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func policyH3Origin(t *testing.T, network string, handler http.Handler) (string, *x509.CertPool) {
	t.Helper()
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(cert.Close)
	addr := "127.0.0.1:0"
	if network == "udp6" {
		addr = "[::1]:0"
	}
	packet, err := net.ListenPacket(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: cert.TLS.Certificates}, Handler: handler}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(packet) }()
	t.Cleanup(func() { _ = server.Close(); _ = packet.Close(); <-done })
	roots := x509.NewCertPool()
	roots.AddCert(cert.Certificate())
	_, port, _ := net.SplitHostPort(packet.LocalAddr().String())
	return "https://example.com:" + port, roots
}

func TestH3PolicyVerifiedOriginReuseAndFreshDial(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::ffff:127.0.0.1", "::1"} {
		t.Run(ip, func(t *testing.T) {
			network := "udp4"
			if ip == "::1" {
				network = "udp6"
			}
			var hits, queries atomic.Int32
			endpoint, roots := policyH3Origin(t, network, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				fmt.Fprint(w, r.Host+"|"+r.TLS.ServerName+"|"+r.Proto)
			}))
			p := mustPolicy(t, AddressPolicyConfig{AllowHosts: []string{"example.com"}, AllowCIDRs: []string{ip + map[bool]string{true: "/128", false: "/32"}[strings.Contains(ip, ":")]}, Resolver: policyResolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
				if host != "example.com" || network != "ip" {
					t.Errorf("unexpected lookup %s %s", network, host)
				}
				if queries.Add(1) > 1 {
					return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
				}
				return []netip.Addr{netip.MustParseAddr(ip)}, nil
			})})
			session, err := NewSession(Options{HTTPVersion: HTTPVersion3, AddressPolicy: p, VerifyTLS: true, TLSRootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for range 2 {
				response, err := session.DoContext(ctx, endpoint, RequestOptions{}, "GET")
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(body) != strings.TrimPrefix(endpoint, "https://")+"|example.com|HTTP/3.0" {
					t.Fatalf("body=%q err=%v", body, err)
				}
			}
			if queries.Load() != 1 || hits.Load() != 2 {
				t.Fatalf("queries=%d hits=%d", queries.Load(), hits.Load())
			}
			session.CloseIdleConnections()
			_, err = session.DoContext(ctx, endpoint, RequestOptions{}, "GET")
			requirePolicyReason(t, err, "cidr_not_allowed")
			if queries.Load() != 2 || hits.Load() != 2 {
				t.Fatalf("rebind queries=%d hits=%d", queries.Load(), hits.Load())
			}
		})
	}
}

func TestH3PolicyRejectsAllAnswersBeforeAnyPacket(t *testing.T) {
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	_, port, _ := net.SplitHostPort(sink.LocalAddr().String())
	for _, answers := range [][]netip.Addr{nil, {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}, make([]netip.Addr, 257)} {
		p := mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"127.0.0.1/32"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return answers, nil })})
		d := &http3PolicyDialer{policy: p}
		_, err := d.Dial(context.Background(), "example.com:"+port, &tls.Config{ServerName: "example.com", NextProtos: []string{"h3"}}, nil)
		if !errors.Is(err, ErrAddressDenied) || len(d.sockets) != 0 {
			t.Fatalf("err=%v sockets=%d", err, len(d.sockets))
		}
		d.Close()
	}
	sink.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if n, _, err := sink.ReadFrom(make([]byte, 2048)); err == nil || n != 0 {
		t.Fatal("rejected DNS answers emitted a packet", n, err)
	}
}

func TestH3PolicyUnspecifiedAnswersCannotAuthorizeLocalSystem(t *testing.T) {
	for _, ip := range []string{"0.0.0.0", "::", "::ffff:0.0.0.0"} {
		p := mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"0.0.0.0/0", "::/0"}, DenyCIDRs: []string{"127.0.0.0/8", "::1/128"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr(ip)}, nil
		})})
		d := &http3PolicyDialer{policy: p}
		_, err := d.Dial(context.Background(), "example.com:443", &tls.Config{ServerName: "example.com", NextProtos: []string{"h3"}}, nil)
		requirePolicyReason(t, err, "invalid_ip")
		if len(d.sockets) != 0 {
			t.Fatal("invalid mixed answer opened socket")
		}
		d.Close()
	}
}

func TestH3PolicyPacketConnPinsPeer(t *testing.T) {
	allowed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	denied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	peer := allowed.LocalAddr().(*net.UDPAddr)
	udp, err := net.DialUDP("udp4", nil, peer)
	if err != nil {
		t.Fatal(err)
	}
	packet := &policyPacketConn{conn: udp, peer: peer.AddrPort()}
	defer packet.Close()
	_, err = packet.WriteTo([]byte("blocked"), denied.LocalAddr())
	requirePolicyReason(t, err, "peer_change_unsupported")
	if _, err = packet.WriteTo([]byte("allowed"), peer); err != nil {
		t.Fatal(err)
	}
	allowed.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 64)
	if n, _, err := allowed.ReadFromUDP(b); err != nil || string(b[:n]) != "allowed" {
		t.Fatalf("n=%d err=%v", n, err)
	}
	denied.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := denied.ReadFromUDP(b); err == nil {
		t.Fatal("alternate peer received data")
	}
	_, err = denied.WriteToUDP([]byte("injected"), udp.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	packet.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := packet.ReadFrom(b); err == nil {
		t.Fatal("alternate peer injected data")
	}
}

func TestH3PolicyRedirectAndCertificateBoundary(t *testing.T) {
	var hits atomic.Int32
	endpoint, roots := policyH3Origin(t, "udp4", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "https://blocked.test/", 302)
	}))
	p := mustPolicy(t, AddressPolicyConfig{AllowHosts: []string{"example.com"}, AllowCIDRs: []string{"127.0.0.1/32"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := NewSession(Options{HTTPVersion: HTTPVersion3, AddressPolicy: p, VerifyTLS: true, TLSRootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.DoContext(ctx, endpoint, RequestOptions{}, "GET")
	if r.Body != nil {
		r.Body.Close()
	}
	requirePolicyReason(t, err, "host_not_allowed")
	if hits.Load() != 1 {
		t.Fatal(hits.Load())
	}
	bad, err := NewSession(Options{HTTPVersion: HTTPVersion3, AddressPolicy: p, VerifyTLS: true, TLSRootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	_, err = bad.DoContext(ctx, endpoint, RequestOptions{}, "GET")
	if err == nil || hits.Load() != 1 {
		t.Fatalf("certificate bypass %v hits=%d", err, hits.Load())
	}
}

func TestH3PolicyHandshakeCancellationAndSocketOwnership(t *testing.T) {
	for _, closeTransport := range []bool{false, true} {
		t.Run(fmt.Sprint(closeTransport), func(t *testing.T) {
			sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			p := mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"127.0.0.1/32"}})
			d := &http3PolicyDialer{policy: p}
			defer d.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := d.Dial(ctx, sink.LocalAddr().String(), &tls.Config{ServerName: "example.com", NextProtos: []string{"h3"}}, nil)
				done <- err
			}()
			sink.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := sink.ReadFromUDP(make([]byte, 2048)); err != nil {
				t.Fatal(err)
			}
			if closeTransport {
				d.Close()
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("stalled handshake succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("handshake did not stop")
			}
			d.mu.Lock()
			remaining := len(d.sockets)
			d.mu.Unlock()
			if remaining != 0 {
				t.Fatal("socket retained after handshake end", remaining)
			}
		})
	}
}
