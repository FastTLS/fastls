package fastls

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func proxyWire(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		serve(c)
	}()
	t.Cleanup(func() {
		l.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("proxy handler did not terminate")
		}
	})
	return l.Addr().String()
}

func TestProxyConnectPreservesBufferedBytesAndAuth(t *testing.T) {
	address := proxyWire(t, func(c net.Conn) {
		r, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			t.Error(err)
			return
		}
		if r.Method != "CONNECT" || r.Host != "localhost:443" || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("name:p:a@ss")) {
			t.Error("invalid CONNECT or credentials")
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nX-Proxy: yes\r\n\r\nfirst")
	})
	u, err := parseTunnelProxy("http://" + url.UserPassword("name", "p:a@ss").String() + "@" + address)
	if err != nil {
		t.Fatal(err)
	}
	c, err := (&tunnelProxyDialer{endpoint: u}).DialContext(context.Background(), "tcp", "localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := make([]byte, 5)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "first" {
		t.Fatal("lost tunnel bytes", string(b), err)
	}
}

func TestProxyConnectBoundsHeaders(t *testing.T) {
	address := proxyWire(t, func(c net.Conn) {
		http.ReadRequest(bufio.NewReader(c))
		io.WriteString(c, "HTTP/1.1 200 OK\r\nX-Huge: "+strings.Repeat("x", 70000)+"\r\n\r\n")
	})
	u, _ := parseTunnelProxy("http://" + address)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := (&tunnelProxyDialer{endpoint: u}).DialContext(ctx, "tcp", "localhost:80"); err == nil {
		c.Close()
		t.Fatal("accepted oversized proxy response")
	}
}

func TestHTTPSProxyUsesVerifiedTLSAndHTTP1(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.TLS == nil || r.ProtoMajor != 1 {
			t.Error("expected TLS HTTP1 CONNECT")
		}
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\nfirst")
	}))
	defer server.Close()
	endpoint, err := parseTunnelProxy(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := (&tunnelProxyDialer{endpoint: endpoint, roots: roots}).DialContext(ctx, "tcp", "localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	_, err = io.ReadFull(c, b)
	c.Close()
	if err != nil || string(b) != "first" {
		t.Fatal("lost TLS tunnel bytes", err)
	}
	if c, err = (&tunnelProxyDialer{endpoint: endpoint}).DialContext(ctx, "tcp", "localhost:443"); err == nil {
		c.Close()
		t.Fatal("accepted untrusted proxy certificate")
	}
}

func TestProxyHandshakeContextClosesSocket(t *testing.T) {
	for _, scheme := range []string{"http", "socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			closed := make(chan struct{})
			address := proxyWire(t, func(c net.Conn) { io.Copy(io.Discard, c); close(closed) })
			u, _ := parseTunnelProxy(scheme + "://" + address)
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if c, err := (&tunnelProxyDialer{endpoint: u}).DialContext(ctx, "tcp", "localhost:80"); !errors.Is(err, context.DeadlineExceeded) {
				if c != nil {
					c.Close()
				}
				t.Fatal("wrong timeout", err)
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("cancelled proxy handshake retained socket")
			}
		})
	}
}

func TestProxyValidationRedactsCredentials(t *testing.T) {
	for _, raw := range []string{"http://name:secret@host:0", "http://name:secret@host/path", "http://name:secret@host?x=1", "socks4://name:secret@host", "http://name:sec%ZZret@host"} {
		err := ValidateProxy(raw)
		if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "name") {
			t.Fatalf("unsafe proxy validation error: %v", err)
		}
	}
	for _, raw := range []string{"", "http://localhost", "https://localhost", "socks5://localhost", "socks5h://[::1]:1080"} {
		if err := ValidateProxy(raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := newClient(browser{}, 1, true, "", "http://name:sec%ZZret@host"); err == nil || strings.Contains(err.Error(), "name") {
		t.Fatal("core parse error leaked credentials", err)
	}
}

func TestSOCKSAddressTypesAndBoundReply(t *testing.T) {
	for target, atyp := range map[string]byte{"127.0.0.1:443": 1, "[::1]:443": 4, "proxy-only.invalid:443": 3} {
		t.Run(target, func(t *testing.T) {
			address := proxyWire(t, func(c net.Conn) {
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(c, greeting); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				header := make([]byte, 4)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				if header[3] != atyp {
					t.Error("wrong SOCKS address type")
				}
				n := 4
				if header[3] == 4 {
					n = 16
				}
				if header[3] == 3 {
					var size [1]byte
					io.ReadFull(c, size[:])
					n = int(size[0])
				}
				io.CopyN(io.Discard, c, int64(n+2))
				packet := append([]byte{5, 0, 0, 4}, make([]byte, 18)...)
				packet = append(packet, []byte("first")...)
				c.Write(packet)
			})
			u, _ := parseTunnelProxy("socks5h://" + address)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, err := (&tunnelProxyDialer{endpoint: u}).DialContext(ctx, "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			b := make([]byte, 5)
			if _, err = io.ReadFull(c, b); err != nil || string(b) != "first" {
				t.Fatal("incorrect bound reply consumption", err)
			}
		})
	}
}
