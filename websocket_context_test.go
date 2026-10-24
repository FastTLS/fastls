package fastls

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketVerifiedTLSAndHTTP1(t *testing.T) {
	upgrader := websocket.Upgrader{Subprotocols: []string{"chat"}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.NegotiatedProtocol != "http/1.1" {
			t.Error("unexpected ALPN", r.TLS.NegotiatedProtocol)
		}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		kind, data, err := c.ReadMessage()
		if err == nil {
			c.WriteMessage(kind, data)
		}
	}))
	defer server.Close()
	opts := Options{Fingerprint: Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}}
	endpoint := strings.Replace(server.URL, "https", "wss", 1)
	if c, _, err := DialWebSocketContext(context.Background(), endpoint, opts, []string{"chat"}); err == nil {
		c.Close()
		t.Fatal("accepted untrusted certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	opts.TLSRootCAs = roots
	c, resp, err := DialWebSocketContext(context.Background(), endpoint, opts, []string{"chat"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if resp.StatusCode != 101 || c.Subprotocol() != "chat" {
		t.Fatal("upgrade metadata")
	}
	if err = c.WriteMessage(websocket.TextMessage, []byte("verified")); err != nil {
		t.Fatal(err)
	}
	_, body, err := c.ReadMessage()
	if err != nil || string(body) != "verified" {
		t.Fatal(string(body), err)
	}
}

func TestWebSocketHandshakeContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	opts := Options{Fingerprint: Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}}
	_, _, err := DialWebSocketContext(ctx, strings.Replace(server.URL, "http", "ws", 1), opts, nil)
	if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("handshake did not honor context", err)
	}
}
