package fastls

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
	received := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(received); <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := Options{Fingerprint: Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}}
	finished := make(chan error, 1)
	go func() {
		c, _, err := DialWebSocketContext(ctx, strings.Replace(server.URL, "http", "ws", 1), opts, nil)
		if c != nil {
			c.Close()
		}
		finished <- err
	}()
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		server.CloseClientConnections()
		t.Fatal("server never received handshake")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("handshake did not honor cancellation", err)
		}
	case <-time.After(time.Second):
		server.CloseClientConnections()
		<-finished
		t.Fatal("cancel did not unblock Upgrade response read")
	}
}

func TestWebSocketRejectsDuplicateNegotiationHeaders(t *testing.T) {
	for _, extra := range []string{
		"Sec-WebSocket-Extensions: \r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n",
		"Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: unoffered\r\n",
		"Sec-WebSocket-Accept: invalid-second-value\r\n",
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			digest := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s\r\n", base64.StdEncoding.EncodeToString(digest[:]), extra)
			rw.Flush()
			io.Copy(io.Discard, c)
		}))
		opts := Options{Fingerprint: Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}}
		c, _, err := DialWebSocketContext(context.Background(), strings.Replace(srv.URL, "http", "ws", 1), opts, []string{"chat"})
		if c != nil {
			c.Close()
		}
		srv.Close()
		if err == nil {
			t.Error("accepted duplicate negotiation headers", extra)
		}
	}
}
