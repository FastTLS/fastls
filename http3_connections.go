package fastls

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// http3Connections retains ownership independently of the backend's request
// cache: a failed header read can evict a still-live QUIC connection from it.
// No new connection pool is introduced. All connections are gracefully closed
// before their shared UDP transport is destroyed, after active responses finish.
type http3Connections struct {
	mu     sync.Mutex
	closed bool
	conns  map[*quic.Conn]struct{}
	direct *quic.Transport
	udp    *net.UDPConn
	policy *http3PolicyDialer
}

func (o *http3Connections) Dial(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	var conn *quic.Conn
	var err error
	if o.policy != nil {
		conn, err = o.policy.Dial(ctx, address, tlsConfig, config)
	} else {
		conn, err = o.dialDirect(ctx, address, tlsConfig, config)
	}
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		_ = conn.CloseWithError(0, "")
		return nil, http3.ErrTransportClosed
	}
	if o.conns == nil {
		o.conns = make(map[*quic.Conn]struct{})
	}
	o.conns[conn] = struct{}{}
	o.mu.Unlock()
	context.AfterFunc(conn.Context(), func() { o.mu.Lock(); delete(o.conns, conn); o.mu.Unlock() })
	return conn, nil
}

func (o *http3Connections) dialDirect(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("udp", portString)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Name: host, Err: "no addresses"}
	}
	ip := ips[0]
	for _, candidate := range ips {
		if candidate.IP.To4() != nil {
			ip = candidate
			break
		}
	}
	peer := &net.UDPAddr{IP: ip.IP, Zone: ip.Zone, Port: port}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil, http3.ErrTransportClosed
	}
	if o.direct == nil {
		udp, e := net.ListenUDP("udp", nil)
		if e != nil {
			o.mu.Unlock()
			return nil, e
		}
		o.udp = udp
		o.direct = &quic.Transport{Conn: udp}
	}
	transport := o.direct
	o.mu.Unlock()
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.ConnectStart != nil {
		trace.ConnectStart("udp", peer.String())
	}
	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}
	// Match the backend's context-aware direct path and shared socket semantics.
	// TLS config already carries the original authority's SNI and trusted roots.
	conn, err := transport.DialEarly(ctx, peer, tlsConfig, config)
	if trace != nil && trace.TLSHandshakeDone != nil {
		var state tls.ConnectionState
		if conn != nil {
			state = conn.ConnectionState().TLS
		}
		trace.TLSHandshakeDone(state, err)
	}
	if trace != nil && trace.ConnectDone != nil {
		trace.ConnectDone("udp", peer.String(), err)
	}
	return conn, err
}

func (o *http3Connections) closeConnections() {
	o.mu.Lock()
	o.closed = true
	conns := make([]*quic.Conn, 0, len(o.conns))
	for conn := range o.conns {
		conns = append(conns, conn)
	}
	o.mu.Unlock()
	for _, conn := range conns {
		_ = conn.CloseWithError(0, "")
	}
}

func (o *http3Connections) closeSockets() {
	// Called after backend.Close has cancelled and joined pending dial attempts.
	o.mu.Lock()
	transport, udp := o.direct, o.udp
	o.direct, o.udp = nil, nil
	o.mu.Unlock()
	if transport != nil {
		_ = transport.Close()
	}
	if udp != nil {
		_ = udp.Close()
	}
	if o.policy != nil {
		o.policy.Close()
	}
}
