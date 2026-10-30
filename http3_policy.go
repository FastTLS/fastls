package fastls

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptrace"
	"net/netip"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

// Each policy connection owns one connected UDP socket. The kernel fixes the
// remote peer, and WriteTo also rejects attempts to select an alternate peer.
// Deliberately expose only net.PacketConn: raw/OOB/batch writes must not bypass
// WriteTo. This path does not enable ECN/GSO or connection migration.
type policyPacketConn struct {
	conn *net.UDPConn
	peer netip.AddrPort
	once sync.Once
	err  error
}

func (c *policyPacketConn) ReadFrom(b []byte) (int, net.Addr, error) { return c.conn.ReadFrom(b) }
func (c *policyPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	peer, ok := addr.(*net.UDPAddr)
	if !ok || peer == nil || peer.AddrPort() != c.peer {
		return 0, addressDenied("peer_change_unsupported")
	}
	return c.conn.Write(b)
}
func (c *policyPacketConn) Close() error {
	c.once.Do(func() { c.err = c.conn.Close() })
	return c.err
}
func (c *policyPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *policyPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *policyPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *policyPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// Buffer sizing does not expose raw socket access or an alternate write path.
func (c *policyPacketConn) SetReadBuffer(n int) error  { return c.conn.SetReadBuffer(n) }
func (c *policyPacketConn) SetWriteBuffer(n int) error { return c.conn.SetWriteBuffer(n) }

// http3.Transport closes QUIC connections but does not own sockets supplied by
// Dial. Track them through handshake failure, connection end and transport close.
type http3PolicyDialer struct {
	policy  *AddressPolicy
	mu      sync.Mutex
	closed  bool
	sockets map[*policyPacketConn]struct{}
}

func (d *http3PolicyDialer) release(c *policyPacketConn) {
	_ = c.Close()
	d.mu.Lock()
	delete(d.sockets, c)
	d.mu.Unlock()
}

func (d *http3PolicyDialer) Close() {
	d.mu.Lock()
	d.closed = true
	sockets := d.sockets
	d.sockets = nil
	d.mu.Unlock()
	for c := range sockets {
		_ = c.Close()
	}
}

func (d *http3PolicyDialer) Dial(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	host, port, err := d.policy.dialAuthority(address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// All answers are validated before opening any socket. Each new physical
	// connection resolves afresh; neither preflight nor cached DNS grants access.
	ips, err := d.policy.resolveAddresses(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		peer, err := netip.ParseAddrPort(net.JoinHostPort(ip.Unmap().String(), port))
		if err != nil {
			return nil, err
		}
		conn, err := d.dialPeer(ctx, peer, tlsConfig, config)
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

func (d *http3PolicyDialer) dialPeer(ctx context.Context, peer netip.AddrPort, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	network := "udp6"
	if peer.Addr().Is4() {
		network = "udp4"
	}
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.ConnectStart != nil {
		trace.ConnectStart(network, peer.String())
	}
	udp, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(peer))
	var conn *quic.Conn
	if err == nil {
		packet := &policyPacketConn{conn: udp, peer: peer}
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			_ = packet.Close()
			return nil, net.ErrClosed
		}
		if d.sockets == nil {
			d.sockets = make(map[*policyPacketConn]struct{})
		}
		d.sockets[packet] = struct{}{}
		d.mu.Unlock()
		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		// Dial (not DialEarly) completes verification before application data.
		// tlsConfig comes from HTTP/3 with the original origin's ServerName.
		conn, err = quic.Dial(ctx, packet, net.UDPAddrFromAddrPort(peer), tlsConfig, config)
		if trace != nil && trace.TLSHandshakeDone != nil {
			var state tls.ConnectionState
			if conn != nil {
				state = conn.ConnectionState().TLS
			}
			trace.TLSHandshakeDone(state, err)
		}
		if err != nil {
			d.release(packet)
		} else {
			context.AfterFunc(conn.Context(), func() { d.release(packet) })
		}
	}
	if trace != nil && trace.ConnectDone != nil {
		trace.ConnectDone(network, peer.String(), err)
	}
	return conn, err
}
