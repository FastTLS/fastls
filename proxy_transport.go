package fastls

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ValidateProxy accepts the explicitly supported tunnel schemes. Errors never
// contain the supplied URL, user name, or password.
func ValidateProxy(raw string) error {
	if raw == "" {
		return nil
	}
	_, err := parseTunnelProxy(raw)
	return err
}

func parseTunnelProxy(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("invalid proxy URL")
	}
	port := u.Port()
	switch u.Scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
	case "socks5", "socks5h":
		if port == "" {
			port = "1080"
		}
	default:
		return nil, errors.New("proxy scheme must be http, https, socks5 or socks5h")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("invalid proxy port")
	}
	if u.User != nil {
		user := u.User.Username()
		password, _ := u.User.Password()
		httpProxy := u.Scheme == "http" || u.Scheme == "https"
		if user == "" || (httpProxy && strings.Contains(user, ":")) || (!httpProxy && (len(user) > 255 || len(password) > 255)) {
			return nil, errors.New("invalid proxy credentials")
		}
	}
	u.Host = net.JoinHostPort(u.Hostname(), port)
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return nil, errors.New("invalid proxy host")
	}
	u.Path, u.RawPath = "", ""
	return u, nil
}

type tunnelProxyDialer struct {
	endpoint *url.URL
	roots    *x509.CertPool
}

func (d *tunnelProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("proxy requires TCP")
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.endpoint.Host)
	if err != nil {
		return nil, err
	}
	// Cancel the whole handshake, including blocked writes and response reads.
	raw := c
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	if d.endpoint.Scheme == "https" {
		secure := tls.Client(raw, &tls.Config{ServerName: d.endpoint.Hostname(), RootCAs: d.roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
		err = secure.HandshakeContext(ctx)
		if err == nil {
			c = secure
		}
	}
	var result net.Conn = c
	if err == nil {
		if d.endpoint.Scheme == "http" || d.endpoint.Scheme == "https" {
			result, err = d.connect(c, address)
		} else {
			err = d.socks(ctx, c, address)
		}
	}
	stopped := stop()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil || !stopped {
		raw.Close()
		if err == nil {
			err = context.Canceled
		}
		return nil, err
	}
	return result, nil
}

type tunnelBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *tunnelBufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (d *tunnelProxyDialer) connect(c net.Conn, target string) (net.Conn, error) {
	if _, _, err := net.SplitHostPort(target); err != nil || strings.ContainsAny(target, "\r\n") {
		return nil, errors.New("invalid tunnel target")
	}
	auth := ""
	if d.endpoint.User != nil {
		password, _ := d.endpoint.User.Password()
		auth = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(d.endpoint.User.Username()+":"+password)) + "\r\n"
	}
	if _, err := io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n"+auth+"\r\n"); err != nil {
		return nil, err
	}
	// Bound the proxy response headers; preserve any tunnel bytes read ahead.
	r := bufio.NewReader(io.LimitReader(c, 65537))
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, errors.New("invalid proxy CONNECT response")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || (fields[0] != "HTTP/1.1" && fields[0] != "HTTP/1.0") {
		return nil, errors.New("invalid proxy CONNECT response")
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil || code != 200 {
		return nil, fmt.Errorf("proxy CONNECT rejected (status %d)", code)
	}
	for {
		line, err = r.ReadString('\n')
		if err != nil {
			return nil, errors.New("proxy CONNECT headers exceed limit or are incomplete")
		}
		if line == "\r\n" {
			break
		}
		if !strings.Contains(line, ":") {
			return nil, errors.New("invalid proxy CONNECT headers")
		}
	}
	// LimitReader is only for the handshake, not for the established tunnel.
	pending := make([]byte, r.Buffered())
	if _, err = io.ReadFull(r, pending); err != nil {
		return nil, err
	}
	return &tunnelBufferedConn{Conn: c, reader: bufio.NewReader(io.MultiReader(strings.NewReader(string(pending)), c))}, nil
}

func (d *tunnelProxyDialer) socks(ctx context.Context, c net.Conn, target string) error {
	method := byte(0)
	if d.endpoint.User != nil {
		method = 2
	}
	if _, err := c.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != method {
		return errors.New("SOCKS5 proxy rejected authentication method")
	}
	if method == 2 {
		user := d.endpoint.User.Username()
		password, _ := d.endpoint.User.Password()
		packet := append([]byte{1, byte(len(user))}, []byte(user)...)
		packet = append(packet, byte(len(password)))
		packet = append(packet, []byte(password)...)
		if _, err := c.Write(packet); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, reply[:]); err != nil {
			return err
		}
		if reply[0] != 1 || reply[1] != 0 {
			return errors.New("SOCKS5 proxy authentication failed")
		}
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return errors.New("invalid SOCKS5 target")
	}
	ip := net.ParseIP(host)
	if ip == nil && d.endpoint.Scheme == "socks5" {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return err
		}
		if len(ips) == 0 {
			return errors.New("SOCKS5 target resolved to no addresses")
		}
		ip = ips[0].IP
		for _, candidate := range ips {
			if candidate.IP.To4() != nil {
				ip = candidate.IP
				break
			}
		}
	}
	packet := []byte{5, 1, 0}
	if v4 := ip.To4(); v4 != nil {
		packet = append(packet, 1)
		packet = append(packet, v4...)
	} else if ip != nil {
		packet = append(packet, 4)
		packet = append(packet, ip.To16()...)
	} else {
		if len(host) < 1 || len(host) > 255 {
			return errors.New("SOCKS5 target host exceeds limit")
		}
		packet = append(packet, 3, byte(len(host)))
		packet = append(packet, []byte(host)...)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("invalid SOCKS5 target port")
	}
	packet = append(packet, byte(p>>8), byte(p))
	if _, err = c.Write(packet); err != nil {
		return err
	}
	var header [4]byte
	if _, err = io.ReadFull(c, header[:]); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return errors.New("SOCKS5 proxy CONNECT rejected")
	}
	n := 0
	switch header[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var size [1]byte
		if _, err = io.ReadFull(c, size[:]); err != nil {
			return err
		}
		n = int(size[0])
	default:
		return errors.New("invalid SOCKS5 bound address")
	}
	_, err = io.CopyN(io.Discard, c, int64(n+2))
	return err
}
