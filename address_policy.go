package fastls

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// ErrAddressDenied matches all destination-policy rejections, including paths
// for which a verified destination cannot currently be guaranteed.
var ErrAddressDenied = errors.New("address policy denied request")

// AddressPolicyError contains a stable reason, never the URL or credentials.
type AddressPolicyError struct{ Reason string }

func (e *AddressPolicyError) Error() string { return ErrAddressDenied.Error() + ": " + e.Reason }
func (e *AddressPolicyError) Unwrap() error { return ErrAddressDenied }

// AddressPolicyReason permits capability-aware adapters to classify policy
// errors without a compile-time dependency on this newly added concrete type.
func (e *AddressPolicyError) AddressPolicyReason() string { return e.Reason }

func addressDenied(reason string) error { return &AddressPolicyError{Reason: reason} }

// IPResolver must respect context cancellation and be safe for concurrent use.
// Custom resolvers are trusted operator code, not request-controlled values.
type IPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// AddressPolicyConfig is copied by NewAddressPolicy. Empty allow lists impose
// no restriction in that dimension. DenyCIDRs always take precedence. Hosts
// are exact names (IDNA-normalized), not suffixes or wildcard expressions.
type AddressPolicyConfig struct {
	AllowSchemes []string
	AllowHosts   []string
	AllowPorts   []uint16
	AllowCIDRs   []string
	DenyCIDRs    []string
	Resolver     IPResolver
}

// AddressPolicy fixes the identity of a direct HTTP/1 or HTTP/2 transport.
// A nil Options.AddressPolicy disables policy enforcement. A non-nil zero
// AddressPolicy fails closed; construct usable policies with NewAddressPolicy.
// There are no mutators; the policy can be shared across sessions.
type AddressPolicy struct {
	ready    bool
	schemes  []string
	hosts    []string
	ports    []uint16
	allow    []netip.Prefix
	deny     []netip.Prefix
	resolver IPResolver
}

func NewAddressPolicy(config AddressPolicyConfig) (*AddressPolicy, error) {
	p := &AddressPolicy{resolver: config.Resolver}
	if p.resolver == nil {
		p.resolver = net.DefaultResolver
	}
	for _, scheme := range config.AllowSchemes {
		if scheme != "http" && scheme != "https" {
			return nil, errors.New("address policy schemes must be http or https")
		}
		p.schemes = append(p.schemes, scheme)
	}
	for _, host := range config.AllowHosts {
		name, err := policyHost(host)
		if err != nil {
			return nil, errors.New("invalid address policy host")
		}
		p.hosts = append(p.hosts, name)
	}
	p.ports = slices.Clone(config.AllowPorts)
	if slices.Contains(p.ports, 0) {
		return nil, errors.New("address policy port must be 1..65535")
	}
	for i, list := range [][]string{config.AllowCIDRs, config.DenyCIDRs} {
		for _, raw := range list {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Addr().Zone() != "" {
				return nil, errors.New("invalid address policy CIDR")
			}
			if prefix.Addr().Is4In6() {
				if prefix.Bits() < 96 {
					return nil, errors.New("mapped IPv4 policy CIDR must have at least 96 prefix bits")
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			if i == 0 {
				p.allow = append(p.allow, prefix.Masked())
			} else {
				p.deny = append(p.deny, prefix.Masked())
			}
		}
	}
	p.ready = true
	return p, nil
}

func policyHost(raw string) (string, error) {
	if raw == "" || !utf8.ValidString(raw) || strings.ContainsAny(raw, "%/\\@?#[] \t\r\n") {
		return "", addressDenied("invalid_host")
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		return ip.Unmap().String(), nil
	}
	if strings.Contains(raw, ":") {
		return "", addressDenied("invalid_host")
	}
	name, err := idna.Lookup.ToASCII(raw)
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if err != nil || name == "" || len(name) > 253 {
		return "", addressDenied("invalid_host")
	}
	// Require a stable ASCII form. Some Unicode replacement/mapping inputs can
	// encode successfully but produce an A-label which Lookup itself rejects.
	canonical, err := idna.Lookup.ToASCII(name)
	if err != nil || canonical != name {
		return "", addressDenied("invalid_host")
	}
	// IDNA Lookup does not enforce empty interior labels or DNS label lengths.
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "", addressDenied("invalid_host")
		}
	}
	return name, nil
}

func policyAuthority(scheme, authority string) (string, uint16, error) {
	// Parse the authority alone; no userinfo, paths, percent zones or empty ports.
	u, err := url.Parse(scheme + "://" + authority)
	if err != nil || u.User != nil || u.Host != authority || u.Hostname() == "" || strings.HasSuffix(authority, ":") {
		return "", 0, addressDenied("invalid_authority")
	}
	host, err := policyHost(u.Hostname())
	if err != nil {
		return "", 0, err
	}
	port := uint64(80)
	if scheme == "https" {
		port = 443
	}
	if raw := u.Port(); raw != "" {
		port, err = strconv.ParseUint(raw, 10, 16)
		if err != nil || port == 0 {
			return "", 0, addressDenied("invalid_port")
		}
	}
	return host, uint16(port), nil
}

func (p *AddressPolicy) checkRequest(req *http.Request) error {
	if p == nil || !p.ready {
		return addressDenied("uninitialized_policy")
	}
	u := req.URL
	if u == nil || u.Opaque != "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return addressDenied("invalid_url")
	}
	if len(p.schemes) > 0 && !slices.Contains(p.schemes, u.Scheme) {
		return addressDenied("scheme_not_allowed")
	}
	host, port, err := policyAuthority(u.Scheme, u.Host)
	if err != nil {
		return err
	}
	if len(p.hosts) > 0 && !slices.Contains(p.hosts, host) {
		return addressDenied("host_not_allowed")
	}
	if len(p.ports) > 0 && !slices.Contains(p.ports, port) {
		return addressDenied("port_not_allowed")
	}
	if req.Host != "" {
		h, n, err := policyAuthority(u.Scheme, req.Host)
		if err != nil || h != host || n != port {
			return addressDenied("host_override")
		}
	}
	return nil
}

func (p *AddressPolicy) checkIP(ip netip.Addr) error {
	if !ip.IsValid() || ip.Zone() != "" {
		return addressDenied("invalid_ip")
	}
	ip = ip.Unmap()
	for _, prefix := range p.deny {
		if prefix.Contains(ip) {
			return addressDenied("cidr_denied")
		}
	}
	if len(p.allow) > 0 {
		for _, prefix := range p.allow {
			if prefix.Contains(ip) {
				return nil
			}
		}
		return addressDenied("cidr_not_allowed")
	}
	return nil
}

// DialContext resolves once for this connection attempt, validates ALL answers,
// then dials only numeric addresses from that snapshot. No second DNS lookup
// is handed to net.Dialer. TLS still uses the original URL host for SNI/roots.
// Proxy and HTTP/3 paths must not use this policy until they have equivalent
// binding guarantees. The overall DNS + TCP budget is at most 30 seconds.
func (p *AddressPolicy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return p.dialContext(ctx, network, address, (&net.Dialer{}).DialContext)
}

func (p *AddressPolicy) dialContext(ctx context.Context, network, address string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if p == nil || !p.ready {
		return nil, addressDenied("uninitialized_policy")
	}
	if ctx == nil {
		return nil, errors.New("nil address policy context")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, addressDenied("network_unsupported")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, addressDenied("invalid_authority")
	}
	// Repeat host/port checks at the socket boundary as a defense against a
	// transport attempting to connect to a different origin than its request.
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return nil, addressDenied("invalid_port")
	}
	host, err = policyHost(host)
	if err != nil {
		return nil, err
	}
	if len(p.hosts) > 0 && !slices.Contains(p.hosts, host) {
		return nil, addressDenied("host_not_allowed")
	}
	if len(p.ports) > 0 && !slices.Contains(p.ports, uint16(number)) {
		return nil, addressDenied("port_not_allowed")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addresses, err := p.resolveAddresses(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range addresses {
		ip = ip.Unmap()
		if (network == "tcp4" && !ip.Is4()) || (network == "tcp6" && !ip.Is6()) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = addressDenied("dns_address_family")
	}
	return nil, last
}

func (p *AddressPolicy) resolveAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = p.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	if len(addresses) == 0 || len(addresses) > 256 {
		return nil, addressDenied("dns_answer_count")
	}
	for _, ip := range addresses {
		if err := p.checkIP(ip); err != nil {
			return nil, err
		}
	}
	return addresses, nil
}
