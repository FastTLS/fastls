package fastls

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// CheckAddressPolicy performs a no-socket preflight using this client's fixed
// policy. If expectedOrigin is nonempty, the request must address that exact
// normalized scheme/host/effective-port origin, e.g. a CONNECT tunnel target.
// This check is not a reusable DNS permission: the real dial still resolves,
// validates and pins a fresh snapshot. It cannot authorize an unchecked dialer.
func (client Fastls) CheckAddressPolicy(ctx context.Context, request *http.Request, expectedOrigin string) error {
	if ctx == nil {
		return errors.New("nil address policy context")
	}
	if request == nil {
		return addressDenied("invalid_url")
	}
	p := client.addressPolicy
	if p == nil {
		return addressDenied("uninitialized_policy")
	}
	if err := p.checkRequest(request); err != nil {
		return err
	}
	if expectedOrigin != "" {
		origin, err := url.Parse(expectedOrigin)
		if err != nil || origin.Opaque != "" || origin.User != nil || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") || (origin.Scheme != "http" && origin.Scheme != "https") {
			return addressDenied("invalid_origin")
		}
		host, port, err := policyAuthority(origin.Scheme, origin.Host)
		if err != nil {
			return addressDenied("invalid_origin")
		}
		actualHost, actualPort, err := policyAuthority(request.URL.Scheme, request.URL.Host)
		if err != nil || request.URL.Scheme != origin.Scheme || actualHost != host || actualPort != port {
			return addressDenied("origin_mismatch")
		}
	}
	host, _, err := policyAuthority(request.URL.Scheme, request.URL.Host)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err = ctx.Err(); err != nil {
		return err
	}
	_, err = p.resolveAddresses(ctx, host)
	return err
}
