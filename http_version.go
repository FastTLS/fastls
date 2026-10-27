package fastls

import (
	"fmt"
	"strings"
)

// HTTPVersion selects the transport protocol for a client or Session.
type HTTPVersion string

const (
	// HTTPVersionAuto preserves the existing H1/H2 ALPN and q-JA4R selection.
	// It does not discover H3 through Alt-Svc or automatically try QUIC.
	HTTPVersionAuto HTTPVersion = ""
	// HTTPVersion3 requires HTTPS over QUIC, without TCP fallback.
	// It uses Go TLS and does not reproduce a browser TLS/H3 fingerprint.
	HTTPVersion3 HTTPVersion = "h3"
)

func (o Options) validateHTTPVersion() error {
	switch o.HTTPVersion {
	case HTTPVersionAuto:
		return nil
	case HTTPVersion3:
	default:
		return fmt.Errorf("fastls: unsupported HTTP version %q", o.HTTPVersion)
	}
	if o.Proxy != "" {
		return fmt.Errorf("fastls: HTTP/3 does not support configured proxies")
	}
	if o.Profile != nil {
		return fmt.Errorf("fastls: HTTP/3 does not support H1/H2 profile.Spec")
	}
	if o.Fingerprint != nil && !o.Fingerprint.IsEmpty() {
		if o.Fingerprint.Type() != "ja4r" || !strings.HasPrefix(o.Fingerprint.Value(), "q") {
			return fmt.Errorf("fastls: HTTP/3 does not support TCP TLS fingerprints")
		}
		if _, err := ParseJA4R(o.Fingerprint.Value(), o.UserAgent); err != nil {
			return fmt.Errorf("fastls: invalid HTTP/3 JA4R selector: %w", err)
		}
	}
	if o.TLSExtensions != nil || len(o.FingerprintSignatureAlgorithms) > 0 {
		return fmt.Errorf("fastls: HTTP/3 does not support TCP TLS extension overrides")
	}
	if o.HTTP2Settings != nil || o.HTTP2SettingsString != "" {
		return fmt.Errorf("fastls: HTTP/3 does not support HTTP/2 settings")
	}
	if len(o.PHeaderOrderKeys) > 0 || len(o.HeaderOrderKeys) > 0 || len(o.HeaderOrder) > 0 {
		return fmt.Errorf("fastls: HTTP/3 does not support custom header ordering")
	}
	return nil
}
