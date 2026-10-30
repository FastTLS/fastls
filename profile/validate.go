package profile

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidProfile = errors.New("invalid profile")
var ErrUnknownProfile = errors.New("unknown profile")

func invalid(id, path, reason string) error {
	return fmt.Errorf("%w: %s.%s: %s", ErrInvalidProfile, id, path, reason)
}
func grease(c Code) bool { return uint16(c)&0x0f0f == 0x0a0a && byte(c) == byte(c>>8) }
func Validate(s Spec) error {
	fail := func(path, reason string) error { return invalid(s.ID, path, reason) }
	if s.SchemaVersion != SchemaVersion {
		return fail("schema_version", "unsupported version")
	}
	if s.ID == "" || len(s.ID) > 256 || strings.ContainsAny(s.ID, " \\\x00") {
		return fail("id", "invalid identity")
	}
	if err := validateHTTP2(s.HTTP2); err != nil {
		return fail("http2", err.Error())
	}
	if s.HTTP2.FirstStreamID != 0 || s.HTTP2.StreamWindowIncrement != 0 {
		found := false
		for _, feature := range s.Capabilities.RequiredFeatures {
			found = found || feature == "http2.stream.v1"
		}
		if !found {
			return fail("capabilities.required_features", "stream configuration requires http2.stream.v1")
		}
	}
	if err := validateOrder(s.Headers.Order, s.Headers.PseudoOrder); err != nil {
		return fail("headers.order", err.Error())
	}
	if err := validateOrder(s.Headers.HTTP1Order, nil); err != nil {
		return fail("headers.http1_order", err.Error())
	}
	for _, headers := range [][]Header{s.Headers.HTTP1Defaults, s.Headers.HTTP2Defaults} {
		if err := validateHeaders(headers); err != nil {
			return fail("headers.protocol_defaults", err.Error())
		}
		for _, h := range headers {
			if strings.EqualFold(h.Name, "user-agent") || strings.EqualFold(h.Name, "host") {
				return fail("headers.protocol_defaults", "identity and authority belong to common headers")
			}
		}
	}
	common := map[string]bool{"user-agent": true, "host": true}
	for _, h := range s.Headers.Defaults {
		common[strings.ToLower(h.Name)] = true
	}
	if s.Identity != nil {
		for _, h := range s.Identity.ClientHints {
			common[strings.ToLower(h.Name)] = true
		}
	}
	for _, headers := range [][]Header{s.Headers.HTTP1Defaults, s.Headers.HTTP2Defaults} {
		for _, h := range headers {
			if common[strings.ToLower(h.Name)] {
				return fail("headers.protocol_defaults", "protocol defaults conflict with common defaults")
			}
		}
	}
	for _, h := range s.Headers.HTTP2Defaults {
		switch strings.ToLower(h.Name) {
		case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
			return fail("headers.http2_defaults", "HTTP2 forbids connection-specific headers")
		}
	}
	if s.Identity != nil && strings.ContainsAny(s.Identity.UserAgent, "\r\n\x00") {
		return fail("identity.user_agent", "invalid control character")
	}
	m := s.Metadata
	if m.ID != "" && m.ID != s.ID {
		return fail("metadata.id", "must match the authoritative spec ID")
	}
	if m.Kind != "browser" && m.Kind != "library" && m.Kind != "client" {
		return fail("metadata.kind", "expected browser, library or client")
	}
	if m.Product == "" || m.ProductVersion == "" || m.Platform == "" || m.Family == "" {
		return fail("metadata", "product, version, platform and implementation family are required")
	}
	if m.Kind != "browser" && (m.Implementation == "" || m.ImplementationVersion == "" || m.Variant == "") {
		return fail("metadata", "non-browser records require implementation, implementation_version and variant")
	}
	if s.TLS.MinVersion > s.TLS.MaxVersion {
		return fail("tls", "minimum exceeds maximum")
	}
	if !s.Capabilities.Legacy && (s.TLS.MinVersion < 0x0303 || s.TLS.MaxVersion > 0x0304) {
		return fail("tls", "new profiles must target TLS1.2/TLS1.3")
	}
	if len(s.TLS.CipherSuites) == 0 || len(s.TLS.CipherSuites) > 4096 {
		return fail("tls.cipher_suites", "empty or too many entries")
	}
	seen := map[Code]bool{}
	for _, c := range s.TLS.CipherSuites {
		if seen[c] && !grease(c) {
			return fail("tls.cipher_suites", "duplicate suite")
		}
		seen[c] = true
	}
	if len(s.TLS.Extensions) > 4096 {
		return fail("tls.extensions", "too many entries")
	}
	seen = map[Code]bool{}
	groups := map[Code]bool{}
	keyShares := []Code{}
	for i, e := range s.TLS.Extensions {
		path := fmt.Sprintf("tls.extensions[%d]", i)
		if e.RawHex != nil && len(*e.RawHex) > 131070 || len(e.Groups) > 4096 || len(e.KeyShares) > 4096 || len(e.SignatureAlgorithms) > 4096 || len(e.Versions) > 256 || len(e.ALPN) > 256 || len(e.CompressionAlgorithms) > 256 || len(e.PSKModes) > 256 || len(e.PointFormats) > 256 {
			return fail(path, "extension parameter budget exceeded")
		}
		if seen[e.ID] && !grease(e.ID) {
			return fail(path, "duplicate extension")
		}
		seen[e.ID] = true
		if e.ID == 41 && i != len(s.TLS.Extensions)-1 {
			return fail(path, "pre_shared_key must be last")
		}
		if e.RawHex != nil {
			if _, err := hex.DecodeString(*e.RawHex); err != nil {
				return fail(path+".raw_hex", "expected complete hex bytes")
			}
		}
		if e.ID == 10 {
			for _, g := range e.Groups {
				groups[g] = true
			}
		}
		if e.ID == 51 {
			keyShares = e.KeyShares
		}
		if e.ID == 43 {
			for _, v := range e.Versions {
				if !grease(v) && (v < s.TLS.MinVersion || v > s.TLS.MaxVersion) {
					return fail(path+".versions", "version outside declared range")
				}
			}
		}
		if e.ID == 16 {
			for _, p := range e.ALPN {
				if p == "" || len(p) > 255 {
					return fail(path+".alpn", "invalid ALPN protocol")
				}
			}
		}
	}
	for _, g := range keyShares {
		if !grease(g) && !groups[g] {
			return fail("tls.extensions.key_shares", "group not present in supported_groups")
		}
	}
	switch s.TLS.ExtensionOrder {
	case "", "fixed", "shuffle-except-psk-last", "shuffle-chrome":
	default:
		return fail("tls.extension_order", "unknown generation strategy")
	}
	switch s.TLS.GREASEPolicy {
	case "", "none", "per-connection":
	default:
		return fail("tls.grease_policy", "unknown generation strategy")
	}
	switch s.TLS.SessionPolicy {
	case "", "disabled", "resumption":
	default:
		return fail("tls.session_policy", "unknown session strategy")
	}
	for _, id := range s.TLS.OptionalExtensions {
		if !seen[id] {
			return fail("tls.optional_extensions", "optional extension not declared")
		}
	}
	settings := map[uint16]bool{}
	for _, v := range s.HTTP2.Settings {
		if settings[v.ID] {
			return fail("http2.settings", "duplicate setting")
		}
		settings[v.ID] = true
	}
	for _, p := range s.HTTP2.PriorityFrames {
		if p.Weight < 1 || p.Weight > 256 {
			return fail("http2.priority_frames", "weight must be 1..256")
		}
	}
	if p := s.HTTP2.HeaderPriority; p != nil && (p.Weight < 1 || p.Weight > 256) {
		return fail("http2.header_priority", "weight must be 1..256")
	}
	for _, h := range s.Headers.Defaults {
		if strings.EqualFold(h.Name, "user-agent") {
			if len(h.Values) != 1 {
				return fail("headers.defaults", "User-Agent requires one value")
			}
			if s.Identity != nil && s.Identity.UserAgent != h.Values[0] {
				return fail("identity", "conflicting User-Agent")
			}
		}
	}
	if err := validateHeaders(s.Headers.Defaults); err != nil {
		return fail("headers.defaults", err.Error())
	}
	names := map[string]bool{}
	for _, name := range s.Headers.Order {
		n := strings.ToLower(name)
		if n == "" || strings.HasPrefix(n, ":") || names[n] {
			return fail("headers.order", "empty, duplicate or pseudo header")
		}
		names[n] = true
	}
	names = map[string]bool{}
	for _, name := range s.Headers.PseudoOrder {
		if !strings.HasPrefix(name, ":") || names[name] {
			return fail("headers.pseudo_order", "invalid or duplicate pseudo header")
		}
		names[name] = true
	}
	if s.Identity != nil {
		occupied := map[string]bool{}
		for _, h := range s.Headers.Defaults {
			occupied[strings.ToLower(h.Name)] = true
		}
		for _, h := range s.Identity.ClientHints {
			key := strings.ToLower(h.Name)
			if !strings.HasPrefix(key, "sec-ch-") || occupied[key] {
				return fail("identity.client_hints", "conflicting or non-Client-Hint header")
			}
		}
	}
	if s.Identity != nil {
		if err := validateHeaders(s.Identity.ClientHints); err != nil {
			return fail("identity.client_hints", err.Error())
		}
	}
	for _, e := range s.Evidence {
		if e.Source == "" {
			return fail("evidence.source", "source is required")
		}
		if len(e.VerifiedFields) > 0 && (e.CapturedAt == "" || e.ProductVersion == "" || e.Platform == "") {
			return fail("evidence", "verified fields require capture time, exact version and platform")
		}
		if e.CapturedAt != "" {
			if _, err := time.Parse(time.RFC3339, e.CapturedAt); err != nil {
				return fail("evidence.captured_at", "expected RFC3339 timestamp")
			}
		}
	}
	return nil
}
func validateHeaders(headers []Header) error {
	if len(headers) > 1024 {
		return errors.New("too many headers")
	}
	seen := map[string]bool{}
	for _, h := range headers {
		if len(h.Values) > 1024 {
			return errors.New("too many header values")
		}
		n := strings.ToLower(h.Name)
		if !headerToken(n) || seen[n] {
			return errors.New("invalid or duplicate header name; use Values for repeated values")
		}
		seen[n] = true
		for _, v := range h.Values {
			if strings.ContainsAny(v, "\r\n\x00") || len(v) > 65536 {
				return errors.New("header value contains newline")
			}
		}
	}
	return nil
}

func headerToken(n string) bool {
	if n == "" || len(n) > 256 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	return true
}
func validateOrder(order, pseudo []string) error {
	seen := map[string]bool{}
	for _, key := range order {
		k := strings.ToLower(key)
		if !headerToken(k) || seen[k] {
			return ErrInvalidProfile
		}
		seen[k] = true
	}
	seen = map[string]bool{}
	for _, key := range pseudo {
		if key != ":method" && key != ":authority" && key != ":scheme" && key != ":path" || seen[key] {
			return ErrInvalidProfile
		}
		seen[key] = true
	}
	if len(pseudo) != 0 && len(pseudo) != 4 {
		return ErrInvalidProfile
	}
	return nil
}
func validateHTTP2(h HTTP2Config) error {
	if h.FirstStreamID != 0 && (h.FirstStreamID%2 == 0 || h.FirstStreamID > 0x7fffffff) {
		return ErrInvalidProfile
	}
	streamWindow := uint32(65535)
	for _, setting := range h.Settings {
		if setting.ID == 4 {
			streamWindow = setting.Value
		}
	}
	if uint64(streamWindow)+uint64(h.StreamWindowIncrement) > 0x7fffffff {
		return ErrInvalidProfile
	}
	if len(h.Settings) > 1024 || len(h.PriorityFrames) > 1024 || h.ConnectionFlow > 0x7fffffff {
		return ErrInvalidProfile
	}
	seen := map[uint16]bool{}
	for _, s := range h.Settings {
		if seen[s.ID] || s.ID == 0 {
			return ErrInvalidProfile
		}
		seen[s.ID] = true
		if s.ID == 2 && s.Value > 1 || s.ID == 4 && s.Value > 0x7fffffff || s.ID == 5 && (s.Value < 16384 || s.Value > 16777215) {
			return ErrInvalidProfile
		}
	}
	validatePriority := func(p Priority) error {
		if p.Weight < 1 || p.Weight > 256 || p.Dependency > 0x7fffffff || p.StreamID > 0x7fffffff {
			return ErrInvalidProfile
		}
		return nil
	}
	if h.HeaderPriority != nil {
		if err := validatePriority(*h.HeaderPriority); err != nil {
			return err
		}
	}
	streams := map[uint32]bool{}
	for _, p := range h.PriorityFrames {
		if err := validatePriority(p); err != nil {
			return err
		}
		if p.StreamID == 0 || p.StreamID == p.Dependency || streams[p.StreamID] {
			return ErrInvalidProfile
		}
		streams[p.StreamID] = true
	}
	return nil
}
