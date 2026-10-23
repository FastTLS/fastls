package imitate

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/textproto"
	"reflect"
	"slices"
	"strings"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/profile"
)

func WithProvider(p profile.Provider) UseOption {
	return func(c *useConfig) { c.provider = p; c.providerSet = true }
}

func Use(o *fastls.Options, selector string, opts ...UseOption) (profile.Match, error) {
	return UseContext(context.Background(), o, selector, opts...)
}
func UseContext(ctx context.Context, o *fastls.Options, selector string, opts ...UseOption) (profile.Match, error) {
	zero := profile.Match{}
	if o == nil || ctx == nil {
		return zero, fmt.Errorf("%w: nil options/context", profile.ErrInvalidOptions)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	c := useConfig{policy: profile.AllowCompatible}
	for _, opt := range opts {
		if opt == nil {
			return zero, profile.ErrInvalidOptions
		}
		opt(&c)
	}
	if c.policy != profile.RecordedOnly && c.policy != profile.AllowCompatible {
		return zero, profile.ErrInvalidOptions
	}
	w := *o
	w.Headers = maps.Clone(o.Headers)
	w.HeaderValues = maps.Clone(o.HeaderValues)
	if err := normalizeHeaders(&w, c.uaSet); err != nil {
		return zero, err
	}
	if c.uaSet {
		if strings.ContainsAny(c.ua, "\r\n\x00") {
			return zero, profile.ErrInvalidUserAgent
		}
		w.UserAgent = c.ua
		w.Headers["User-Agent"] = c.ua
		delete(w.HeaderValues, "User-Agent")
	}
	p := c.provider
	if !c.providerSet {
		p = o.FingerprintProvider
	}
	if nilProvider(p) {
		return zero, fmt.Errorf("%w: fingerprint provider required (use WithProvider or Options.FingerprintProvider)", profile.ErrInvalidOptions)
	}
	r := profile.ResolveRequest{Selector: selector, Defaults: c.defaults, Policy: c.policy}
	result, err := p.Resolve(ctx, r)
	if err != nil {
		return zero, err
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	m, err := applyResolution(&w, result)
	if err != nil {
		return zero, err
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	*o = w
	return m, nil
}
func nilProvider(p profile.Provider) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// Apply accepts a complete custom Spec through the same validation/application path.
func Apply(o *fastls.Options, s profile.Spec) (profile.Match, error) {
	return applyResolution(o, profile.Resolution{Spec: &s, Match: profile.Match{ProfileID: s.ID, Method: "custom", ContractVersion: profile.ContractVersion}})
}

func applyResolution(o *fastls.Options, result profile.Resolution) (profile.Match, error) {
	zero := profile.Match{}
	if o == nil {
		return zero, profile.ErrInvalidOptions
	}
	if (result.Spec == nil) == (result.Legacy == nil) {
		return zero, fmt.Errorf("%w: exactly one Spec or Legacy required", profile.ErrInvalidProfile)
	}
	if err := profile.ValidateResolution(result); err != nil {
		return zero, err
	}
	result = profile.CloneResolution(result)
	if result.Match.ContractVersion != "" && result.Match.ContractVersion != profile.ContractVersion {
		return zero, &profile.UnsupportedFeature{Field: "match.contract_version", Feature: result.Match.ContractVersion}
	}
	w := *o
	w.Headers = maps.Clone(o.Headers)
	w.HeaderValues = maps.Clone(o.HeaderValues)
	if err := normalizeHeaders(&w, false); err != nil {
		return zero, err
	}
	callerHeaders := maps.Clone(w.Headers)
	callerValues := maps.Clone(w.HeaderValues)
	callerUA := w.UserAgent
	w.Headers = map[string]string{}
	w.HeaderValues = nil
	w.UserAgent = ""
	w.FingerprintUserAgent = ""
	w.Profile = nil
	w.HTTP2Settings = nil
	w.HTTP2SettingsString = ""
	w.HeaderOrderKeys = nil
	w.PHeaderOrderKeys = nil
	if s := result.Spec; s != nil {
		w.UserAgent = ""
		if err := fastls.ApplyProfile(&w, *s); err != nil {
			return zero, err
		}
	} else {
		l := result.Legacy
		switch l.Format {
		case "ja3":
			w.Fingerprint = fastls.Ja3Fingerprint{FingerprintValue: l.Hello}
		case "ja4r":
			w.Fingerprint = fastls.Ja4Fingerprint{FingerprintValue: l.Hello}
		default:
			return zero, &profile.UnsupportedFeature{Field: "legacy.format", Feature: string(l.Format)}
		}
		if l.Hello == "" {
			return zero, fmt.Errorf("%w: empty legacy Hello", profile.ErrInvalidProfile)
		}
		w.UserAgent = l.UserAgent
		w.FingerprintUserAgent = l.UserAgent
		if _, err := fastls.StringToSpec(l.Hello, l.UserAgent); err != nil {
			return zero, fmt.Errorf("%w: compatibility TLS adapter: %v", profile.ErrInvalidProfile, err)
		}
		w.HTTP2SettingsString = l.HTTP2Settings
		if l.HTTP2 != nil {
			w.HTTP2Settings = fastls.ProfileHTTP2(*l.HTTP2)
			w.HTTP2Settings.Explicit = false
		}
		if l.HTTP2Settings != "" {
			h, pseudo, err := fastls.ParseH2SettingsStringWithPHeaderOrder(l.HTTP2Settings)
			if err != nil {
				return zero, fmt.Errorf("%w: legacy HTTP2: %v", profile.ErrInvalidProfile, err)
			}
			w.HTTP2Settings = fastls.ToHTTP2Settings(h)
			w.PHeaderOrderKeys = pseudo
		}
		if len(l.PseudoOrder) > 0 {
			w.PHeaderOrderKeys = slices.Clone(l.PseudoOrder)
		}
		w.HeaderOrderKeys = slices.Clone(l.HeaderOrder)
	}
	removeUA := false
	for _, key := range result.Headers.Remove {
		if strings.EqualFold(key, "User-Agent") {
			removeUA = true
		}
	}
	for _, prefix := range result.Headers.RemovePrefixes {
		if strings.HasPrefix("user-agent", strings.ToLower(prefix)) {
			removeUA = true
		}
	}
	if removeUA {
		if result.Legacy != nil && result.Legacy.UserAgent != "" {
			return zero, &profile.UnsupportedFeature{Field: "legacy.headers.user-agent", Feature: "removing the legacy TLS identity"}
		}
		w.UserAgent = ""
	}
	for k := range w.Headers {
		remove := false
		for _, prefix := range result.Headers.RemovePrefixes {
			if prefix == "" {
				return zero, profile.ErrInvalidProfile
			}
			if strings.HasPrefix(strings.ToLower(k), strings.ToLower(prefix)) {
				remove = true
			}
		}
		for _, key := range result.Headers.Remove {
			if strings.EqualFold(k, key) {
				remove = true
			}
		}
		if remove {
			delete(w.Headers, k)
			delete(w.HeaderValues, k)
		}
	}
	seen := map[string]bool{}
	for _, rule := range result.Headers.Rules {
		k := textproto.CanonicalMIMEHeaderKey(rule.Name)
		if seen[k] || len(rule.Values) == 0 || (rule.Mode != "default" && rule.Mode != "replace") {
			return zero, fmt.Errorf("%w: malformed header policy", profile.ErrInvalidProfile)
		}
		seen[k] = true
		if rule.Mode == "replace" || w.Headers[k] == "" || slices.Contains(rule.IfEquals, w.Headers[k]) {
			w.Headers[k] = rule.Values[0]
			if k == "User-Agent" {
				w.UserAgent = rule.Values[0]
			}
			delete(w.HeaderValues, k)
			if len(rule.Values) > 1 {
				if w.HeaderValues == nil {
					w.HeaderValues = map[string][]string{}
				}
				w.HeaderValues[k] = slices.Clone(rule.Values)
			}
		}
	}
	if w.Profile != nil && w.Profile.Identity != nil {
		w.FingerprintUserAgent = w.Profile.Identity.UserAgent
	}
	// Caller values, including explicitly empty values, win over generated defaults.
	for k, v := range callerHeaders {
		w.Headers[k] = v
		delete(w.HeaderValues, k)
	}
	for k, values := range callerValues {
		if w.HeaderValues == nil {
			w.HeaderValues = map[string][]string{}
		}
		w.HeaderValues[k] = slices.Clone(values)
	}
	if ua, exists := callerHeaders["User-Agent"]; exists {
		w.UserAgent = ua
	} else if callerUA != "" {
		w.UserAgent = callerUA
	}
	if strings.ContainsAny(w.UserAgent, "\r\n\x00") {
		return zero, profile.ErrInvalidUserAgent
	}
	w.Headers["User-Agent"] = w.UserAgent
	delete(w.HeaderValues, "User-Agent")
	if err := normalizeHeaders(&w, false); err != nil {
		return zero, err
	}
	for k, values := range w.HeaderValues {
		for _, v := range values {
			if strings.ContainsAny(v, "\r\n\x00") {
				return zero, profile.ErrInvalidProfile
			}
		}
		if len(values) == 0 {
			delete(w.HeaderValues, k)
		}
	}
	result.Match.UserAgent = w.UserAgent
	result.Match.ContractVersion = profile.ContractVersion
	*o = w
	return result.Match, nil
}

// Register validates a closed offline bundle and returns an isolated provider.
func Register(data []byte) (profile.Provider, error) {
	p, err := profile.DecodeBundle(data)
	if err != nil {
		return nil, err
	}
	var bundle profile.Bundle
	if err = json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}
	for _, r := range bundle.Records {
		if _, err = applyResolution(&fastls.Options{}, r); err != nil {
			return nil, fmt.Errorf("register %s: %w", r.Match.ProfileID, err)
		}
	}
	return p, nil
}

func normalizeHeaderValues(o *fastls.Options, overrideUA bool) error {
	if o.HeaderValues == nil {
		return nil
	}
	normalized := map[string][]string{}
	for key, values := range o.HeaderValues {
		k := textproto.CanonicalMIMEHeaderKey(key)
		if overrideUA && k == "User-Agent" {
			continue
		}
		if _, duplicate := normalized[k]; duplicate {
			return profile.ErrInvalidOptions
		}
		if len(values) == 0 {
			continue
		}
		check := fastls.Options{Headers: map[string]string{key: values[0]}}
		if err := normalizeHeaders(&check, false); err != nil {
			return err
		}
		for _, v := range values {
			if strings.ContainsAny(v, "\r\n\x00") {
				return profile.ErrInvalidOptions
			}
		}
		if k == "User-Agent" && len(values) != 1 {
			return profile.ErrIdentityConflict
		}
		o.Headers[k] = values[0]
		normalized[k] = slices.Clone(values)
	}
	o.HeaderValues = normalized
	return nil
}
