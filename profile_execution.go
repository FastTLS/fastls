package fastls

import (
	"maps"
	"net/textproto"
	"slices"

	"github.com/FastTLS/fastls/internal/compiler"
	"github.com/FastTLS/fastls/profile"
	"github.com/FastTLS/ftransport"
)

// ValidateProfile checks semantic and backend support without opening a connection.
func ValidateProfile(s profile.Spec) error { _, err := compiler.TLS(s); return err }

// ApplyProfile atomically prepares a complete neutral fingerprint, without a generator.
func ApplyProfile(o *Options, s profile.Spec) error {
	if o == nil {
		return profile.ErrInvalidOptions
	}
	s = profile.Clone(s)
	if err := ValidateProfile(s); err != nil {
		return err
	}
	w := *o
	w.Headers = maps.Clone(o.Headers)
	if w.Headers == nil {
		w.Headers = map[string]string{}
	}
	w.HeaderValues = maps.Clone(o.HeaderValues)
	if w.HeaderValues == nil {
		w.HeaderValues = map[string][]string{}
	}
	setDefault := func(h profile.Header) {
		k := textproto.CanonicalMIMEHeaderKey(h.Name)
		for existing := range w.HeaderValues {
			if textproto.CanonicalMIMEHeaderKey(existing) == k {
				return
			}
		}
		for existing := range w.Headers {
			if textproto.CanonicalMIMEHeaderKey(existing) == k {
				return
			}
		}
		if len(h.Values) > 0 {
			w.Headers[k] = h.Values[0]
			if len(h.Values) > 1 {
				w.HeaderValues[k] = slices.Clone(h.Values)
			}
		}
	}
	for _, h := range s.Headers.Defaults {
		setDefault(h)
	}
	if s.Identity != nil {
		if w.UserAgent == "" {
			w.UserAgent = s.Identity.UserAgent
		}
		if w.FingerprintUserAgent == "" {
			w.FingerprintUserAgent = s.Identity.UserAgent
		}
		for _, h := range s.Identity.ClientHints {
			setDefault(h)
		}
	}
	w.UserAgent = w.requestUserAgent()
	w.Profile = &s
	w.Fingerprint = nil
	w.FingerprintSignatureAlgorithms = nil
	w.HTTP2SettingsString = ""
	w.HTTP2Settings = ProfileHTTP2(s.HTTP2)
	w.HeaderOrderKeys = slices.Clone(s.Headers.Order)
	w.PHeaderOrderKeys = slices.Clone(s.Headers.PseudoOrder)
	*o = w
	return nil
}

func ProfileHTTP2(h profile.HTTP2Config) *ftransport.HTTP2Config {
	r := &ftransport.HTTP2Config{
		FirstStreamID:             h.FirstStreamID,
		StreamWindowIncrement:     h.StreamWindowIncrement,
		InitialSettings:           ftransport.ExplicitHTTP2Settings(),
		ConnectionWindowIncrement: h.ConnectionFlow,
	}
	for _, s := range h.Settings {
		r.InitialSettings.Values = append(r.InitialSettings.Values, ftransport.HTTP2Setting{ID: ftransport.HTTP2SettingID(s.ID), Value: s.Value})
	}
	priority := func(p profile.Priority) ftransport.HTTP2PriorityParam {
		return ftransport.HTTP2PriorityParam{Dependency: p.Dependency, Weight: p.Weight, Exclusive: p.Exclusive}
	}
	if h.HeaderPriority != nil {
		v := priority(*h.HeaderPriority)
		r.HeaderPriority = &v
	}
	for _, p := range h.PriorityFrames {
		r.PriorityFrames = append(r.PriorityFrames, ftransport.HTTP2PriorityFrame{StreamID: p.StreamID, HTTP2PriorityParam: priority(p)})
	}
	return r
}
