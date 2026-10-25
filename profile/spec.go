// Package profile describes ordered client fingerprints without a protocol backend dependency.
package profile

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
)

const SchemaVersion = 1

// Code encodes a TLS identifier as an explicit, fixed-width hexadecimal string.
type Code uint16

func (c Code) MarshalJSON() ([]byte, error) { return json.Marshal(fmt.Sprintf("0x%04x", uint16(c))) }
func (c *Code) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("TLS identifier must be a 0x0000 string: %w", err)
	}
	if len(s) != 6 || s[:2] != "0x" {
		return fmt.Errorf("invalid TLS identifier %q", s)
	}
	n, err := strconv.ParseUint(s[2:], 16, 16)
	if err != nil {
		return err
	}
	*c = Code(n)
	return nil
}

type Metadata struct {
	ID                    string `json:"id,omitempty"`
	Kind                  string `json:"kind"`
	Family                string `json:"family"`
	Product               string `json:"product"`
	ProductVersion        string `json:"product_version"`
	EngineVersion         string `json:"engine_version,omitempty"`
	Platform              string `json:"platform"`
	OSVersion             string `json:"os_version,omitempty"`
	Arch                  string `json:"arch,omitempty"`
	Device                string `json:"device,omitempty"`
	Channel               string `json:"channel,omitempty"`
	Variant               string `json:"variant,omitempty"`
	Implementation        string `json:"implementation,omitempty"`
	ImplementationVersion string `json:"implementation_version,omitempty"`
}
type Spec struct {
	SchemaVersion int          `json:"schema_version"`
	ID            string       `json:"id"`
	Metadata      Metadata     `json:"metadata"`
	TLS           TLSConfig    `json:"tls"`
	HTTP2         HTTP2Config  `json:"http2"`
	Headers       HeaderConfig `json:"headers"`
	Identity      *Identity    `json:"identity,omitempty"`
	Capabilities  Capabilities `json:"capabilities"`
	Evidence      []Evidence   `json:"evidence"`
}
type TLSConfig struct {
	MinVersion         Code        `json:"min_version"`
	MaxVersion         Code        `json:"max_version"`
	RecordVersion      Code        `json:"record_version,omitempty"`
	LegacyVersion      Code        `json:"legacy_version,omitempty"`
	CipherSuites       []Code      `json:"cipher_suites"`
	Extensions         []Extension `json:"extensions"`
	ExtensionOrder     string      `json:"extension_order,omitempty"`
	OptionalExtensions []Code      `json:"optional_extensions,omitempty"`
	GREASEPolicy       string      `json:"grease_policy,omitempty"`
	SessionPolicy      string      `json:"session_policy,omitempty"`
}

// Extension contains neutral generation parameters, never connection key material.
type Extension struct {
	ID                    Code     `json:"id"`
	Strategy              string   `json:"strategy,omitempty"`
	Versions              []Code   `json:"versions,omitempty"`
	Groups                []Code   `json:"groups,omitempty"`
	KeyShares             []Code   `json:"key_shares,omitempty"`
	SignatureAlgorithms   []Code   `json:"signature_algorithms,omitempty"`
	ALPN                  []string `json:"alpn,omitempty"`
	CompressionAlgorithms []Code   `json:"compression_algorithms,omitempty"`
	PSKModes              []uint8  `json:"psk_modes,omitempty"`
	PointFormats          []uint8  `json:"point_formats,omitempty"`
	RawHex                *string  `json:"raw_hex,omitempty"`
}
type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}
type Priority struct {
	StreamID   uint32 `json:"stream_id"`
	Dependency uint32 `json:"dependency"`
	Weight     uint16 `json:"weight"`
	Exclusive  bool   `json:"exclusive"`
}
type HTTP2Config struct {
	Settings       []Setting  `json:"settings"`
	ConnectionFlow uint32     `json:"connection_flow"`
	HeaderPriority *Priority  `json:"header_priority,omitempty"`
	PriorityFrames []Priority `json:"priority_frames"`
}
type Header struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}
type HeaderConfig struct {
	HTTP1Defaults []Header `json:"http1_defaults,omitempty"`
	HTTP2Defaults []Header `json:"http2_defaults,omitempty"`
	HTTP1Order    []string `json:"http1_order,omitempty"` // Ordered wire names, including HTTP/1 capitalization.
	Defaults      []Header `json:"defaults"`
	Order         []string `json:"order"`
	PseudoOrder   []string `json:"pseudo_order"`
	ExtraOrder    string   `json:"extra_order,omitempty"`
}
type Identity struct {
	UserAgent   string   `json:"user_agent,omitempty"`
	ClientHints []Header `json:"client_hints,omitempty"`
}
type Capabilities struct {
	Protocols        []string `json:"protocols"`
	RequiredFeatures []string `json:"required_features"`
	AdvertisedOnly   []Code   `json:"advertised_only"`
	Limitations      []string `json:"limitations"`
	Legacy           bool     `json:"legacy,omitempty"`
}
type Evidence struct {
	Source         string   `json:"source"`
	CapturedAt     string   `json:"captured_at,omitempty"`
	ProductVersion string   `json:"product_version,omitempty"`
	Platform       string   `json:"platform,omitempty"`
	VerifiedFields []string `json:"verified_fields"`
	Transport      string   `json:"transport,omitempty"`
	SampleSHA256   string   `json:"sample_sha256,omitempty"`
}

func cloneHeaders(h []Header) []Header {
	result := slices.Clone(h)
	for i := range result {
		result[i].Values = slices.Clone(result[i].Values)
	}
	return result
}
func Clone(s Spec) Spec {
	s.TLS.CipherSuites = slices.Clone(s.TLS.CipherSuites)
	s.TLS.OptionalExtensions = slices.Clone(s.TLS.OptionalExtensions)
	s.TLS.Extensions = slices.Clone(s.TLS.Extensions)
	for i := range s.TLS.Extensions {
		e := &s.TLS.Extensions[i]
		e.Versions = slices.Clone(e.Versions)
		e.Groups = slices.Clone(e.Groups)
		e.KeyShares = slices.Clone(e.KeyShares)
		e.SignatureAlgorithms = slices.Clone(e.SignatureAlgorithms)
		e.ALPN = slices.Clone(e.ALPN)
		e.CompressionAlgorithms = slices.Clone(e.CompressionAlgorithms)
		e.PSKModes = slices.Clone(e.PSKModes)
		e.PointFormats = slices.Clone(e.PointFormats)
		if e.RawHex != nil {
			v := *e.RawHex
			e.RawHex = &v
		}
	}
	s.HTTP2.Settings = slices.Clone(s.HTTP2.Settings)
	s.HTTP2.PriorityFrames = slices.Clone(s.HTTP2.PriorityFrames)
	if s.HTTP2.HeaderPriority != nil {
		v := *s.HTTP2.HeaderPriority
		s.HTTP2.HeaderPriority = &v
	}
	s.Headers.Defaults = cloneHeaders(s.Headers.Defaults)
	s.Headers.HTTP1Defaults = cloneHeaders(s.Headers.HTTP1Defaults)
	s.Headers.HTTP2Defaults = cloneHeaders(s.Headers.HTTP2Defaults)
	s.Headers.HTTP1Order = slices.Clone(s.Headers.HTTP1Order)
	s.Headers.Order = slices.Clone(s.Headers.Order)
	s.Headers.PseudoOrder = slices.Clone(s.Headers.PseudoOrder)
	if s.Identity != nil {
		v := *s.Identity
		v.ClientHints = cloneHeaders(v.ClientHints)
		s.Identity = &v
	}
	s.Capabilities.Protocols = slices.Clone(s.Capabilities.Protocols)
	s.Capabilities.RequiredFeatures = slices.Clone(s.Capabilities.RequiredFeatures)
	s.Capabilities.AdvertisedOnly = slices.Clone(s.Capabilities.AdvertisedOnly)
	s.Capabilities.Limitations = slices.Clone(s.Capabilities.Limitations)
	s.Evidence = slices.Clone(s.Evidence)
	for i := range s.Evidence {
		s.Evidence[i].VerifiedFields = slices.Clone(s.Evidence[i].VerifiedFields)
	}
	return s
}
