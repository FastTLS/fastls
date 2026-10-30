// Package compiler translates the neutral contract without product or UA rules.
package compiler

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"

	"github.com/FastTLS/fastls/profile"
	utls "github.com/refraction-networking/utls"
)

func unsupported(field, feature string) error {
	return &profile.UnsupportedFeature{Field: field, Feature: feature}
}
func grease(c profile.Code) bool { return uint16(c)&0x0f0f == 0x0a0a && byte(c) == byte(c>>8) }
func codes(a []profile.Code) []uint16 {
	b := make([]uint16, len(a))
	for i, c := range a {
		b[i] = uint16(c)
		if grease(c) {
			b[i] = utls.GREASE_PLACEHOLDER
		}
	}
	return b
}

// TLS creates a fresh preset on every call. Key shares carry no fixed secrets.
func TLS(s profile.Spec) (*utls.ClientHelloSpec, error) {
	if err := profile.Validate(s); err != nil {
		return nil, err
	}
	if err := profile.ValidateID(s); err != nil {
		return nil, err
	}
	for _, f := range s.Capabilities.RequiredFeatures {
		switch f {
		case "tls.ordered.v1", "http1.ordered.v1", "http2.ordered.v1", "http2.stream.v1", "ordered-settings", "http.headers.protocol.v1", "tls.signature-advertised.v1", "tls.shuffle-chrome.v1":
		default:
			return nil, unsupported("capabilities.required_features", f)
		}
	}
	for _, p := range s.Capabilities.Protocols {
		switch p {
		case "tls", "http1", "http2":
		default:
			return nil, unsupported("capabilities.protocols", p)
		}
	}
	if s.TLS.RecordVersion != 0 && s.TLS.RecordVersion != 0x0301 {
		return nil, unsupported("tls.record_version", "explicit-record-version")
	}
	if s.TLS.LegacyVersion != 0 && s.TLS.LegacyVersion != 0x0303 {
		return nil, unsupported("tls.legacy_version", "explicit-legacy-version")
	}
	if s.TLS.SessionPolicy == "resumption" {
		return nil, unsupported("tls.session_policy", "resumption.v1")
	}
	if s.Headers.ExtraOrder != "" && s.Headers.ExtraOrder != "sorted" {
		return nil, unsupported("headers.extra_order", s.Headers.ExtraOrder)
	}
	supported := map[uint16]bool{}
	for _, c := range append(utls.CipherSuites(), utls.InsecureCipherSuites()...) {
		supported[c.ID] = true
	}
	for _, c := range s.TLS.CipherSuites {
		if !grease(c) && !supported[uint16(c)] && !slices.Contains(s.Capabilities.AdvertisedOnly, c) {
			return nil, unsupported("tls.cipher_suites", fmt.Sprintf("0x%04x", c))
		}
	}
	if s.TLS.GREASEPolicy == "none" {
		for _, c := range s.TLS.CipherSuites {
			if grease(c) {
				return nil, unsupported("tls.grease_policy", "GREASE conflicts with none")
			}
		}
	}
	h2 := false
	spec := &utls.ClientHelloSpec{TLSVersMin: uint16(s.TLS.MinVersion), TLSVersMax: uint16(s.TLS.MaxVersion), CipherSuites: codes(s.TLS.CipherSuites), CompressionMethods: []uint8{0}}
	for _, e := range s.TLS.Extensions {
		if s.TLS.GREASEPolicy == "none" {
			values := append(append(append([]profile.Code{}, e.Groups...), e.KeyShares...), e.Versions...)
			values = append(values, e.ID)
			for _, c := range values {
				if grease(c) {
					return nil, unsupported("tls.grease_policy", "GREASE conflicts with none")
				}
			}
		}
		if e.ID == 16 {
			h2 = slices.Contains(e.ALPN, "h2")
		}
		x, err := extension(e, s.Capabilities.AdvertisedOnly)
		if err != nil {
			return nil, err
		}
		if slices.Contains(s.TLS.OptionalExtensions, e.ID) && rand.IntN(2) == 0 {
			continue
		}
		spec.Extensions = append(spec.Extensions, x)
	}
	if h2 {
		for _, v := range s.HTTP2.Settings {
			if v.ID == 2 && v.Value > 1 {
				return nil, unsupported("http2.settings", "ENABLE_PUSH outside 0..1")
			}
		}
	}

	if s.TLS.ExtensionOrder == "shuffle-except-psk-last" {
		rand.Shuffle(len(spec.Extensions), func(i, j int) { spec.Extensions[i], spec.Extensions[j] = spec.Extensions[j], spec.Extensions[i] })
	}
	if s.TLS.ExtensionOrder == "shuffle-chrome" {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}
	return spec, nil
}

func extension(e profile.Extension, advertisedOnly []profile.Code) (utls.TLSExtension, error) {
	field := fmt.Sprintf("tls.extensions[0x%04x]", e.ID)
	// Reject parameters attached to the wrong extension instead of dropping them.
	allowed := map[string]bool{"id": true, "strategy": true}
	for _, k := range map[profile.Code][]string{10: {"groups"}, 11: {"point_formats"}, 13: {"signature_algorithms"}, 34: {"signature_algorithms"}, 50: {"signature_algorithms"}, 16: {"alpn"}, 43: {"versions"}, 51: {"key_shares"}, 27: {"compression_algorithms"}, 45: {"psk_modes"}, 17513: {"alpn"}, 17613: {"alpn"}}[e.ID] {
		allowed[k] = true
	}
	b, _ := json.Marshal(e)
	var params map[string]json.RawMessage
	_ = json.Unmarshal(b, &params)
	for k := range params {
		if k != "raw_hex" && !allowed[k] {
			return nil, unsupported(field+"."+k, "parameter on wrong extension")
		}
	}
	if e.Strategy != "" && e.Strategy != "generate" && !(e.ID == 21 && e.Strategy == "boringssl") && !(e.ID == 65037 && e.Strategy == "grease-ech") {
		return nil, unsupported(field+".strategy", e.Strategy)
	}
	if e.RawHex != nil {
		if len(params) > 2 {
			return nil, unsupported(field, "raw payload combined with generated parameters")
		}
		switch e.ID {
		case 0, 10, 11, 13, 16, 27, 41, 43, 45, 51, 50, 65281, 35:
			return nil, unsupported(field, "raw override of semantic extension")
		}
		data, err := hex.DecodeString(*e.RawHex)
		if err != nil {
			return nil, err
		}
		if grease(e.ID) {
			return &utls.UtlsGREASEExtension{Body: data}, nil
		}
		return &utls.GenericExtension{Id: uint16(e.ID), Data: data}, nil
	}
	if grease(e.ID) {
		return &utls.UtlsGREASEExtension{}, nil
	}
	switch e.ID {
	case 0:
		return &utls.SNIExtension{}, nil
	case 5:
		return &utls.StatusRequestExtension{}, nil
	case 10:
		groups := []utls.CurveID{}
		for _, g := range codes(e.Groups) {
			switch g {
			case 23, 24, 25, 29, 256, 257, 258, 259, 260, 4588, 25497, utls.GREASE_PLACEHOLDER:
			default:
				return nil, unsupported(field, "unsupported key exchange group")
			}
			groups = append(groups, utls.CurveID(g))
		}
		return &utls.SupportedCurvesExtension{Curves: groups}, nil
	case 11:
		return &utls.SupportedPointsExtension{SupportedPoints: slices.Clone(e.PointFormats)}, nil
	case 13, 34, 50:
		a := []utls.SignatureScheme{}
		for _, v := range e.SignatureAlgorithms {
			if grease(v) {
				a = append(a, utls.SignatureScheme(0x0a0a+0x1010*rand.IntN(16)))
				continue
			}
			switch v {
			case 0x0201, 0x0203, 0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807:
			case 0x0904, 0x0905, 0x0906:
				if !slices.Contains(advertisedOnly, v) {
					return nil, unsupported(field, "ML-DSA requires explicit advertised_only declaration; backend verification unavailable")
				}
			default:
				return nil, unsupported(field, "unsupported signature algorithm")
			}
			a = append(a, utls.SignatureScheme(v))
		}
		if e.ID == 50 {
			return &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: a}, nil
		}
		if e.ID == 34 {
			return &utls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: a}, nil
		}
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: a}, nil
	case 16:
		for _, p := range e.ALPN {
			if p != "h2" && p != "http/1.1" {
				return nil, unsupported(field+".alpn", p)
			}
		}
		return &utls.ALPNExtension{AlpnProtocols: slices.Clone(e.ALPN)}, nil
	case 18:
		return &utls.SCTExtension{}, nil
	case 21:
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}, nil
	case 23:
		return &utls.ExtendedMasterSecretExtension{}, nil
	case 27:
		a := []utls.CertCompressionAlgo{}
		for _, v := range e.CompressionAlgorithms {
			if v < 1 || v > 3 {
				return nil, unsupported(field, "certificate compression")
			}
			a = append(a, utls.CertCompressionAlgo(v))
		}
		return &utls.UtlsCompressCertExtension{Algorithms: a}, nil
	case 35:
		return &utls.SessionTicketExtension{}, nil
	case 43:
		return &utls.SupportedVersionsExtension{Versions: codes(e.Versions)}, nil
	case 45:
		return &utls.PSKKeyExchangeModesExtension{Modes: slices.Clone(e.PSKModes)}, nil
	case 51:
		a := []utls.KeyShare{}
		for _, v := range codes(e.KeyShares) {
			switch v {
			case 23, 24, 25, 29, 4588, 25497, utls.GREASE_PLACEHOLDER:
			default:
				return nil, unsupported(field, "unsupported generated key share")
			}
			share := utls.KeyShare{Group: utls.CurveID(v)}
			if v == utls.GREASE_PLACEHOLDER {
				share.Data = []byte{0}
			}
			a = append(a, share)
		}
		return &utls.KeyShareExtension{KeyShares: a}, nil
	case 17513:
		return &utls.ApplicationSettingsExtension{SupportedProtocols: slices.Clone(e.ALPN)}, nil
	case 17613:
		return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: slices.Clone(e.ALPN)}, nil
	case 65281:
		return &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}, nil
	case 65037:
		if e.Strategy != "grease-ech" {
			return nil, unsupported(field, "ECH requires explicit grease-ech strategy")
		}
		return &utls.GREASEEncryptedClientHelloExtension{}, nil
	default:
		return nil, unsupported(field, "extension needs a supported strategy or explicit raw payload")
	}
}
