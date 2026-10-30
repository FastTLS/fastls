package fastls

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/FastTLS/fastls/profile"
)

// FingerprintParameters overlays compact observations onto an explicit complete
// base. Fields omitted by JA3 (ALPN, signature algorithms, key shares, etc.) keep
// the base's values. This does not certify browser equivalence.
type FingerprintParameters struct {
	JA3 string `json:"ja3"`
	H2  string `json:"h2"`
}

func fingerprintNumber(text string, bits int) (uint64, error) {
	if text == "" || len(text) > 1 && text[0] == '0' {
		return 0, profile.ErrInvalidProfile
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return 0, profile.ErrInvalidProfile
		}
	}
	return strconv.ParseUint(text, 10, bits)
}

func fingerprintCodes(text string, bits int, limit int) ([]profile.Code, error) {
	result := []profile.Code{}
	if text == "" {
		return result, nil
	}
	parts := strings.Split(text, "-")
	if len(parts) > limit {
		return nil, profile.ErrInvalidProfile
	}
	seen := map[uint64]bool{}
	for _, part := range parts {
		n, err := fingerprintNumber(part, bits)
		if err != nil || seen[n] || n&0x0f0f == 0x0a0a && byte(n) == byte(n>>8) {
			return nil, profile.ErrInvalidProfile
		}
		seen[n] = true
		result = append(result, profile.Code(n))
	}
	return result, nil
}

// AdaptProfile performs no I/O. It returns an independent, backend-validated
// Spec, or an error without changing base. Compact fields must be canonical
// decimal text, and extensions must already have explicit parameters in base.
func AdaptProfile(base profile.Spec, parameters FingerprintParameters) (profile.Spec, error) {
	fail := func() (profile.Spec, error) {
		return profile.Spec{}, fmt.Errorf("%w: invalid fingerprint parameters", profile.ErrInvalidProfile)
	}
	if parameters.JA3 == "" && parameters.H2 == "" || len(parameters.JA3) > 16384 || len(parameters.H2) > 16384 {
		return fail()
	}
	if err := ValidateProfile(base); err != nil {
		return profile.Spec{}, err
	}
	s := profile.Clone(base)
	if parameters.JA3 != "" {
		parts := strings.Split(parameters.JA3, ",")
		if len(parts) != 5 || parts[0] != "771" {
			return fail()
		}
		ciphers, err := fingerprintCodes(parts[1], 16, 4096)
		if err != nil || len(ciphers) == 0 {
			return fail()
		}
		ids, err := fingerprintCodes(parts[2], 16, 4096)
		if err != nil {
			return fail()
		}
		groups, err := fingerprintCodes(parts[3], 16, 4096)
		if err != nil {
			return fail()
		}
		points, err := fingerprintCodes(parts[4], 8, 256)
		if err != nil {
			return fail()
		}
		if !slices.Contains(ids, profile.Code(10)) && len(groups) != 0 || !slices.Contains(ids, profile.Code(11)) && len(points) != 0 {
			return fail()
		}
		if slices.Contains(ids, profile.Code(10)) && len(groups) == 0 || slices.Contains(ids, profile.Code(11)) && len(points) == 0 {
			return fail()
		}
		known := map[profile.Code]profile.Extension{}
		for _, extension := range s.TLS.Extensions {
			known[extension.ID] = extension
		}
		s.TLS.CipherSuites, s.TLS.Extensions = ciphers, []profile.Extension{}
		s.TLS.ExtensionOrder, s.TLS.OptionalExtensions = "", nil
		for _, id := range ids {
			extension, ok := known[id]
			if !ok {
				return fail()
			}
			if id == 41 || id == 21 && extension.Strategy == "boringssl" {
				return fail()
			}
			if id == 10 {
				extension.Groups = groups
			}
			if id == 51 {
				extension.KeyShares = slices.DeleteFunc(extension.KeyShares, func(c profile.Code) bool { return uint16(c)&0x0f0f == 0x0a0a && byte(c) == byte(c>>8) })
			}
			if id == 11 {
				extension.PointFormats = []uint8{}
				for _, point := range points {
					extension.PointFormats = append(extension.PointFormats, uint8(point))
				}
			}
			s.TLS.Extensions = append(s.TLS.Extensions, extension)
		}
	}
	if parameters.H2 != "" {
		parts := strings.Split(parameters.H2, "|")
		if len(parts) != 4 {
			return fail()
		}
		h := s.HTTP2
		h.Settings = []profile.Setting{}
		h.PriorityFrames = []profile.Priority{}
		if parts[0] != "" {
			settings := strings.Split(parts[0], ";")
			if len(settings) > 1024 {
				return fail()
			}
			for _, item := range settings {
				pair := strings.Split(item, ":")
				if len(pair) != 2 {
					return fail()
				}
				id, err := fingerprintNumber(pair[0], 16)
				if err != nil {
					return fail()
				}
				value, err := fingerprintNumber(pair[1], 32)
				if err != nil {
					return fail()
				}
				h.Settings = append(h.Settings, profile.Setting{ID: uint16(id), Value: uint32(value)})
			}
		}
		flow, err := fingerprintNumber(parts[1], 31)
		if err != nil {
			return fail()
		}
		h.ConnectionFlow = uint32(flow)
		if parts[2] != "0" {
			frames := strings.Split(parts[2], ",")
			if len(frames) > 1024 {
				return fail()
			}
			for _, frame := range frames {
				fields := strings.Split(frame, ":")
				if len(fields) != 4 {
					return fail()
				}
				numbers := [4]uint64{}
				for i, field := range fields {
					n, err := fingerprintNumber(field, 31)
					if err != nil {
						return fail()
					}
					numbers[i] = n
				}
				if numbers[1] > 1 || numbers[3] < 1 || numbers[3] > 256 {
					return fail()
				}
				h.PriorityFrames = append(h.PriorityFrames, profile.Priority{StreamID: uint32(numbers[0]), Exclusive: numbers[1] == 1, Dependency: uint32(numbers[2]), Weight: uint16(numbers[3])})
			}
		}
		names := map[string]string{"m": ":method", "a": ":authority", "s": ":scheme", "p": ":path"}
		order := strings.Split(parts[3], ",")
		if len(order) != 4 {
			return fail()
		}
		s.Headers.PseudoOrder = []string{}
		for _, short := range order {
			name, ok := names[short]
			if !ok {
				return fail()
			}
			delete(names, short)
			s.Headers.PseudoOrder = append(s.Headers.PseudoOrder, name)
		}
		s.HTTP2 = h
	}
	// The candidate has not inherited the base's observed validation.
	if s.Metadata.Kind == "browser" {
		s.Metadata.Variant = "custom"
		s.ID = strings.Join([]string{s.Metadata.Product, s.Metadata.ProductVersion, s.Metadata.Platform, "custom"}, "/")
		s.Metadata.ID = s.ID
	} else {
		s.Metadata.Variant = "custom"
		s.ID = strings.Join([]string{s.Metadata.Kind, s.Metadata.Product, s.Metadata.ProductVersion, s.Metadata.Platform, "custom"}, "/")
		s.Metadata.ID = s.ID
	}
	s.Evidence = nil
	s.Capabilities.Limitations = append(s.Capabilities.Limitations, "custom fingerprint parameters; omitted fields inherit base; browser equivalence unverified")
	if err := ValidateProfile(s); err != nil {
		return profile.Spec{}, err
	}
	return s, nil
}
