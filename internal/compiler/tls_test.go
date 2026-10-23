package compiler

import (
	"bytes"
	"errors"
	"testing"

	"github.com/FastTLS/fastls/profile"
	utls "github.com/refraction-networking/utls"
)

func fixture() profile.Spec {
	return profile.Spec{SchemaVersion: 1, ID: "library/compiler-fixture/1/any/default", Metadata: profile.Metadata{Kind: "library", Family: "fixture", Product: "compiler-fixture", ProductVersion: "1", Platform: "any", Variant: "default", Implementation: "utls", ImplementationVersion: "1.8.1"}, TLS: profile.TLSConfig{MinVersion: 0x0303, MaxVersion: 0x0304, CipherSuites: []profile.Code{0x1301, 0xc02b}, Extensions: []profile.Extension{{ID: 0}, {ID: 10, Groups: []profile.Code{29, 23}}, {ID: 13, SignatureAlgorithms: []profile.Code{0x0403, 0x0804}}, {ID: 43, Versions: []profile.Code{0x0304, 0x0303}}, {ID: 51, KeyShares: []profile.Code{29}}, {ID: 45, PSKModes: []uint8{1}}}}}
}
func TestFreshKeySharesPerHandshake(t *testing.T) {
	original := fixture()
	build := func() []byte {
		t.Helper()
		s, err := TLS(original)
		if err != nil {
			t.Fatal(err)
		}
		c := utls.UClient(nil, &utls.Config{ServerName: "localhost"}, utls.HelloCustom)
		if err = c.ApplyPreset(s); err != nil {
			t.Fatal(err)
		}
		if err = c.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		if len(c.HandshakeState.Hello.KeyShares) != 1 || len(c.HandshakeState.Hello.KeyShares[0].Data) == 0 {
			t.Fatal("missing generated key share")
		}
		return append([]byte{}, c.HandshakeState.Hello.KeyShares[0].Data...)
	}
	if bytes.Equal(build(), build()) {
		t.Fatal("handshakes reused ephemeral key material")
	}
	if original.TLS.Extensions[4].RawHex != nil {
		t.Fatal("execution mutated the input Spec")
	}
}
func TestUnsupportedParametersAreExplicit(t *testing.T) {
	cases := map[string]func(*profile.Spec){
		"feature":         func(s *profile.Spec) { s.Capabilities.RequiredFeatures = []string{"future.v99"} },
		"cipher":          func(s *profile.Spec) { s.TLS.CipherSuites = []profile.Code{0xffff} },
		"extension":       func(s *profile.Spec) { s.TLS.Extensions = append(s.TLS.Extensions, profile.Extension{ID: 12345}) },
		"signature":       func(s *profile.Spec) { s.TLS.Extensions[2].SignatureAlgorithms = []profile.Code{0x0904} },
		"record":          func(s *profile.Spec) { s.TLS.RecordVersion = 0x0303 },
		"wrong-parameter": func(s *profile.Spec) { s.TLS.Extensions[0].ALPN = []string{"h2"} },
		"resumption":      func(s *profile.Spec) { s.TLS.SessionPolicy = "resumption" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := fixture()
			change(&s)
			_, err := TLS(s)
			if !errors.Is(err, profile.ErrUnsupportedFeature) {
				t.Fatal(err)
			}
		})
	}
}
