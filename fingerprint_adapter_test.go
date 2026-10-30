package fastls

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/FastTLS/fastls/profile"
)

func adapterBase() profile.Spec {
	return profile.Spec{SchemaVersion: 1, ID: "library/fixture/1/any/default", Metadata: profile.Metadata{Kind: "library", Family: "fixture", Product: "fixture", ProductVersion: "1", Platform: "any", Variant: "default", Implementation: "utls", ImplementationVersion: "1.8.2"}, TLS: profile.TLSConfig{MinVersion: 771, MaxVersion: 772, CipherSuites: []profile.Code{4865, 4866}, Extensions: []profile.Extension{{ID: 0}, {ID: 10, Groups: []profile.Code{29, 23}}, {ID: 11, PointFormats: []uint8{0}}, {ID: 13, SignatureAlgorithms: []profile.Code{0x0403, 0x0804}}, {ID: 16, ALPN: []string{"h2", "http/1.1"}}, {ID: 43, Versions: []profile.Code{772, 771}}, {ID: 51, KeyShares: []profile.Code{29}}, {ID: 45, PSKModes: []uint8{1}}}}, Headers: profile.HeaderConfig{PseudoOrder: []string{":method", ":authority", ":scheme", ":path"}}}
}

const adapterJA3 = "771,4866-4865,0-10-11-13-16-43-51-45,29-23,0"
const adapterH2 = "2:0;4:131072;1:4096|100000|3:0:0:201|p,a,m,s"

func TestAdaptProfileIsolationAndWire(t *testing.T) {
	base := adapterBase()
	base.HTTP2.HeaderPriority = &profile.Priority{Weight: 42}
	base.HTTP2.FirstStreamID = 3
	base.HTTP2.StreamWindowIncrement = 12451840
	base.Capabilities.RequiredFeatures = []string{"http2.stream.v1"}
	before, _ := json.Marshal(base)
	got, err := AdaptProfile(base, FingerprintParameters{JA3: adapterJA3, H2: adapterH2})
	if err != nil {
		t.Fatal(err)
	}
	if got.TLS.CipherSuites[0] != 4866 || got.HTTP2.Settings[0].ID != 2 || got.HTTP2.ConnectionFlow != 100000 || got.HTTP2.PriorityFrames[0].Weight != 201 || got.Headers.PseudoOrder[0] != ":path" {
		t.Fatal("overlay lost ordered parameters")
	}
	if got.HTTP2.HeaderPriority == nil || got.HTTP2.HeaderPriority.Weight != 42 {
		t.Fatal("unencoded HEADERS priority lost")
	}
	if got.HTTP2.FirstStreamID != 3 || got.HTTP2.StreamWindowIncrement != 12451840 {
		t.Fatal("unencoded stream configuration lost")
	}
	config := ProfileHTTP2(got.HTTP2)
	if config.FirstStreamID != 3 || config.StreamWindowIncrement != 12451840 {
		t.Fatal("transport adaptation lost stream configuration")
	}
	preset, err := ProfileToSpec(got)
	if err != nil {
		t.Fatal(err)
	}
	payloads := helloPayloads(t, preset)
	if !reflect.DeepEqual(payloads[13], []byte{0, 4, 4, 3, 8, 4}) || !reflect.DeepEqual(payloads[10], []byte{0, 4, 0, 29, 0, 23}) {
		t.Fatalf("wire payloads: %v", payloads)
	}
	got.TLS.Extensions[1].Groups[0] = 23
	got.HTTP2.Settings[0].Value = 99
	after, _ := json.Marshal(base)
	if string(before) != string(after) {
		t.Fatal("base mutated")
	}
}

func TestAdaptProfileRejectsAmbiguityAndUnsupported(t *testing.T) {
	cases := []FingerprintParameters{{}, {JA3: "771,4865"}, {JA3: strings.Replace(adapterJA3, "4866-4865", "04866-4865", 1)}, {JA3: strings.Replace(adapterJA3, "4866-4865", "4866-4866", 1)}, {JA3: strings.Replace(adapterJA3, "0-10-11", "0-999-11", 1)}, {JA3: strings.Replace(adapterJA3, "29-23", "23", 1)}, {JA3: strings.Replace(adapterJA3, "0-10-11", "0-11", 1)}, {JA3: strings.Replace(adapterJA3, "4866-4865", "2570-4865", 1)}, {H2: "2:2|0|0|m,a,s,p"}, {H2: "2:0;2:0|0|0|m,a,s,p"}, {H2: "4:2147483648|0|0|m,a,s,p"}, {H2: "5:1|0|0|m,a,s,p"}, {H2: "|2147483648|0|m,a,s,p"}, {H2: "|0|3:0:3:1|m,a,s,p"}, {H2: "|0|3:0:0:257|m,a,s,p"}, {H2: "|0|0|m,m,s,p"}, {H2: strings.Repeat("x", 16385)}}
	for i, p := range cases {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			if _, err := AdaptProfile(adapterBase(), p); err == nil {
				t.Fatalf("accepted %#v", p)
			}
		})
	}
}
