package profile

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func fixture() Spec {
	return Spec{SchemaVersion: 1, ID: "chrome/156/windows", Metadata: Metadata{Kind: "browser", Family: "chromium", Product: "chrome", ProductVersion: "156", Platform: "windows"},
		TLS:          TLSConfig{MinVersion: 0x0303, MaxVersion: 0x0304, CipherSuites: []Code{0x1302, 0x1301, 0xc02f}, Extensions: []Extension{{ID: 10, Groups: []Code{29, 23}}, {ID: 51, KeyShares: []Code{29}}, {ID: 43, Versions: []Code{0x0304, 0x0303}}, {ID: 16, ALPN: []string{"h2", "http/1.1"}}}},
		HTTP2:        HTTP2Config{Settings: []Setting{{ID: 4, Value: 131072}, {ID: 1, Value: 65536}}, HeaderPriority: &Priority{Weight: 42}},
		Headers:      HeaderConfig{Defaults: []Header{{Name: "Accept", Values: []string{"text/html", "application/custom"}}}, Order: []string{"user-agent", "accept"}, PseudoOrder: []string{":method", ":path", ":authority", ":scheme"}},
		Identity:     &Identity{UserAgent: "fixture", ClientHints: []Header{{Name: "Sec-CH-UA", Values: []string{"fixture"}}}},
		Capabilities: Capabilities{Protocols: []string{"tls", "http1", "http2"}, RequiredFeatures: []string{"ordered-settings"}, Limitations: []string{"configuration fixture only"}},
		Evidence:     []Evidence{{Source: "unit fixture, not a real-browser validation", VerifiedFields: []string{}}},
	}
}
func catalog() Catalog {
	s := fixture()
	return Catalog{SchemaVersion: 1, Records: []Record{{ID: s.ID, Spec: &s}}, Aliases: []Alias{{Name: "chrome156-win", Target: s.ID}}}
}

func TestCatalogStrictDecode(t *testing.T) {
	data, err := json.Marshal(catalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"duplicate", []byte(`{"schema_version":1,"schema_version":1}`)},
		{"nested-duplicate", []byte(`{"records":[{"id":"x","id":"y"}]}`)},
		{"unknown", []byte(`{"schema_version":1,"typo":true}`)},
		{"number-id", []byte(strings.Replace(string(data), `"0x1302"`, `4866`, 1))},
		{"overflow-id", []byte(strings.Replace(string(data), `"0x1302"`, `"0x11302"`, 1))},
		{"trailing", append(append([]byte{}, data...), []byte(` {}`)...)},
		{"depth", []byte(strings.Repeat("[", 70) + strings.Repeat("]", 70))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeCatalog(tc.data); !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("expected typed invalid error, got %v", err)
			}
		})
	}
	got, err := DecodeCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, catalog()) {
		t.Fatal("strict roundtrip lost ordering or nil/empty semantics")
	}
}

func TestRegistryOwnershipAndConcurrentLookups(t *testing.T) {
	input := catalog()
	r, err := NewRegistry(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Records[0].Spec.TLS.CipherSuites[0] = 999
	input.Records[0].Spec.Headers.Defaults[0].Values[0] = "changed"
	got, err := r.Lookup(" CHROME156-WIN ")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, fixture()) {
		t.Fatal("registry retained mutable input")
	}
	got.TLS.Extensions[0].Groups[0] = 999
	got.TLS.Extensions[3].ALPN[0] = "bad"
	got.Headers.Defaults[0].Values[0] = "bad"
	got.Identity.ClientHints[0].Values[0] = "bad"
	got.HTTP2.HeaderPriority.Weight = 1
	got.HTTP2.Settings[0].Value = 1
	again, _ := r.Lookup(got.ID)
	if !reflect.DeepEqual(again, fixture()) {
		t.Fatal("lookup leaked nested storage")
	}
	listed := r.List()
	if listed[0].ID != fixture().ID {
		t.Fatal("List omitted canonical ID")
	}
	listed[0].Product = "mutated"
	if r.List()[0].Product != "chrome" {
		t.Fatal("List leaked storage")
	}
	if _, err := r.Lookup("unknown"); !errors.Is(err, ErrUnknownProfile) {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 30 {
				s, e := r.Lookup("chrome156-win")
				if e != nil || s.TLS.CipherSuites[0] != 0x1302 {
					t.Error("concurrent lookup changed")
				}
				s.TLS.CipherSuites[0] = 1
			}
		}()
	}
	wg.Wait()
}

func TestSingleLayerOverridesPreservePresenceAndOrder(t *testing.T) {
	base := fixture()
	base.ID = "chromium-shared"
	base.Metadata.ID = base.ID
	meta := base.Metadata
	meta.ID = "chrome/157/windows"
	meta.ProductVersion = "157"
	max := Code(0x0304)
	empty := []Extension{}
	falseValue := false
	c := Catalog{SchemaVersion: 1, Baselines: []Spec{base}, Records: []Record{{ID: "chrome/157/windows", Baseline: base.ID, Patch: &Patch{Metadata: &meta, TLS: &TLSPatch{MaxVersion: &max, Extensions: &empty}, ClearIdentity: &falseValue, HTTP2: &HTTP2Config{ConnectionFlow: 0, Settings: []Setting{}}}}}}
	r, err := NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := r.Lookup("chrome/157/windows")
	if got.TLS.Extensions == nil || len(got.TLS.Extensions) != 0 || got.HTTP2.ConnectionFlow != 0 || got.Identity == nil {
		t.Fatal("presence semantics lost")
	}
	if !reflect.DeepEqual(got.TLS.CipherSuites, base.TLS.CipherSuites) {
		t.Fatal("inheritance changed suite order")
	}
	c.Records[0].Baseline = "another-record"
	if _, err := NewRegistry(c); !errors.Is(err, ErrInvalidProfile) {
		t.Fatal("accepted reference to a record or missing baseline")
	}
}

func TestRegistryRejectsInvalidReferences(t *testing.T) {
	for _, mutate := range []func(*Catalog){
		func(c *Catalog) { c.SchemaVersion = 2 },
		func(c *Catalog) { c.Records = append(c.Records, c.Records[0]) },
		func(c *Catalog) { c.Aliases = append(c.Aliases, c.Aliases[0]) },
		func(c *Catalog) { c.Aliases[0].Name = c.Records[0].ID },
		func(c *Catalog) { c.Aliases[0].Target = "missing" },
		func(c *Catalog) { c.Records[0].ID = "chrome/999/windows" },
	} {
		c := catalog()
		mutate(&c)
		if _, err := NewRegistry(c); !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("expected typed error, got %v", err)
		}
	}
}

func TestSemanticConstraintsAndNonBrowserIdentity(t *testing.T) {
	for _, mutate := range []func(*Spec){
		func(s *Spec) { s.TLS.MinVersion = 0x0301 },
		func(s *Spec) { s.TLS.CipherSuites = append(s.TLS.CipherSuites, s.TLS.CipherSuites[0]) },
		func(s *Spec) { s.TLS.Extensions = append(s.TLS.Extensions, s.TLS.Extensions[0]) },
		func(s *Spec) { s.TLS.Extensions[1].KeyShares = []Code{25} },
		func(s *Spec) { s.TLS.Extensions = append([]Extension{{ID: 41}}, s.TLS.Extensions...) },
		func(s *Spec) { s.TLS.Extensions[2].Versions = []Code{0x0301} },
		func(s *Spec) { s.HTTP2.Settings = append(s.HTTP2.Settings, s.HTTP2.Settings[0]) },
		func(s *Spec) { s.HTTP2.HeaderPriority.Weight = 257 },
		func(s *Spec) { s.Headers.Defaults[0].Values[0] = "bad\r\ninjected" },
		func(s *Spec) { s.Headers.Order = append(s.Headers.Order, "ACCEPT") },
		func(s *Spec) { s.Evidence[0].VerifiedFields = []string{"cipher_suites"} },
	} {
		s := fixture()
		mutate(&s)
		if err := Validate(s); !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("expected typed invalid profile, got %v", err)
		}
	}
	s := fixture()
	s.ID = "library/net-http/go1.26/windows/crypto-tls"
	s.Metadata = Metadata{Kind: "library", Family: "go", Product: "net-http", ProductVersion: "go1.26", Platform: "windows", Implementation: "crypto/tls", ImplementationVersion: "go1.26", Variant: "crypto-tls"}
	s.Identity = nil
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegistry(Catalog{SchemaVersion: 1, Records: []Record{{ID: s.ID, Spec: &s}}}); err != nil {
		t.Fatal(err)
	}
	s.ID = "library/net/http/go1.26/windows/crypto-tls"
	s.Metadata.Product = "net/http"
	if _, err := NewRegistry(Catalog{SchemaVersion: 1, Records: []Record{{ID: s.ID, Spec: &s}}}); !errors.Is(err, ErrInvalidProfile) {
		t.Fatal("accepted slash inside metadata identity component")
	}
}

func FuzzDecodeCatalog(f *testing.F) {
	b, _ := json.Marshal(catalog())
	f.Add(b)
	f.Add([]byte(`{"schema_version":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeCatalog(b)
		if err != nil {
			return
		}
		r, err := NewRegistry(c)
		if err != nil {
			return
		}
		for _, m := range r.List() {
			if m.Kind == "" {
				t.Fatal("accepted empty metadata")
			}
		}
	})
}
