package profile

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestOfflineBundleStrictnessAndOwnership(t *testing.T) {
	s := fixture()
	r := Resolution{Spec: &s, Match: Match{ProfileID: s.ID, UserAgent: s.Identity.UserAgent, Method: "configured"}}
	b := Bundle{SchemaVersion: 1, ProviderID: "fixture", ProviderVersion: "1", DataRevision: "1", Records: []Resolution{r}, Aliases: []Alias{{Name: "alias", Target: s.ID}}}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Resolve(context.Background(), ResolveRequest{Selector: "alias"})
	if err != nil {
		t.Fatal(err)
	}
	got.Spec.TLS.CipherSuites[0] = 0xffff
	next, err := p.Resolve(context.Background(), ResolveRequest{Selector: s.ID})
	if err != nil || next.Spec.TLS.CipherSuites[0] == 0xffff {
		t.Fatal("bundle leaked storage")
	}
	ua := "different"
	if _, err = p.Resolve(context.Background(), ResolveRequest{Selector: s.ID, UserAgent: &ua}); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{append(data, []byte("{}")...), []byte(`{"schema_version":1,"schema_version":1}`), []byte(`{"schema_version":1,"unknown":true}`)} {
		if _, err = DecodeBundle(invalid); !errors.Is(err, ErrInvalidProfile) {
			t.Fatal(err)
		}
	}
	b.Records = append(b.Records, b.Records[0])
	data, _ = json.Marshal(b)
	if _, err = DecodeBundle(data); !errors.Is(err, ErrInvalidProfile) {
		t.Fatal("duplicate IDs accepted", err)
	}
}
