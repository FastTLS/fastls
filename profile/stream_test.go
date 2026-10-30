package profile

import (
	"encoding/json"
	"testing"
)

func TestStreamConfigurationContract(t *testing.T) {
	s := fixture()
	s.HTTP2.FirstStreamID = 3
	s.HTTP2.StreamWindowIncrement = 12451840
	if Validate(s) == nil {
		t.Fatal("missing capability accepted")
	}
	s.Capabilities.RequiredFeatures = append(s.Capabilities.RequiredFeatures, "http2.stream.v1")
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(Catalog{SchemaVersion: 1, Records: []Record{{ID: s.ID, Spec: &s}}})
	c, err := DecodeCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(c)
	if err != nil {
		t.Fatal(err)
	}
	_ = r
	if c.Records[0].Spec.HTTP2.FirstStreamID != 3 || c.Records[0].Spec.HTTP2.StreamWindowIncrement != 12451840 {
		t.Fatal("roundtrip lost fields")
	}
	clone := Clone(s)
	clone.HTTP2.FirstStreamID = 5
	if s.HTTP2.FirstStreamID != 3 {
		t.Fatal("clone mutated original")
	}
	for _, id := range []uint32{2, 0x80000001} {
		bad := Clone(s)
		bad.HTTP2.FirstStreamID = id
		if Validate(bad) == nil {
			t.Fatal("accepted invalid stream", id)
		}
	}
	bad := Clone(s)
	bad.HTTP2.StreamWindowIncrement = 0x7fffffff
	if Validate(bad) == nil {
		t.Fatal("accepted window overflow")
	}
}
