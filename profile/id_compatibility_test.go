package profile

import "testing"

func TestCanonicalIDOrder(t *testing.T) {
	r, err := NewRegistry(catalog())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lookup("chrome/windows/156"); err == nil {
		t.Fatal("implicit old ID alias remains")
	}
	for _, id := range []string{"chrome/156/windows"} {
		s, err := r.Lookup(id)
		if err != nil || s.ID != "chrome/156/windows" {
			t.Fatalf("old ID alias: %s %v", s.ID, err)
		}

	}

}

func TestNonBrowserVersionBeforePlatform(t *testing.T) {
	for _, kind := range []string{"library", "client"} {
		s := fixture()
		s.Metadata.Kind = kind
		s.Metadata.Product = "fixture"
		s.Metadata.ProductVersion = "1.2"
		s.Metadata.Platform = "windows"
		s.Metadata.Variant = "default"
		s.Metadata.Implementation = "fixture"
		s.Metadata.ImplementationVersion = "1.2"
		s.ID = kind + "/fixture/1.2/windows/default"
		r, err := NewRegistry(Catalog{SchemaVersion: 1, Records: []Record{{ID: s.ID, Spec: &s}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{s.ID} {
			got, err := r.Lookup(id)
			if err != nil || got.ID != s.ID {
				t.Fatalf("%s: %v", id, err)
			}
		}
	}
}
