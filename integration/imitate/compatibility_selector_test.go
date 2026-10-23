package integration

import (
	"errors"
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
	"github.com/FastTLS/fastls/profile"
	"reflect"
	"testing"
)

func TestV2RejectsBusinessCompatibilitySelectors(t *testing.T) {
	for _, id := range []string{"chrome156-win", "chrome", "chrome/windows/156", "chrome/156/windows/compat-v1", "chrome/windows/156/legacy-ua-first", "", "chrome/999/windows"} {
		o := fastls.Options{Headers: map[string]string{"User-Agent": "arbitrary-ua", "X-Test": "keep"}}
		before := o
		_, err := useGenerated(&o, id)
		if !errors.Is(err, profile.ErrUnknownProfile) || !reflect.DeepEqual(o, before) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	o := fastls.Options{}
	if _, err := useGenerated(&o, "chrome/156/windows", imitate.WithPolicy(profile.LegacyUAFirst)); !errors.Is(err, profile.ErrInvalidOptions) {
		t.Fatal(err)
	}
}
