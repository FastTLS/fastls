package imitate_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
	"github.com/FastTLS/fastls/profile"
)

type testProvider struct {
	resolve func(context.Context, profile.ResolveRequest) (profile.Resolution, error)
}

func (p *testProvider) Resolve(c context.Context, r profile.ResolveRequest) (profile.Resolution, error) {
	return p.resolve(c, r)
}
func sampleResolution() profile.Resolution {
	return profile.Resolution{Legacy: &profile.LegacyDefinition{Format: "ja3", Hello: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-11-0-17613-5-45-23-65037-16-27-13-10-18-35-51-43-41,4588-29-23-24,0", UserAgent: "fixture"}, Headers: profile.HeaderPolicy{Rules: []profile.HeaderRule{{Header: profile.Header{Name: "X-Test", Values: []string{"one", "two"}}, Mode: "replace"}}}, Match: profile.Match{ProfileID: "fixture", ProviderID: "test", ContractVersion: profile.ContractVersion}}
}
func TestProviderPriorityAndNoFallback(t *testing.T) {
	unknown := errors.New("provider missing")
	a := &testProvider{resolve: func(context.Context, profile.ResolveRequest) (profile.Resolution, error) {
		return profile.Resolution{}, unknown
	}}
	b := &testProvider{resolve: func(context.Context, profile.ResolveRequest) (profile.Resolution, error) {
		return sampleResolution(), nil
	}}
	o := fastls.Options{FingerprintProvider: a}
	if _, err := imitate.Use(&o, "chrome/155/windows"); !errors.Is(err, unknown) {
		t.Fatal(err)
	}
	if _, err := imitate.Use(&o, "anything", imitate.WithProvider(b)); err != nil {
		t.Fatal(err)
	}
	if o.Headers["X-Test"] != "one" || len(o.HeaderValues["X-Test"]) != 2 {
		t.Fatal("multivalue policy lost")
	}
}
func TestProviderErrorsAreAtomic(t *testing.T) {
	missing := fastls.Options{Headers: map[string]string{"X-Business": "keep"}, Timeout: 17}
	beforeMissing := missing
	if _, err := imitate.Use(&missing, "chrome/156/windows"); !errors.Is(err, profile.ErrInvalidOptions) || !reflect.DeepEqual(missing, beforeMissing) {
		t.Fatal("missing provider must fail without changing options", err)
	}
	var typedNil *testProvider
	for _, p := range []profile.Provider{nil, typedNil, &testProvider{resolve: func(context.Context, profile.ResolveRequest) (profile.Resolution, error) {
		return profile.Resolution{}, nil
	}}, &testProvider{resolve: func(context.Context, profile.ResolveRequest) (profile.Resolution, error) {
		r := sampleResolution()
		r.Match.ContractVersion = "999"
		return r, nil
	}}, &testProvider{resolve: func(context.Context, profile.ResolveRequest) (profile.Resolution, error) {
		r := sampleResolution()
		r.Headers.Rules[0].Values = []string{"bad\r\nvalue"}
		return r, nil
	}}} {
		o := fastls.Options{URL: "https://example.invalid", Headers: map[string]string{"X-Business": "keep"}, Timeout: 17}
		before := fastls.Options{URL: o.URL, Headers: map[string]string{"X-Business": "keep"}, Timeout: 17}
		if _, err := imitate.Use(&o, "chrome", imitate.WithProvider(p)); err == nil {
			t.Fatal("invalid provider accepted")
		}
		if !reflect.DeepEqual(o, before) {
			t.Fatal("failure changed options")
		}
	}
	o := fastls.Options{FingerprintProvider: typedNil}
	if _, err := imitate.Use(&o, "chrome"); err == nil {
		t.Fatal("typed nil options provider accepted")
	}
}
func TestProviderCancellationAndOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := fastls.Options{}
	if _, err := imitate.UseContext(ctx, &o, "chrome"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r := sampleResolution()
	p := &testProvider{resolve: func(context.Context, profile.ResolveRequest) (profile.Resolution, error) { return r, nil }}
	if _, err := imitate.Use(&o, "fixture", imitate.WithProvider(p)); err != nil {
		t.Fatal(err)
	}
	o.HeaderValues["X-Test"][0] = "mutated"
	if r.Headers.Rules[0].Values[0] != "one" {
		t.Fatal("borrowed provider storage")
	}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := fastls.Options{}
			if _, err := imitate.Use(&w, "fixture", imitate.WithProvider(p)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
