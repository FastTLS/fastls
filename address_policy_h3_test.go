package fastls

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
)

type policyH3Upload struct{ closes atomic.Int32 }

func (*policyH3Upload) Read([]byte) (int, error) { return 0, io.EOF }
func (b *policyH3Upload) Close() error           { b.closes.Add(1); return nil }

type policyCachedTransport struct{ calls atomic.Int32 }

func (s *policyCachedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	s.calls.Add(1)
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

// Exercise RoundTrip directly as well as the public setup tests. A cached
// transport must never bypass the policy, and rejected uploads close once.
func TestAddressPolicyH3RejectsBeforeCachedTransport(t *testing.T) {
	for _, selector := range []string{"explicit", "q-ja4r"} {
		for _, cached := range []bool{false, true} {
			t.Run(selector+map[bool]string{false: "/new", true: "/cached"}[cached], func(t *testing.T) {
				var queries atomic.Int32
				policy := mustPolicy(t, AddressPolicyConfig{Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					queries.Add(1)
					return nil, nil
				})})
				identity := browser{AddressPolicy: policy}
				if selector == "explicit" {
					identity.HTTPVersion = HTTPVersion3
				} else {
					identity.Fingerprint = Ja4Fingerprint{FingerprintValue: "q" + regressionJA4R[1:]}
				}
				rt := newRoundTripper(identity).(*roundTripper)
				spy := &policyCachedTransport{}
				if cached {
					rt.cachedTransports["https://allowed.test:443"] = spy
				}
				body := &policyH3Upload{}
				req, err := http.NewRequest("POST", "https://allowed.test/", body)
				if err != nil {
					t.Fatal(err)
				}
				response, err := rt.RoundTrip(req)
				requirePolicyReason(t, err, "http3_unsupported")
				if response != nil || queries.Load() != 0 || spy.calls.Load() != 0 || body.closes.Load() != 1 {
					t.Fatalf("response=%v DNS=%d dispatches=%d closes=%d", response, queries.Load(), spy.calls.Load(), body.closes.Load())
				}
				if !cached && len(rt.cachedTransports) != 0 {
					t.Fatal("rejected request created a transport")
				}
			})
		}
	}
}

func TestH3SchemeRejectionClosesUploadOnce(t *testing.T) {
	rt := newRoundTripper(browser{HTTPVersion: HTTPVersion3})
	body := &policyH3Upload{}
	req, err := http.NewRequest("POST", "http://allowed.test/", body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := rt.RoundTrip(req)
	if err == nil || response != nil || body.closes.Load() != 1 {
		t.Fatalf("response=%v error=%v closes=%d", response, err, body.closes.Load())
	}
}
