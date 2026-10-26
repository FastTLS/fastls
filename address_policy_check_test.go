package fastls

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
)

func TestAddressPolicyPreflightOriginAndFreshDial(t *testing.T) {
	answers := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	queries := 0
	p := mustPolicy(t, AddressPolicyConfig{AllowCIDRs: []string{"127.0.0.1/32"}, Resolver: policyResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { queries++; return answers, nil })})
	client := Fastls{addressPolicy: p}
	req, _ := http.NewRequest("GET", "https://EXAMPLE.test.:443/path", nil)
	if err := client.CheckAddressPolicy(context.Background(), req, "https://example.test"); err != nil {
		t.Fatal(err)
	}
	if queries != 1 {
		t.Fatal(queries)
	}
	for _, origin := range []string{"https://other.test", "https://example.test:444", "http://example.test:443"} {
		requirePolicyReason(t, client.CheckAddressPolicy(context.Background(), req, origin), "origin_mismatch")
	}
	if queries != 1 {
		t.Fatal("mismatched origin reached DNS")
	}
	answers = []netip.Addr{netip.MustParseAddr("127.0.0.2")}
	_, err := p.DialContext(context.Background(), "tcp", "example.test:443")
	requirePolicyReason(t, err, "cidr_not_allowed")
	if queries != 2 {
		t.Fatal("dial incorrectly reused a preflight DNS permission")
	}
	_, err = NewClient().WithAddressPolicyJSON([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddressPolicyPreflightDoesNotConnectAndHandlesInvalidInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("preflight sent a request")
		io.WriteString(w, "unexpected")
	}))
	defer server.Close()
	client, err := NewClient().WithAddressPolicyJSON([]byte(`{"allow_cidrs":["127.0.0.0/8"]}`))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", server.URL, nil)
	if err = client.CheckAddressPolicy(context.Background(), req, server.URL); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://user:secret@127.0.0.1", "http://127.0.0.1/path", "http://127.0.0.1?", "http://127.0.0.1#fragment", "ftp://127.0.0.1"} {
		requirePolicyReason(t, client.CheckAddressPolicy(context.Background(), req, origin), "invalid_origin")
	}
	requirePolicyReason(t, NewClient().CheckAddressPolicy(context.Background(), req, ""), "uninitialized_policy")
	if err = client.CheckAddressPolicy(nil, req, ""); err == nil {
		t.Fatal("nil context accepted")
	}
	requirePolicyReason(t, client.CheckAddressPolicy(context.Background(), nil, ""), "invalid_url")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = client.CheckAddressPolicy(ctx, req, ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzAddressPolicyOrigin(f *testing.F) {
	for _, seed := range []string{"http://127.0.0.1", "http://127.0.0.1:80/", "https://127.0.0.1:80", "http://user:secret@127.0.0.1", "http://127.0.0.1/path", "http://127.0.0.1?"} {
		f.Add(seed)
	}
	client, err := NewClient().WithAddressPolicyJSON([]byte(`{"allow_cidrs":["127.0.0.1/32"]}`))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, origin string) {
		if len(origin) > 8192 {
			t.Skip()
		}
		req, _ := http.NewRequest("GET", "http://127.0.0.1/", nil)
		err := client.CheckAddressPolicy(context.Background(), req, origin)
		if err == nil && origin != "" {
			u, parseErr := url.Parse(origin)
			if parseErr != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
				t.Fatal("invalid origin accepted", origin)
			}
			host, port, parseErr := policyAuthority(u.Scheme, u.Host)
			if parseErr != nil || host != "127.0.0.1" || port != 80 {
				t.Fatal("different origin accepted", origin)
			}
		}
	})
}
