package fastls

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAddressPolicyJSONStrictAndAtomic(t *testing.T) {
	client, err := NewClient().WithAddressPolicyJSON([]byte(`{"allow_hosts":["allowed.test"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		``, `null`, `[]`, `{"allow_hosts":null}`, `{"allow_hosts":["allowed.test"],"allow_hosts":[]}`,
		`{"allow_hosts":[],"\u0061llow_hosts":[]}`, `{"ALLOW_HOSTS":[]}`, `{"resolver":{}}`,
		`{"allow_ports":[0]}`, `{"allow_ports":[65536]}`, `{"allow_ports":[1.1]}`, `{"allow_ports":[-1]}`,
		`{"allow_hosts":["*.test"]}`, `{"allow_schemes":["ftp"]}`, `{"deny_cidrs":["bad"]}`,
		`{} {}`, "{\"allow_hosts\":[\"\x8e\"]}", strings.Repeat(" ", (1<<20)+1),
	} {
		copy, err := client.WithAddressPolicyJSON([]byte(input))
		if err == nil || copy.addressPolicy != client.addressPolicy {
			t.Fatalf("invalid configuration changed policy: %q %v", input[:min(50, len(input))], err)
		}
	}
	if _, err := NewClient().WithAddressPolicyJSON([]byte(`{"allow_schemes":[],"allow_hosts":[],"allow_ports":[],"allow_cidrs":[],"deny_cidrs":[]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestAddressPolicyClientPolicyCannotBeReplacedByRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer server.Close()
	original := NewClient()
	configured, err := original.WithAddressPolicyJSON([]byte(`{"deny_cidrs":["127.0.0.0/8"]}`))
	if err != nil {
		t.Fatal(err)
	}
	permissive := mustPolicy(t, AddressPolicyConfig{})
	for _, requestPolicy := range []*AddressPolicy{nil, permissive} {
		response, err := configured.DoContext(context.Background(), server.URL, Options{AddressPolicy: requestPolicy}, "GET")
		if response.Body != nil {
			response.Body.Close()
		}
		response.Client.CloseIdleConnections()
		requirePolicyReason(t, err, "cidr_denied")
		var classified interface{ AddressPolicyReason() string }
		if !errors.As(err, &classified) || classified.AddressPolicyReason() != "cidr_denied" {
			t.Fatal("capability error classification lost", err)
		}
	}
	response, err := original.DoContext(context.Background(), server.URL, Options{}, "GET")
	if body := policyReadResult(t, response, err); body != "ok" {
		t.Fatal("original client changed")
	}
}

func FuzzAddressPolicyJSON(f *testing.F) {
	for _, seed := range []string{`{}`, `null`, `{"allow_hosts":["example.test"]}`, `{"allow_hosts":[],"allow_hosts":null}`, `{"allow_ports":[443]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8192 {
			t.Skip()
		}
		client, err := NewClient().WithAddressPolicyJSON([]byte(input))
		if err == nil && (client.addressPolicy == nil || !client.addressPolicy.ready) {
			t.Fatal("accepted JSON without a ready policy")
		}
	})
}
