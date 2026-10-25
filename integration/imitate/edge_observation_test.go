package integration

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
	"github.com/FastTLS/fastls/profile"
	generators "github.com/FastTLS/imitate"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func observedTLS(t *testing.T, events []event) map[string]any {
	t.Helper()
	result := map[string]any{}
	for _, e := range events {
		if e.Type != "tls.client_hello" {
			continue
		}
		var h struct {
			Record     uint16   `json:"record_version"`
			Legacy     uint16   `json:"legacy_version"`
			Ciphers    []uint16 `json:"cipher_suites"`
			Extensions []struct {
				ID      uint16   `json:"id"`
				Payload string   `json:"payload_hex"`
				Keys    []uint16 `json:"key_share_groups"`
			} `json:"extensions"`
		}
		if err := json.Unmarshal(e.Data, &h); err != nil {
			t.Fatal(err)
		}
		result["record"] = h.Record
		result["legacy"] = h.Legacy
		for i := range h.Ciphers {
			h.Ciphers[i] = normalizeGrease(h.Ciphers[i])
		}
		result["ciphers"] = h.Ciphers
		ids := []uint16{}
		for _, ext := range h.Extensions {
			id := normalizeGrease(ext.ID)
			ids = append(ids, id)
			if id == 0x0a0a || id == 65037 {
				continue
			}
			b, err := hex.DecodeString(ext.Payload)
			if err != nil {
				t.Fatal(err)
			}
			switch id {
			case 10, 13:
				b = b[2:]
			case 43:
				b = b[1:]
			case 51:
				for i := range ext.Keys {
					ext.Keys[i] = normalizeGrease(ext.Keys[i])
				}
				result["key_share_groups"] = ext.Keys
				continue
			default:
				result["extension:"+string(rune(id))] = ext.Payload
				continue
			}
			codes := []uint16{}
			for i := 0; i < len(b); i += 2 {
				codes = append(codes, normalizeGrease(binary.BigEndian.Uint16(b[i:])))
			}
			result["extension:"+string(rune(id))] = codes
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		result["extension_membership"] = ids
		return result
	}
	t.Fatal("missing ClientHello evidence")
	return nil
}
func observedHeaders(t *testing.T, es []event) []struct{ Name, Value string } {
	t.Helper()
	for _, e := range es {
		if e.Type != "http1.headers" && e.Type != "http2.headers" {
			continue
		}
		var h struct {
			Headers []struct{ Name, Value string }
		}
		if err := json.Unmarshal(e.Data, &h); err != nil {
			t.Fatal(err)
		}
		for i := range h.Headers {
			switch strings.ToLower(h.Headers[i].Name) {
			case "host", ":authority":
				h.Headers[i].Value = "localhost:<test-port>"
			case ":path":
				h.Headers[i].Value = "/inspect"
			}
		}
		return h.Headers
	}
	t.Fatal("missing header evidence")
	return nil
}

func TestEdgeSpecsMatchIndependentBrowserObservations(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(workspace, "imitate/testdata/edge-windows-20261025.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Version, Scenario string
			Events            []event
		}
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	bundle, err := generators.New().Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	offline, err := imitate.Register(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		name string
		p    profile.Provider
	}{{"online", generators.New()}, {"offline", offline}} {
		for _, f := range fixture.Cases {
			if !strings.HasPrefix(f.Scenario, "tls13-") {
				continue
			}
			t.Run(p.name+"/"+f.Version+"/"+f.Scenario, func(t *testing.T) {
				selector := "edge/" + strings.Split(f.Version, ".")[0] + "/windows"
				o := fastls.Options{}
				if _, err := imitate.Use(&o, selector, imitate.WithProvider(p.p)); err != nil {
					t.Fatal(err)
				}
				before := len(events(t))
				target := lab.HTTPS
				if strings.HasSuffix(f.Scenario, "h2") {
					target = lab.HTTPS2
				}
				request(t, o, target)
				actual := events(t)[before:]
				if !reflect.DeepEqual(observedTLS(t, actual), observedTLS(t, f.Events)) {
					t.Fatal("TLS wire fields diverged from independent browser evidence")
				}
				if !reflect.DeepEqual(observedHeaders(t, actual), observedHeaders(t, f.Events)) {
					t.Fatal("navigation header values/order/case diverged from browser evidence")
				}
			})
		}
	}
}
