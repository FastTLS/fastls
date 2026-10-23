package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
	"github.com/FastTLS/fastls/profile"
	generators "github.com/FastTLS/imitate"
	"reflect"
	"strings"
	"testing"
)

type protocolObservation struct {
	Ciphers     []uint16
	Extensions  []uint16
	Signatures  string
	Settings    []string
	HeaderOrder []string
}

func normalizeGrease(code uint16) uint16 {
	if byte(code>>8) == byte(code) && code&0x0f0f == 0x0a0a {
		return 0x0a0a
	}
	return code
}
func inspectOverride(t *testing.T, es []event, ua string) protocolObservation {
	t.Helper()
	var got protocolObservation
	sawUA, sawHints := false, false
	for _, e := range es {
		switch e.Type {
		case "tls.client_hello":
			var h struct {
				CipherSuites []uint16 `json:"cipher_suites"`
				Extensions   []struct {
					ID      uint16
					Payload string `json:"payload_hex"`
				}
			}
			if err := json.Unmarshal(e.Data, &h); err != nil {
				t.Fatal(err)
			}
			for _, c := range h.CipherSuites {
				got.Ciphers = append(got.Ciphers, normalizeGrease(c))
			}
			for _, x := range h.Extensions {
				got.Extensions = append(got.Extensions, normalizeGrease(x.ID))
				if x.ID == 13 {
					got.Signatures = x.Payload
					if _, err := hex.DecodeString(x.Payload); err != nil {
						t.Fatal(err)
					}
				}
			}
		case "http2.settings", "http2.window_update", "http2.priority", "http2.header_priority":
			got.Settings = append(got.Settings, e.Type+":"+string(e.Data))
		case "http1.headers", "http2.headers":
			var h struct {
				Headers []struct{ Name, Value string }
			}
			if err := json.Unmarshal(e.Data, &h); err != nil {
				t.Fatal(err)
			}
			for _, f := range h.Headers {
				name := strings.ToLower(f.Name)
				got.HeaderOrder = append(got.HeaderOrder, name)
				if name == "user-agent" {
					sawUA = true
					if f.Value != ua {
						t.Fatalf("wire UA %q want %q", f.Value, ua)
					}
				}
				if name == "sec-ch-ua" {
					sawHints = true
					if f.Value != "caller-hints" {
						t.Fatal("caller Client Hints were regenerated", f.Value)
					}
				}
				if name == "sec-fetch-mode" && f.Value != "cors" {
					t.Fatal("caller header overwritten", f)
				}
			}
		}
	}
	if len(got.Ciphers) == 0 || len(got.HeaderOrder) == 0 || !sawUA || !sawHints {
		t.Fatalf("missing wire evidence: %+v", got)
	}
	return got
}
func TestHeaderOverridesPreserveSelectedProtocolOnWire(t *testing.T) {
	bundle, err := generators.New().Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	offline, err := imitate.Register(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		name     string
		provider profile.Provider
	}{{"generator", generators.New()}, {"offline", offline}} {
		for _, target := range []string{lab.HTTPS, lab.HTTPS2} {
			t.Run(p.name+target, func(t *testing.T) {
				var original protocolObservation
				for i, style := range []string{"before", "after-header", "after-field"} {
					ua := "custom-agent/" + style
					if style == "after-header" {
						ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0"
					}
					if style == "after-field" {
						ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
					}
					o := fastls.Options{FingerprintProvider: p.provider}
					if style == "before" {
						o.Headers = map[string]string{"User-Agent": ua, "Sec-Ch-Ua": "caller-hints", "Sec-Fetch-Mode": "cors"}
					}
					m, err := imitate.Use(&o, "chrome/156/windows")
					if err != nil {
						t.Fatal(err)
					}
					if style != "before" {
						o.Headers["Sec-Ch-Ua"] = "caller-hints"
						o.Headers["Sec-Fetch-Mode"] = "cors"
						if style == "after-header" {
							o.Headers["User-Agent"] = ua
						} else {
							o.UserAgent = ua
						}
					}
					if m.ProfileID != "chrome/156/windows" || m.Product != "chrome" {
						t.Fatal("UA selected a different fingerprint", m)
					}
					before := len(events(t))
					request(t, o, target)
					observed := inspectOverride(t, events(t)[before:], ua)
					if i == 0 {
						original = observed
					} else if !reflect.DeepEqual(original, observed) {
						t.Fatalf("header edit changed protocol or order:\n%+v\n%+v", original, observed)
					}
				}
			})
		}
	}
}
