package integration

import (
	"errors"
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
	"github.com/FastTLS/fastls/profile"
	generators "github.com/FastTLS/imitate"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestUseEveryDeclaredRecipe(t *testing.T) {
	selections, err := generators.New().List()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range selections {
		t.Run(s, func(t *testing.T) {
			o := fastls.Options{Headers: map[string]string{"Sec-Ch-Ua": "caller", "Sec-Ch-Ua-Platform-Version": "99", "Accept": ""}}
			m, err := useGenerated(&o, s)
			if err != nil {
				t.Fatal(err)
			}
			if m.ProfileID != s || (o.Fingerprint == nil && o.Profile == nil) || o.Headers["Sec-Ch-Ua"] != "caller" || o.Headers["Accept"] != "" {
				t.Fatal(m, o.Headers)
			}
			if o.Fingerprint == nil {
				if err := fastls.ValidateProfile(*o.Profile); err != nil {
					t.Fatal(err)
				}
				return
			}
			if _, err = fastls.StringToSpec(o.Fingerprint.Value(), o.FingerprintUserAgent); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestHeadersAreOverridesNotSelectors(t *testing.T) {
	base := fastls.Options{}
	if _, err := useGenerated(&base, "chrome/156/windows"); err != nil {
		t.Fatal(err)
	}
	for _, ua := range []string{"arbitrary-agent", "Firefox/151.0", ""} {
		o := fastls.Options{Headers: map[string]string{"User-Agent": ua, "Sec-Ch-Ua": "arbitrary-hints", "Sec-Ch-Ua-Mobile": "?1", "Sec-Fetch-Mode": "cors", "Accept-Encoding": "identity"}}
		m, err := useGenerated(&o, "chrome/156/windows")
		if err != nil {
			t.Fatal(err)
		}
		if m.Product != "chrome" || m.ProfileID != "chrome/156/windows" || o.UserAgent != ua {
			t.Fatal(m)
		}
		if o.Profile == nil || base.Profile == nil || !reflect.DeepEqual(o.Profile.TLS, base.Profile.TLS) || !reflect.DeepEqual(o.Profile.HTTP2, base.Profile.HTTP2) || !slices.Equal(o.HeaderOrderKeys, base.HeaderOrderKeys) || o.FingerprintUserAgent != base.FingerprintUserAgent {
			t.Fatal("header override changed protocol")
		}
		if o.Headers["Sec-Ch-Ua"] != "arbitrary-hints" || o.Headers["Sec-Fetch-Mode"] != "cors" || o.Headers["Accept-Encoding"] != "identity" {
			t.Fatal(o.Headers)
		}
	}
}
func TestUseAtomicHeaderValidation(t *testing.T) {
	for _, headers := range []map[string]string{{"Bad Header": "x"}, {"X-Test": "bad\r\nvalue"}, {"User-Agent": "bad\x00ua"}} {
		o := fastls.Options{Headers: headers, Timeout: 17}
		before := o
		if _, err := useGenerated(&o, "chrome/156/windows"); err == nil || !reflect.DeepEqual(o, before) {
			t.Fatal("malformed request mutated options", err)
		}
	}
	o := fastls.Options{}
	if _, err := useGenerated(&o, "chrome/156/windows", imitate.WithPolicy(profile.RecordedOnly)); !errors.Is(err, profile.ErrUnknownProfile) {
		t.Fatal(err)
	}
	if _, err := useGenerated(&o, "chrome/156/windows", imitate.WithUserAgent("arbitrary-agent")); err != nil || o.UserAgent != "arbitrary-agent" {
		t.Fatal(err)
	}
}
func TestUseLoopbackHTTPS(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.UserAgent(); w.Write([]byte("local-ok")) }))
	defer server.Close()
	o := fastls.Options{Timeout: 5}
	m, err := useGenerated(&o, "chrome/156/windows")
	if err != nil {
		t.Fatal(err)
	}
	response, err := fastls.Init().Do(server.URL, o, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	defer response.Client.CloseIdleConnections()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.Status != 200 || string(body) != "local-ok" {
		t.Fatalf("local request: %d %s %v", response.Status, body, err)
	}
	if ua := <-seen; ua != m.UserAgent {
		t.Fatal("selected UA not used on wire")
	}
}

func TestUseLoopbackHTTP2(t *testing.T) {
	type observed struct {
		protocol int
		ua, body string
	}
	seen := make(chan observed, 3)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- observed{r.ProtoMajor, r.UserAgent(), string(body)}
		w.Write([]byte("h2-ok"))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	for _, selector := range []string{"chrome/156/windows", "firefox/158/windows", "chrome/160/windows/legacy-ja4r"} {
		t.Run(selector, func(t *testing.T) {
			o := fastls.Options{Timeout: 5, Body: "post-body"}
			m, err := useGenerated(&o, selector)
			if err != nil {
				t.Fatal(err)
			}
			response, err := fastls.Init().Do(server.URL, o, "POST")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			defer response.Client.CloseIdleConnections()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.Status != 200 || string(body) != "h2-ok" {
				t.Fatalf("local h2 request: %d %s %v", response.Status, body, err)
			}
			select {
			case got := <-seen:
				if got.protocol != 2 || got.ua != m.UserAgent || got.body != "post-body" {
					t.Fatalf("unexpected wire request: %+v", got)
				}
			case <-time.After(time.Second):
				t.Fatal("server observation missing")
			}
		})
	}
}

func useGenerated(o *fastls.Options, selector string, opts ...imitate.UseOption) (profile.Match, error) {
	return imitate.Use(o, selector, append([]imitate.UseOption{imitate.WithProvider(generators.New())}, opts...)...)
}
