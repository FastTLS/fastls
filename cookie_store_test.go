package fastls

import (
	"context"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	http "github.com/FastTLS/fhttp"
)

func TestCookieStorePublicSuffixAndConcurrentClear(t *testing.T) {
	s := NewCookieStore()
	u, _ := url.Parse("https://foo.github.io/private/page")
	if err := s.SetCookie(u, &http.Cookie{Name: "bad", Value: "no", Domain: "github.io"}); err == nil {
		t.Fatal("public suffix accepted")
	}
	s.SetCookies(u, []*http.Cookie{{Name: "bad", Value: "no", Domain: "github.io", Path: "/"}, {Name: "host", Value: "yes", Path: "/"}})
	if got := s.Cookies(u); len(got) != 1 || got[0].Name != "host" {
		t.Fatalf("unexpected cookies: %v", got)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				s.SetCookies(u, []*http.Cookie{{Name: "same", Value: "yes", Path: "/"}})
				s.Cookies(u)
				s.Clear()
			}
		}()
	}
	wg.Wait()
	s.Clear()
	if len(s.Cookies(u)) != 0 {
		t.Fatal("clear retained cookies")
	}
	s.SetEnabled(false)
	s.SetCookies(u, []*http.Cookie{{Name: "disabled", Value: "no"}})
	if len(s.Cookies(u)) != 0 {
		t.Fatal("disabled store accepted cookies")
	}
	if err := s.SetCookie(u, &http.Cookie{Name: "disabled", Value: "no"}); err == nil {
		t.Fatal("explicit update accepted by disabled store")
	}
}

func TestSessionCookiesRedirectAndMultivalueHeaders(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "h1", true: "h2"}[h2], func(t *testing.T) {
			server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				if r.URL.Path == "/start" {
					w.Header().Add("Set-Cookie", "a=one; Path=/")
					w.Header().Add("Set-Cookie", "b=two; Path=/")
					stdhttp.Redirect(w, r, "/end", 302)
					return
				}
				w.Header().Add("X-Multi", "first, value")
				w.Header().Add("X-Multi", "second")
				io.WriteString(w, r.Header.Get("Cookie"))
			}))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			s, err := NewSession(Options{Fingerprint: Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			r, err := s.DoContext(context.Background(), server.URL+"/start", RequestOptions{}, "GET")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || !strings.Contains(string(body), "a=one") || !strings.Contains(string(body), "b=two") {
				t.Fatalf("body=%q error=%v", body, err)
			}
			if len(r.HeaderValues["X-Multi"]) != 2 || r.HeaderValues["X-Multi"][0] != "first, value" {
				t.Fatalf("headers=%v", r.HeaderValues)
			}
			r, err = s.DoContext(context.Background(), server.URL+"/end", RequestOptions{Headers: map[string]string{"Cookie": "manual=only"}}, "GET")
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || string(body) != "manual=only" {
				t.Fatalf("manual cookie body=%q error=%v", body, err)
			}
		})
	}
}
