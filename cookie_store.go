package fastls

import (
	"errors"
	"net"
	stdhttp "net/http"
	"net/url"
	"strings"
	"sync"

	http "github.com/FastTLS/fhttp"
	"github.com/FastTLS/fhttp/cookiejar"
	"golang.org/x/net/publicsuffix"
)

// CookieStore is a concurrency-safe, in-memory RFC 6265 jar with public suffix checks.
// Clear and SetEnabled take effect across every transport using the same store.
type CookieStore struct {
	mu      sync.RWMutex
	jar     *cookiejar.Jar
	enabled bool
}

func NewCookieStore() *CookieStore {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return &CookieStore{jar: jar, enabled: true}
}

func (s *CookieStore) Cookies(u *url.URL) []*http.Cookie {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.enabled {
		return nil
	}
	return s.jar.Cookies(u)
}

func (s *CookieStore) SetCookies(u *url.URL, cookies []*http.Cookie) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.enabled {
		s.jar.SetCookies(u, cookies)
	}
}

func (s *CookieStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
}

func (s *CookieStore) SetEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = enabled
	if !enabled {
		s.jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	}
}

// SetCookie validates an explicit caller-provided cookie before storing it.
// Automatic Set-Cookie handling follows cookiejar's RFC 6265 acceptance rules.
func (s *CookieStore) SetCookie(u *url.URL, c *http.Cookie) error {
	if u == nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return errors.New("cookie URL must be absolute HTTP(S) without credentials")
	}
	if len(c.Name)+len(c.Value)+len(c.Domain)+len(c.Path) > 4096 {
		return errors.New("cookie exceeds 4096 bytes")
	}
	if c.MaxAge > 2147483647 {
		return errors.New("max_age must not exceed 2147483647 seconds")
	}
	check := &stdhttp.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain, Expires: c.Expires}
	if err := check.Valid(); err != nil {
		return err
	}
	if c.Domain != "" {
		domain := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if domain != host {
			if net.ParseIP(host) != nil || !strings.HasSuffix(host, "."+domain) {
				return errors.New("cookie domain does not match URL")
			}
			if suffix, _ := publicsuffix.PublicSuffix(domain); suffix == domain {
				return errors.New("cookie domain is a public suffix")
			}
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.enabled {
		return errors.New("cookie store is disabled")
	}
	s.jar.SetCookies(u, []*http.Cookie{c})
	return nil
}

// An explicit Cookie header controls outgoing cookies for this request chain;
// responses still update the shared store, including redirect responses.
type outgoingCookieOverride struct{ http.CookieJar }

func (outgoingCookieOverride) Cookies(*url.URL) []*http.Cookie { return nil }
