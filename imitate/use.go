package imitate

import (
	"fmt"
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/profile"
	"net/textproto"
	"slices"
	"strings"
)

type useConfig struct {
	ua          string
	uaSet       bool
	defaults    profile.Defaults
	policy      profile.MatchPolicy
	provider    profile.Provider
	providerSet bool
}
type UseOption func(*useConfig)

// WithUserAgent overrides only the HTTP header; it never selects a protocol recipe.
func WithUserAgent(ua string) UseOption          { return func(c *useConfig) { c.ua = ua; c.uaSet = true } }
func WithDefaults(d profile.Defaults) UseOption  { return func(c *useConfig) { c.defaults = d } }
func WithPolicy(p profile.MatchPolicy) UseOption { return func(c *useConfig) { c.policy = p } }

func normalizeHeaders(o *fastls.Options, overrideUA bool) error {
	keys := make([]string, 0, len(o.Headers))
	for key := range o.Headers {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if key == "" || strings.IndexFunc(key, func(r rune) bool {
			return r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r))
		}) >= 0 {
			return fmt.Errorf("%w: invalid header name", profile.ErrInvalidOptions)
		}
		v := o.Headers[key]
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("%w: invalid header value", profile.ErrInvalidOptions)
		}
		canonical := textproto.CanonicalMIMEHeaderKey(key)
		if overrideUA && canonical == "User-Agent" {
			continue
		}
		if old, ok := result[canonical]; ok && old != v {
			return fmt.Errorf("%w: conflicting duplicate header %s", profile.ErrInvalidOptions, canonical)
		}
		result[canonical] = v
	}
	o.Headers = result
	return normalizeHeaderValues(o, overrideUA)
}
