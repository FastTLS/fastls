package fastls

import (
	"github.com/FastTLS/fastls/internal/compiler"
	"github.com/FastTLS/fastls/profile"
	utls "github.com/refraction-networking/utls"
)

// ProfileToSpec validates a complete profile and returns a fresh TLS preset for
// callers that already own a raw connection. It performs no network I/O and
// shares the compiler used by Session; it does not apply HTTP settings or headers.
func ProfileToSpec(spec profile.Spec) (*utls.ClientHelloSpec, error) {
	return compiler.TLS(profile.Clone(spec))
}
