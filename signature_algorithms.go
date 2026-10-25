package fastls

import (
	"fmt"
	utls "github.com/refraction-networking/utls"
	"math/rand/v2"
)

// StringToSpecWithSignatureAlgorithms supplies the ordered signature declaration
// that JA3 cannot encode. It does not extend uTLS's cryptographic capabilities;
// an unimplemented algorithm selected by a server still fails the handshake.
func StringToSpecWithSignatureAlgorithms(fingerprint, userAgent string, algorithms []uint16) (*utls.ClientHelloSpec, error) {
	spec, err := StringToSpec(fingerprint, userAgent)
	if err != nil || algorithms == nil {
		return spec, err
	}
	if len(algorithms) == 0 || len(algorithms) > 4096 {
		return nil, fmt.Errorf("invalid signature algorithm list length")
	}
	values := make([]utls.SignatureScheme, len(algorithms))
	for i, value := range algorithms {
		if value == 0 {
			return nil, fmt.Errorf("zero signature algorithm")
		}
		if value&0x0f0f == 0x0a0a && byte(value) == byte(value>>8) {
			value = uint16(0x0a0a + 0x1010*rand.IntN(16))
		}
		values[i] = utls.SignatureScheme(value)
	}
	for _, ext := range spec.Extensions {
		if sig, ok := ext.(*utls.SignatureAlgorithmsExtension); ok {
			sig.SupportedSignatureAlgorithms = values
			return spec, nil
		}
	}
	return nil, fmt.Errorf("signature algorithm override requires extension 13")
}
