package ja4r

import (
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// OperaJA4 使用 Chrome150 JA4R + Opera UA/Sec-CH-UA
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func OperaJA4(options *fastls.Options) {
	imitate.Opera(options)
	options.Fingerprint = fastls.Ja4Fingerprint{
		FingerprintValue: Chrome150JA4R,
	}
}
