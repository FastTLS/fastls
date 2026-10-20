package ja4r

import (
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// ChromeJA4 默认使用最新 Chrome 160（TLS JA4R 为 Chrome150 基线，含 ML-DSA）
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func ChromeJA4(options *fastls.Options) {
	imitate.ChromeVersion(options, imitate.ChromiumVersionDefault)
	options.Fingerprint = fastls.Ja4Fingerprint{
		FingerprintValue: Chrome150JA4R,
	}
}
