package ja4r

import (
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// ChromiumJA4 使用最新 Chromium 主版本头 + Chrome150 JA4R
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func ChromiumJA4(options *fastls.Options) {
	imitate.ChromiumVersion(options, imitate.ChromiumVersionDefault)
	options.Fingerprint = fastls.Ja4Fingerprint{
		FingerprintValue: Chrome150JA4R,
	}
}
