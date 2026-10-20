package ja4r

import (
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// EdgeJA4 默认使用最新 Edge 160（TLS JA4R 同 Chrome150 基线）
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func EdgeJA4(options *fastls.Options) {
	imitate.EdgeVersion(options, imitate.ChromiumVersionDefault)
	options.Fingerprint = fastls.Ja4Fingerprint{
		FingerprintValue: Chrome150JA4R,
	}
}
