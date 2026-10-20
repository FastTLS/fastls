package ja4r

import (
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// Firefox158JA4R Firefox 158 JA4R（16 个扩展，无 compress_certificate/001b）
const Firefox158JA4R = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201"

// FirefoxJA4 使用 JA4R 指纹的 Firefox（默认最新 158）配置
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func FirefoxJA4(options *fastls.Options) {
	Firefox158JA4(options)
}

// Firefox158JA4 使用 JA4R 指纹的 Firefox 158 配置
func Firefox158JA4(options *fastls.Options) {
	imitate.Firefox158(options)

	options.Fingerprint = fastls.Ja4Fingerprint{
		FingerprintValue: Firefox158JA4R,
	}
}

// Firefox144JA4 使用 JA4R 指纹的 Firefox 144 配置（仅 UA 为 144）
func Firefox144JA4(options *fastls.Options) {
	FirefoxJA4(options)
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"
}

// Firefox147JA4 使用 JA4R 指纹的 Firefox 147 配置（仅 UA 为 147）
func Firefox147JA4(options *fastls.Options) {
	FirefoxJA4(options)
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0"
}

// Firefox151JA4 使用 JA4R 指纹的 Firefox 151 配置（仅 UA 为 151）
func Firefox151JA4(options *fastls.Options) {
	FirefoxJA4(options)
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0"
}
