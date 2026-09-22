package ja4r

import (
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// Chrome150JA4R Chromium 150 系共用的 JA4R（含 ML-DSA: 0904/0905/0906）
const Chrome150JA4R = "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"

// Chrome150JA4 使用 JA4R 指纹的 Chrome 150 配置（Chromium 系共享）
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func Chrome150JA4(options *fastls.Options) {
	imitate.Chrome150(options)

	options.Fingerprint = fastls.Ja4Fingerprint{
		FingerprintValue: Chrome150JA4R,
	}
}
