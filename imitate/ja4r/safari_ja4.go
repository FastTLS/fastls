package ja4r

import (
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// SafariJA4 使用 JA4R 指纹的 Safari 配置
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func SafariJA4(options *fastls.Options) {
	// 使用 JA4R 指纹（从 https://tls.peet.ws/api/all 获取）
	// JA4R 格式：t13d<num>_<cipher_suites>_<extensions>_<signature_algorithms>
	options.Fingerprint = fastls.Ja4Fingerprint{
		FingerprintValue: "t13d2613h2_000a,002f,0035,003c,003d,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,002b,002d,0033,ff01_0403,0804,0401,0503,0805,0501,0806,0601",
	}
	options.HTTP2Settings = imitate.SafariHttp2Setting
	options.PHeaderOrderKeys = []string{
		":method",
		":scheme",
		":path",
		":authority",
	}
	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}

	if options.Headers["Accept"] == "" {
		options.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	}
	options.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"
}
