package ja4r

import (
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// ChromiumJA4 使用 JA4R 指纹的 Chromium 配置
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func ChromiumJA4(options *fastls.Options) {
	// 使用 JA4R 指纹（从 https://tls.peet.ws/api/all 获取）
	// JA4R 格式：t13d<num>_<cipher_suites>_<extensions>_<signature_algorithms>
	options.Fingerprint = fastls.Ja4Fingerprint{
		FingerprintValue: "t13d5911_002f,0032,0033,0035,0038,0039,003c,003d,0040,0067,006a,006b,009c,009d,009e,009f,00a2,00a3,00ff,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,c050,c051,c052,c053,c056,c057,c05c,c05d,c060,c061,c09c,c09d,c09e,c09f,c0a0,c0a1,c0a2,c0a3,c0ac,c0ad,c0ae,c0af,cca8,cca9,ccaa_000a,000b,000d,0016,0017,0023,0029,002b,002d,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602",
	}
	options.HTTP2Settings = imitate.ChromiumHttp2Setting
	options.PHeaderOrderKeys = []string{
		":method",
		":authority",
		":scheme",
		":path",
	}
	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}

	options.Headers["Sec-Ch-Ua"] = `"Chromium";v="115", "Not/A)Brand";v="99"`
	options.Headers["Sec-Ch-Ua-Mobile"] = "?0"
	options.Headers["Sec-Ch-Ua-Platform"] = `"Windows"`
	options.Headers["Sec-Fetch-Dest"] = "document"
	options.Headers["Sec-Fetch-Mode"] = "navigate"
	options.Headers["Sec-Fetch-Site"] = "none"
	options.Headers["Sec-Fetch-User"] = "?1"
	if options.Headers["Accept"] == "" {
		options.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	}

	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
