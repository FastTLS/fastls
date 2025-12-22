package ja4r

import (
	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// FirefoxJA4 使用 JA4R 指纹的 Firefox 配置
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func FirefoxJA4(options *fastls.Options) {
	// 使用 JA4R 指纹（从 https://tls.peet.ws/api/all 获取）
	// JA4R 格式：t13d<num>_<cipher_suites>_<extensions>_<signature_algorithms>
	options.Fingerprint = fastls.Ja4Fingerprint{
		FingerprintValue: "t13d1717h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
	}
	options.HTTP2Settings = imitate.FirefoxHttp2Setting
	options.PHeaderOrderKeys = []string{
		":method",
		":path",
		":authority",
		":scheme",
	}
	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}

	options.Headers["upgrade-insecure-requests"] = "1"
	options.Headers["Sec-Fetch-Dest"] = "document"
	options.Headers["Sec-Fetch-Mode"] = "navigate"
	options.Headers["Sec-Fetch-Site"] = "none"
	options.Headers["Sec-Fetch-User"] = "?1"
	options.Headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
	options.Headers["Priority"] = "u=0, i"
	options.Headers["te"] = "trailers"
	if options.Headers["Accept"] == "" {
		options.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	}
	if options.Headers["Accept-Language"] == "" {
		options.Headers["Accept-Language"] = "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
	}
	options.HeaderOrderKeys = []string{
		"host",
		"connection",
		"cache-control",
		"device-memory",
		"viewport-width",
		"rtt",
		"downlink",
		"ect",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-full-version",
		"sec-ch-ua-arch",
		"sec-ch-ua-platform",
		"sec-ch-ua-platform-version",
		"sec-ch-ua-model",
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
		"upgrade-insecure-requests",
		"sec-fetch-dest",
		"sec-fetch-mode",
		"sec-fetch-site",
		"sec-fetch-user",
		"cookie",
		"referer",
		"priority",
		"te",
	}
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"
}
