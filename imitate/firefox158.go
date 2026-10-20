package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// Firefox158JA3 Firefox 158 TLS JA3
// 相对 151：移除扩展 27(compress_certificate)，曲线去掉 256/257(ffdhe)
const Firefox158JA3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-65037,4588-29-23-24-25,0"

// Firefox158HTTP2SettingsString Firefox 158 HTTP/2（HEADERS Priority: weight=42, streamDep=0, exclusive=false）
var Firefox158HTTP2SettingsString = "1:65536;2:0;4:131072;5:16384|12517377|0:42:false|m,p,a,s"

// FirefoxHTTP2SettingsString（默认最新）使用 Firefox 158
var FirefoxHTTP2SettingsString = Firefox158HTTP2SettingsString

// Firefox158 使用 Firefox 158 指纹
func Firefox158(options *fastls.Options) {
	options.Fingerprint = fastls.Ja3Fingerprint{
		FingerprintValue: Firefox158JA3,
	}
	options.HTTP2SettingsString = Firefox158HTTP2SettingsString
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
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0"
}

// Firefox 默认使用最新 Firefox 158 指纹
func Firefox(options *fastls.Options) {
	Firefox158(options)
}
