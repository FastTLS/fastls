package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// Firefox148 使用 Firefox 147 指纹（UA: rv:147.0）
// TLS/HTTP2 与 Firefox 144 保持一致，仅 UA 升级为 147
var Firefox148HTTP2SettingsString = "1:65536;2:0;4:131072;5:16384|12517377|0:42:false|m,p,a,s"

func Firefox148(options *fastls.Options) {
	options.Fingerprint = fastls.Ja3Fingerprint{
		FingerprintValue: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0",
	}
	options.HTTP2SettingsString = Firefox148HTTP2SettingsString

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
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"
}
