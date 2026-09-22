package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// Chrome150JA3 Chrome / Chromium / Edge / Opera 共用的 TLS JA3（含 ML-DSA 签名算法对应的 ClientHello 形态）
// 扩展集合与 Chrome142 相同，顺序不同；JA4R 另含 0904/0905/0906
const Chrome150JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-11-0-17613-5-45-23-65037-16-27-13-10-18-35-51-43-41,4588-29-23-24,0"

// Chrome150HTTP2SettingsString 与现代 Chromium 一致（无 MAX_CONCURRENT_STREAMS，无 HeaderPriority）
var Chrome150HTTP2SettingsString = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

// Chrome150 使用 Chromium 150 系共享 TLS/HTTP2 指纹（默认最新 Chromium 系基线）
func Chrome150(options *fastls.Options) {
	options.Fingerprint = fastls.Ja3Fingerprint{
		FingerprintValue: Chrome150JA3,
	}
	options.HTTP2SettingsString = Chrome150HTTP2SettingsString
	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}

	options.Headers["Sec-Ch-Ua"] = `"Chromium";v="150", "Google Chrome";v="150", "Not_A Brand";v="99"`
	options.Headers["Sec-Ch-Ua-Mobile"] = "?0"
	options.Headers["Sec-Ch-Ua-Platform"] = `"Windows"`
	options.Headers["Sec-Fetch-Dest"] = "document"
	options.Headers["Sec-Fetch-Mode"] = "navigate"
	options.Headers["Sec-Fetch-Site"] = "none"
	options.Headers["Sec-Fetch-User"] = "?1"
	options.Headers["Upgrade-Insecure-Requests"] = "1"
	if options.Headers["Accept"] == "" {
		options.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	}

	options.HeaderOrderKeys = []string{
		"pragma",
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
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"accept-language",
		"cookie",
		"priority",
	}
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
}
