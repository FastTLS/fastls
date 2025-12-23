package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

const chrome142Extension = "0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281"

// Chrome142HTTP2SettingsString HTTP/2 设置字符串格式
// 格式: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
// 注意: m,a,s,p 会自动推导为 :method,:authority,:scheme,:path
var Chrome142HTTP2SettingsString = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

func Chrome142(options *fastls.Options) {
	options.Fingerprint = fastls.Ja3Fingerprint{
		FingerprintValue: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-27-51-13-0-11-10-5-18-35-43-45-17613-23-65037-16-41,4588-29-23-24,0",
	}
	options.HTTP2SettingsString = Chrome142HTTP2SettingsString
	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}

	options.Headers["Sec-Ch-Ua"] = `"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"`
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
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

}
