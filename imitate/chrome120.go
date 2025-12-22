package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

const chrome120Extension = "0-5-10-11-13-16-18-21-23-27-35-43-45-51-17513-65037-65281"

var chrome120H2Settings = &fastls.H2Settings{
	Settings: map[string]int{
		"HEADER_TABLE_SIZE": 65536,
		"ENABLE_PUSH":       0,
		//"MAX_CONCURRENT_STREAMS": 1000, // 117 开始不设置
		"INITIAL_WINDOW_SIZE":  6291456,
		"MAX_HEADER_LIST_SIZE": 262144,
		//"MAX_FRAME_SIZE":         16384,
	},
	SettingsOrder: []string{
		"HEADER_TABLE_SIZE",
		"ENABLE_PUSH",
		//"MAX_CONCURRENT_STREAMS",
		"INITIAL_WINDOW_SIZE",
		"MAX_HEADER_LIST_SIZE",
	},
	ConnectionFlow: 15663105,
	HeaderPriority: map[string]interface{}{
		"weight":    256,
		"streamDep": 0,
		"exclusive": true,
	},
	PriorityFrames: []map[string]interface{}{
		/*{
			"streamID": 0,
			"priorityParam": map[string]interface{}{
				"weight":    0,
				"streamDep": 0,
				"exclusive": true,
			},
		},*/
	},
}
var Chrome120Http2Setting = fastls.ToHTTP2Settings(chrome120H2Settings)

func Chrome120(options *fastls.Options) {
	options.Fingerprint = fastls.Ja3Fingerprint{
		FingerprintValue: "771,4865-4866-4867-49195-49199-49196-49120-52393-52392-49171-49172-156-157-47-53" + "," + shuffleExtension(chrome120Extension, 7) + "-41,29-23-24,0",
	}
	options.HTTP2Settings = Chrome120Http2Setting
	options.PHeaderOrderKeys = []string{
		":method",
		":authority",
		":scheme",
		":path",
	}
	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}

	options.Headers["Sec-Ch-Ua"] = `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`
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
		"accept-encoding",
		"accept-language",
		"cookie",
		"referer",
	}
	//options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
	//options.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

}
