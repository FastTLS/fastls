package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// SafariHTTP2SettingsString HTTP/2 设置字符串格式
// 格式: "2:0;3:100;4:2097152;9:1|10420225|0:256:false|m,s,a,p"
// 注意: m,s,a,p 会自动推导为 :method,:scheme,:authority,:path
// 设置 ID 9 是 NO_RFC7540_PRIORITIES (Safari 扩展设置)
var SafariHTTP2SettingsString = "2:0;3:100;4:2097152;9:1|10420225|0:256:false|m,s,a,p"

func Safari(options *fastls.Options) {
	options.Fingerprint = fastls.Ja3Fingerprint{
		FingerprintValue: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
	}
	options.HTTP2SettingsString = SafariHTTP2SettingsString

	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}

	if options.Headers["Accept"] == "" {
		options.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	}
	options.UserAgent = "Mozilla/5.0 (iPad; CPU OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.3 Mobile/15E148 Safari/604.1"
}
