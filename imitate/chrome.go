package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// ChromeHTTP2SettingsString（默认最新）使用 Chrome150 的 HTTP/2 配置
var ChromeHTTP2SettingsString = Chrome150HTTP2SettingsString

// Chrome 默认使用最新 Chrome 160（TLS 为 Chrome150 基线，UA/Sec-CH-UA 为 160）
func Chrome(options *fastls.Options) {
	ChromeVersion(options, ChromiumVersionDefault)
}
