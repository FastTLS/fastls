package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// ChromeHTTP2SettingsString（默认最新）使用 Chrome 150 的 HTTP/2 配置
var ChromeHTTP2SettingsString = Chrome150HTTP2SettingsString

// Chrome 默认使用最新 Chrome 150 指纹（Chromium 系共享 TLS）
func Chrome(options *fastls.Options) {
	Chrome150(options)
}
