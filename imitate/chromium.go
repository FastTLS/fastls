package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// ChromiumHTTP2SettingsString（默认最新）与 Chrome150 共用
var ChromiumHTTP2SettingsString = Chrome150HTTP2SettingsString

// Chromium 使用 Chrome150 TLS，UA/Sec-CH-UA 为最新主版本（裸 Chromium）
func Chromium(options *fastls.Options) {
	ChromiumVersion(options, ChromiumVersionDefault)
}
