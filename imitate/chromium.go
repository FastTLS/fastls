package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// ChromiumHTTP2SettingsString（默认最新）与 Chrome150 共用
var ChromiumHTTP2SettingsString = Chrome150HTTP2SettingsString

// Chromium 使用与 Chrome150 相同的 TLS/HTTP2，仅 UA / Sec-Ch-Ua 为 Chromium
func Chromium(options *fastls.Options) {
	Chrome150(options)

	options.Headers["Sec-Ch-Ua"] = `"Chromium";v="150", "Not_A Brand";v="99"`
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
}
