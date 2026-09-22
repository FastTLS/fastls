package ja4r

import (
	fastls "github.com/FastTLS/fastls"
)

// ChromiumJA4 使用与 Chrome150 相同的 JA4R，仅 UA / Sec-Ch-Ua 为 Chromium
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func ChromiumJA4(options *fastls.Options) {
	Chrome150JA4(options)

	options.Headers["Sec-Ch-Ua"] = `"Chromium";v="150", "Not_A Brand";v="99"`
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
}
