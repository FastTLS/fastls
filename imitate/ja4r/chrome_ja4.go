package ja4r

import (
	fastls "github.com/FastTLS/fastls"
)

// ChromeJA4 默认使用最新 Chrome 150 JA4R（Chromium 系共享）
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func ChromeJA4(options *fastls.Options) {
	Chrome150JA4(options)
}
