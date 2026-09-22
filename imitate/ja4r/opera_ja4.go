package ja4r

import (
	fastls "github.com/FastTLS/fastls"
)

// OperaJA4 使用与 Chrome150 相同的 JA4R，仅 UA / Sec-Ch-Ua 为 Opera
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func OperaJA4(options *fastls.Options) {
	Chrome150JA4(options)

	options.Headers["Sec-Ch-Ua"] = `"Not_A Brand";v="99", "Opera";v="135", "Chromium";v="150"`
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 OPR/135.0.0.0"
}
