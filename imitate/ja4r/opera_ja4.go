package ja4r

import (
	fastls "github.com/ChengHoward/Fastls"
)

// OperaJA4 使用 JA4R 指纹的 Opera 配置
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func OperaJA4(options *fastls.Options) {
	ChromeJA4(options)

	options.Headers["Sec-Ch-Ua"] = `"Not/A)Brand";v="99", "Opera";v="101", "Chromium";v="115"`
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/101.0.0.0"
}
