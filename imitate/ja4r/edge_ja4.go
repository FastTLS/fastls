package ja4r

import (
	fastls "github.com/ChengHoward/Fastls"
)

// EdgeJA4 使用 JA4R 指纹的 Edge 配置
//
// 注意：此功能是实验性的，API 可能会在未来的版本中发生变化。
// EXPERIMENTAL: This feature is experimental and the API may change in future versions.
func EdgeJA4(options *fastls.Options) {
	Chrome142JA4(options)

	options.Headers["Sec-Ch-Ua"] = `"Chromium";v="142", "Microsoft Edge";v="142", "Not_A Brand";v="99"`
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
	if options.Headers["Accept"] == "" {
		options.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	}
}
