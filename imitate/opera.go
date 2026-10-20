package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// Opera 使用 Chrome150 TLS，UA 保持 Opera 形态（Chromium 主版本跟随默认）
func Opera(options *fastls.Options) {
	ChromeVersion(options, ChromiumVersionDefault)

	options.Headers["Sec-Ch-Ua"] = GenerateSecChUa(ChromiumVersionDefault, "Opera")
	// Opera 的 Sec-CH-UA 品牌顺序与 Chrome 不同；上面用 Opera 作为第三品牌
	// 同时补充常见 Opera UA
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36 OPR/145.0.0.0"
}
