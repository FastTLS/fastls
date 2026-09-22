package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// Opera 使用与 Chrome150 相同的 TLS/HTTP2，仅 UA / Sec-Ch-Ua 为 Opera
func Opera(options *fastls.Options) {
	Chrome150(options)

	options.Headers["Sec-Ch-Ua"] = `"Not_A Brand";v="99", "Opera";v="135", "Chromium";v="150"`
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 OPR/135.0.0.0"
}
