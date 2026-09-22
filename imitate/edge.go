package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// Edge 使用与 Chrome150 相同的 TLS/HTTP2，仅 UA / Sec-Ch-Ua 为 Edge
func Edge(options *fastls.Options) {
	Chrome150(options)

	options.Headers["Sec-Ch-Ua"] = `"Not(A:Brand";v="8", "Chromium";v="150", "Microsoft Edge";v="150"`
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"
	if options.Headers["Accept"] == "" {
		options.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	}
}
