package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

// Edge 默认使用最新 Edge 160（TLS 为 Chrome150 基线，UA/Sec-CH-UA 为 160）
func Edge(options *fastls.Options) {
	EdgeVersion(options, ChromiumVersionDefault)
}
