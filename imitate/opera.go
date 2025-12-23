package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

func Opera(options *fastls.Options) {
	Chrome(options)

	options.Headers["Sec-Ch-Ua"] = `"Not/A)Brand";v="99", "Opera";v="101", "Chromium";v="115"`
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/101.0.0.0"
}
