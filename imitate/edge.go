package imitate

import (
	fastls "github.com/FastTLS/fastls"
)

func Edge(options *fastls.Options) {
	Chrome142(options)

	options.Headers["Sec-Ch-Ua"] = `"Not(A:Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144"`
	options.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"
	if options.Headers["Accept"] == "" {
		options.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	}

}
