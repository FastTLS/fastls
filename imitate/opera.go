package imitate

import (
	fastls "github.com/ChengHoward/Fastls"
)

func Opera(options *fastls.Options) {
	Chrome(options)

	options.Headers["Sec-Ch-Ua"] = `"Not/A)Brand";v="99", "Opera";v="101", "Chromium";v="115"`
	options.UserAgent = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
}
