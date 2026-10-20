package imitate

import (
	"fmt"

	fastls "github.com/FastTLS/fastls"
)

// FirefoxVersion 按主版本号应用指纹。
//
//	151–157：TLS/HTTP2 使用 Firefox151，UA 为对应版本
//	158+：TLS/HTTP2 使用 Firefox158，UA 为对应版本（当前上限按调用方约束）
func FirefoxVersion(options *fastls.Options, major int) {
	if major >= 158 {
		Firefox158(options)
		if major != 158 {
			setFirefoxUA(options, major)
		}
		return
	}

	// 151–157：TLS 在 158 之前保持 151 形态
	Firefox151(options)
	if major != 151 {
		setFirefoxUA(options, major)
	}
}

func setFirefoxUA(options *fastls.Options, major int) {
	options.UserAgent = fmt.Sprintf(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%d.0) Gecko/20100101 Firefox/%d.0",
		major, major,
	)
}
