package imitate

import (
	"fmt"
	"strings"

	fastls "github.com/FastTLS/fastls"
)

const (
	// ChromiumVersionMin/Max 为 chromeN / edgeN 版本号支持范围
	ChromiumVersionMin     = 150
	ChromiumVersionMax     = 160
	ChromiumVersionDefault = 160
)

var (
	secChUaGreaseChars    = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	secChUaGreaseVersions = []string{"8", "99", "24"}
	secChUaOrders3        = [][]int{
		{0, 1, 2},
		{0, 2, 1},
		{1, 0, 2},
		{1, 2, 0},
		{2, 0, 1},
		{2, 1, 0},
	}
	uaOS = map[string]string{
		"win":     "Windows NT 10.0; Win64; x64",
		"linux":   "X11; Linux x86_64",
		"mac":     "Macintosh; Intel Mac OS X 10_15_7",
		"android": "Linux; Android 10; SM-G973F",
	}
	secChUaPlatform = map[string]string{
		"win":     `"Windows"`,
		"linux":   `"Linux"`,
		"mac":     `"macOS"`,
		"android": `"Android"`,
	}
)

// GenerateSecChUa 按 Chromium 主版本 seed 确定性生成 Sec-CH-UA
// （对齐 cloudflare-bypass-core / Chromium user_agent_utils.cc）
// productBrand 为空时仅两项（裸 Chromium）；否则为三项（Chrome/Edge）
func GenerateSecChUa(seed int, productBrand string) string {
	greaseBrand := "Not" +
		secChUaGreaseChars[seed%11] +
		"A" +
		secChUaGreaseChars[(seed+1)%11] +
		"Brand"
	greaseVersion := secChUaGreaseVersions[seed%3]

	items := [][2]string{
		{greaseBrand, greaseVersion},
		{"Chromium", fmt.Sprintf("%d", seed)},
	}
	if productBrand != "" {
		items = append(items, [2]string{productBrand, fmt.Sprintf("%d", seed)})
	}

	n := len(items)
	var order []int
	if n == 2 {
		order = []int{seed % 2, (seed + 1) % 2}
	} else {
		order = secChUaOrders3[seed%6]
	}

	shuffled := make([][2]string, n)
	for i, dest := range order {
		shuffled[dest] = items[i]
	}

	parts := make([]string, n)
	for i, it := range shuffled {
		parts[i] = fmt.Sprintf(`"%s";v="%s"`, it[0], it[1])
	}
	return strings.Join(parts, ", ")
}

// GenerateChromiumUserAgent 生成 Chrome / Edge User-Agent
func GenerateChromiumUserAgent(kind string, seed int, platform string) string {
	if platform == "" {
		platform = "win"
	}
	osPart, ok := uaOS[platform]
	if !ok {
		osPart = uaOS["win"]
		platform = "win"
	}
	ua := fmt.Sprintf(
		"Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36",
		osPart, seed,
	)
	if kind == "edge" {
		token := "Edg"
		if platform == "android" {
			token = "EdgA"
		}
		ua = fmt.Sprintf("%s %s/%d.0.0.0", ua, token, seed)
	}
	return ua
}

func clampChromiumVersion(major int) int {
	if major < ChromiumVersionMin {
		return ChromiumVersionMin
	}
	if major > ChromiumVersionMax {
		return ChromiumVersionMax
	}
	return major
}

func applyChromiumClientHints(options *fastls.Options, kind string, major int, platform string) {
	if options.Headers == nil {
		options.Headers = make(map[string]string)
	}
	if platform == "" {
		platform = "win"
	}
	major = clampChromiumVersion(major)

	brand := "Google Chrome"
	if kind == "edge" {
		brand = "Microsoft Edge"
	} else if kind == "chromium" {
		brand = ""
	}

	options.Headers["Sec-Ch-Ua"] = GenerateSecChUa(major, brand)
	if platform == "android" {
		options.Headers["Sec-Ch-Ua-Mobile"] = "?1"
		options.Headers["Sec-Ch-Ua-Model"] = `"SM-G973F"`
	} else {
		options.Headers["Sec-Ch-Ua-Mobile"] = "?0"
	}
	if p, ok := secChUaPlatform[platform]; ok {
		options.Headers["Sec-Ch-Ua-Platform"] = p
	} else {
		options.Headers["Sec-Ch-Ua-Platform"] = `"Windows"`
	}

	uaKind := kind
	if uaKind == "chromium" {
		uaKind = "chrome"
	}
	options.UserAgent = GenerateChromiumUserAgent(uaKind, major, platform)
}

// ChromeVersion 使用 Chrome150 TLS/HTTP2 基线，并按主版本生成 UA / Sec-CH-UA（150–160）
func ChromeVersion(options *fastls.Options, major int) {
	Chrome150(options)
	applyChromiumClientHints(options, "chrome", major, "win")
}

// EdgeVersion 使用 Chrome150 TLS/HTTP2 基线，并按主版本生成 Edge UA / Sec-CH-UA（150–160）
func EdgeVersion(options *fastls.Options, major int) {
	Chrome150(options)
	applyChromiumClientHints(options, "edge", major, "win")
	if options.Headers["Accept"] == "" || strings.Contains(options.Headers["Accept"], "image/avif") {
		// Edge 常用 Accept（与历史 Edge 配置一致）
		options.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	}
}

// ChromiumVersion 裸 Chromium：TLS 同 Chrome150，Sec-CH-UA 仅两项
func ChromiumVersion(options *fastls.Options, major int) {
	Chrome150(options)
	applyChromiumClientHints(options, "chromium", major, "win")
}
