package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	fastls "github.com/ChengHoward/Fastls"
	"github.com/ChengHoward/Fastls/imitate"
)

// APIResponse API 响应结构
type APIResponse struct {
	TLS struct {
		JA4R string `json:"ja4_r"`
	} `json:"tls"`
}

func main() {
	// 定义浏览器和对应的 imitate 函数
	browsers := map[string]func(*fastls.Options){
		"chrome142": imitate.Chrome142,
		"chrome120": imitate.Chrome120,
		"chrome":    imitate.Chrome,
		"firefox":   imitate.Firefox,
		"chromium":  imitate.Chromium,
		"safari":    imitate.Safari,
		"edge":      imitate.Edge,
		"opera":     imitate.Opera,
	}

	apiURL := "https://tls.peet.ws/api/all"
	client := fastls.NewClient()

	fmt.Fprintf(os.Stdout, "%s\n", "正在获取各浏览器的 JA4R 指纹...")
	fmt.Fprintf(os.Stdout, "%s\n", strings.Repeat("=", 60))
	fmt.Fprintf(os.Stdout, "API URL: %s\n", apiURL)
	fmt.Fprintf(os.Stdout, "浏览器数量: %d\n\n", len(browsers))

	results := make(map[string]string)

	for browser, imitateFunc := range browsers {
		fmt.Fprintf(os.Stdout, "\n[%s] 使用 imitate 配置\n", browser)
		fmt.Fprintf(os.Stdout, "  正在请求 API...\n")

		// 创建选项并使用 imitate 函数配置
		options := fastls.Options{
			Headers: make(map[string]string),
			Timeout: 30,
		}

		// 使用 imitate 函数配置（会自动设置 JA3 指纹和 User-Agent）
		imitateFunc(&options)

		// 显示使用的 JA3 指纹
		if options.Fingerprint != nil && !options.Fingerprint.IsEmpty() {
			ja3Preview := options.Fingerprint.Value()
			if len(ja3Preview) > 50 {
				ja3Preview = ja3Preview[:50] + "..."
			}
			fmt.Printf("  JA3: %s\n", ja3Preview)
			fmt.Printf("  User-Agent: %s\n", options.UserAgent)
		} else {
			fmt.Printf("  ⚠️  未设置指纹\n")
			continue
		}

		// 发送请求
		fmt.Printf("  正在发送请求...\n")
		resp, err := client.Do(apiURL, options, "GET")
		if err != nil {
			fmt.Printf("  ❌ 请求失败: %v\n", err)
			continue
		}
		defer resp.Body.Close()
		fmt.Printf("  响应状态码: %d\n", resp.Status)

		// 读取响应体
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ❌ 读取响应失败: %v\n", err)
			continue
		}

		// 解析 JSON
		var apiResp APIResponse
		if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
			fmt.Fprintf(os.Stderr, "  ❌ JSON 解析失败: %v\n", err)
			bodyStr := string(bodyBytes)
			if len(bodyStr) > 200 {
				bodyStr = bodyStr[:200]
			}
			fmt.Fprintf(os.Stderr, "  响应内容: %s\n", bodyStr)
			continue
		}

		// 提取 JA4R
		ja4r := apiResp.TLS.JA4R
		if ja4r == "" {
			fmt.Fprintf(os.Stderr, "  ⚠️  未找到 JA4R 字段\n")
			continue
		}

		results[browser] = ja4r
		fmt.Fprintf(os.Stdout, "  ✅ JA4R: %s\n", ja4r)
	}

	// 输出结果
	fmt.Fprintf(os.Stdout, "\n%s\n", strings.Repeat("=", 60))
	fmt.Fprintf(os.Stdout, "\n获取到的 JA4R 指纹:\n")
	fmt.Fprintf(os.Stdout, "%s\n", strings.Repeat("=", 60))

	for browser, ja4r := range results {
		fmt.Fprintf(os.Stdout, "\n[%s]\n", browser)
		fmt.Fprintf(os.Stdout, "  %s\n", ja4r)
	}

	// 生成更新代码
	fmt.Fprintf(os.Stdout, "\n%s\n", strings.Repeat("=", 60))
	fmt.Fprintf(os.Stdout, "\n生成的更新代码:\n")
	fmt.Fprintf(os.Stdout, "%s\n", strings.Repeat("=", 60))

	for browser, ja4r := range results {
		fmt.Fprintf(os.Stdout, "\n// %s\n", browser)
		fmt.Fprintf(os.Stdout, "options.Fingerprint = fastls.Ja4Fingerprint{\n")
		fmt.Fprintf(os.Stdout, "    FingerprintValue: %q,\n", ja4r)
		fmt.Fprintf(os.Stdout, "}\n")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
