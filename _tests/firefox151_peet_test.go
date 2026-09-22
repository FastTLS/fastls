package tests

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// TestFirefox151TLSpeet 使用 Firefox151 访问 tls.peet.ws 并记录指纹
func TestFirefox151TLSpeet(t *testing.T) {
	const apiURL = "https://tls.peet.ws/api/all"

	expectedJA3 := "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0"
	expectedH2 := "1:65536;2:0;4:131072;5:16384|12517377|0:42:false|m,p,a,s"

	options := fastls.Options{
		Timeout: 30,
		Headers: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	}
	imitate.Firefox151(&options)

	t.Logf("配置的 JA3: %s", options.Fingerprint.Value())
	t.Logf("配置的 H2:  %s", options.HTTP2SettingsString)
	t.Logf("User-Agent: %s", options.UserAgent)

	client := fastls.NewClient()
	resp, err := client.Do(apiURL, options, "GET")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.Status != 200 {
		t.Fatalf("期望状态码 200, 得到 %d", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}

	ce := resp.Headers["Content-Encoding"]
	if ce != "" {
		body = []byte(fastls.DecompressBody(body, []string{ce}, nil))
	}

	var result struct {
		HTTPVersion string `json:"http_version"`
		UserAgent   string `json:"user_agent"`
		TLS         struct {
			JA3  string `json:"ja3"`
			JA4  string `json:"ja4"`
			JA4R string `json:"ja4_r"`
		} `json:"tls"`
		HTTP2 struct {
			AkamaiFingerprint string `json:"akamai_fingerprint"`
		} `json:"http2"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("解析 JSON 失败: %v", err)
	}

	t.Logf("http_version: %s", result.HTTPVersion)
	t.Logf("检测 UA: %s", result.UserAgent)
	t.Logf("检测 JA3: %s", result.TLS.JA3)
	t.Logf("检测 JA4: %s", result.TLS.JA4)
	t.Logf("检测 JA4R: %s", result.TLS.JA4R)
	t.Logf("检测 H2 akamai_fingerprint: %s", result.HTTP2.AkamaiFingerprint)

	if result.TLS.JA3 != expectedJA3 {
		t.Errorf("JA3 不匹配\n  期望: %s\n  实际: %s", expectedJA3, result.TLS.JA3)
	}
	if result.HTTP2.AkamaiFingerprint != expectedH2 {
		t.Errorf("HTTP/2 akamai_fingerprint 不匹配\n  期望: %s\n  实际: %s", expectedH2, result.HTTP2.AkamaiFingerprint)
	}
	if !strings.Contains(result.UserAgent, "Firefox/151") {
		t.Errorf("User-Agent 未包含 Firefox/151: %s", result.UserAgent)
	}
}
