package tests

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
	"github.com/FastTLS/fastls/imitate/ja4r"
)

func testChromiumFamilyTLSpeet(t *testing.T, name string, setup func(*fastls.Options), uaSubstr string) {
	t.Helper()
	const apiURL = "https://tls.peet.ws/api/all"

	options := fastls.Options{
		Timeout: 30,
		Headers: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		},
	}
	setup(&options)

	t.Logf("[%s] 配置 JA3: %s", name, options.Fingerprint.Value())
	t.Logf("[%s] 配置 H2:  %s", name, options.HTTP2SettingsString)
	t.Logf("[%s] UA: %s", name, options.UserAgent)

	client := fastls.NewClient()
	resp, err := client.Do(apiURL, options, "GET")
	if err != nil {
		t.Fatalf("[%s] 请求失败: %v", name, err)
	}
	defer resp.Body.Close()

	if resp.Status != 200 {
		t.Fatalf("[%s] 期望状态码 200, 得到 %d", name, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("[%s] 读取响应失败: %v", name, err)
	}
	if ce := resp.Headers["Content-Encoding"]; ce != "" {
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
		t.Fatalf("[%s] 解析 JSON 失败: %v", name, err)
	}

	t.Logf("[%s] http_version: %s", name, result.HTTPVersion)
	t.Logf("[%s] 检测 UA: %s", name, result.UserAgent)
	t.Logf("[%s] 检测 JA3: %s", name, result.TLS.JA3)
	t.Logf("[%s] 检测 JA4: %s", name, result.TLS.JA4)
	t.Logf("[%s] 检测 JA4R: %s", name, result.TLS.JA4R)
	t.Logf("[%s] 检测 H2: %s", name, result.HTTP2.AkamaiFingerprint)

	if result.TLS.JA3 != imitate.Chrome150JA3 {
		t.Errorf("[%s] JA3 不匹配\n  期望: %s\n  实际: %s", name, imitate.Chrome150JA3, result.TLS.JA3)
	}
	if result.HTTP2.AkamaiFingerprint != imitate.Chrome150HTTP2SettingsString {
		t.Errorf("[%s] H2 不匹配\n  期望: %s\n  实际: %s", name, imitate.Chrome150HTTP2SettingsString, result.HTTP2.AkamaiFingerprint)
	}
	if !strings.Contains(result.UserAgent, uaSubstr) {
		t.Errorf("[%s] User-Agent 未包含 %q: %s", name, uaSubstr, result.UserAgent)
	}
}

func TestChrome150TLSpeet(t *testing.T) {
	testChromiumFamilyTLSpeet(t, "Chrome150", imitate.Chrome150, "Chrome/150")
}

func TestChromeTLSpeet(t *testing.T) {
	testChromiumFamilyTLSpeet(t, "Chrome", imitate.Chrome, "Chrome/150")
}

func TestChromiumTLSpeet(t *testing.T) {
	testChromiumFamilyTLSpeet(t, "Chromium", imitate.Chromium, "Chrome/150")
}

func TestEdgeTLSpeet(t *testing.T) {
	testChromiumFamilyTLSpeet(t, "Edge", imitate.Edge, "Edg/150")
}

func TestOperaTLSpeet(t *testing.T) {
	testChromiumFamilyTLSpeet(t, "Opera", imitate.Opera, "OPR/135")
}

func TestChrome150JA4TLSpeet(t *testing.T) {
	const apiURL = "https://tls.peet.ws/api/all"

	options := fastls.Options{
		Timeout: 30,
		Headers: make(map[string]string),
	}
	ja4r.Chrome150JA4(&options)

	t.Logf("配置 JA4R: %s", options.Fingerprint.Value())
	t.Logf("UA: %s", options.UserAgent)

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
	if ce := resp.Headers["Content-Encoding"]; ce != "" {
		body = []byte(fastls.DecompressBody(body, []string{ce}, nil))
	}

	var result struct {
		TLS struct {
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

	t.Logf("检测 JA3: %s", result.TLS.JA3)
	t.Logf("检测 JA4: %s", result.TLS.JA4)
	t.Logf("检测 JA4R: %s", result.TLS.JA4R)
	t.Logf("检测 H2: %s", result.HTTP2.AkamaiFingerprint)

	if result.TLS.JA4R == "" {
		t.Error("应返回 JA4R")
	}
	if !strings.Contains(result.TLS.JA4R, "0904") || !strings.Contains(result.TLS.JA4R, "0905") || !strings.Contains(result.TLS.JA4R, "0906") {
		t.Errorf("JA4R 应包含 ML-DSA 签名算法 0904/0905/0906，实际: %s", result.TLS.JA4R)
	}
	if result.HTTP2.AkamaiFingerprint != imitate.Chrome150HTTP2SettingsString {
		t.Errorf("H2 不匹配\n  期望: %s\n  实际: %s", imitate.Chrome150HTTP2SettingsString, result.HTTP2.AkamaiFingerprint)
	}
}
