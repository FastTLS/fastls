package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestGoStdlibFingerprint 测试 Go 标准库 net/http 的默认 TLS 指纹
func TestGoStdlibFingerprint(t *testing.T) {
	// 使用 Go 标准库的 http.Client
	client := &http.Client{
		Timeout: 0, // 使用默认超时
	}

	// 发送请求到 tls.peet.ws 来检测 TLS 指纹
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("期望状态码 200, 得到 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}

	if len(body) == 0 {
		t.Error("响应体为空")
	}

	// 解析JSON响应
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("解析JSON失败: %v", err)
	}

	// 提取 TLS 信息
	tlsData, ok := result["tls"]
	if !ok {
		t.Error("响应中缺少 'tls' 字段")
		return
	}

	tlsMap, ok := tlsData.(map[string]interface{})
	if !ok {
		t.Error("'tls' 字段格式不正确")
		return
	}

	// 提取 JA3 指纹
	ja3, ok := tlsMap["ja3"]
	if !ok {
		t.Error("响应中缺少 'tls.ja3' 字段")
		return
	}

	ja3Str, ok := ja3.(string)
	if !ok {
		t.Errorf("'tls.ja3' 字段类型不正确，期望string，得到 %T", ja3)
		return
	}

	// 提取其他有用的 TLS 信息
	tlsVersion, _ := tlsMap["version"].(string)
	cipherSuite, _ := tlsMap["cipher"].(string)

	t.Logf("=== Go 标准库 net/http 的 TLS 指纹信息 ===")
	t.Logf("JA3 指纹: %s", ja3Str)
	if tlsVersion != "" {
		t.Logf("TLS 版本: %s", tlsVersion)
	}
	if cipherSuite != "" {
		t.Logf("加密套件: %s", cipherSuite)
	}

	// 打印完整的 TLS 信息（用于调试）
	t.Logf("完整 TLS 信息: %+v", tlsMap)
}
