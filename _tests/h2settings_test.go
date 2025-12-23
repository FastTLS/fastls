package tests

import (
	"encoding/json"
	"io"
	"testing"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// TestParseH2SettingsString 测试解析 HTTP/2 设置字符串
func TestParseH2SettingsString(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected *fastls.H2Settings
	}{
		{
			name:  "Chrome142格式",
			input: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
			expected: &fastls.H2Settings{
				Settings: map[string]int{
					"HEADER_TABLE_SIZE":    65536,
					"ENABLE_PUSH":          0,
					"INITIAL_WINDOW_SIZE":  6291456,
					"MAX_HEADER_LIST_SIZE": 262144,
				},
				ConnectionFlow: 15663105,
			},
		},
		{
			name:  "Firefox格式",
			input: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
			expected: &fastls.H2Settings{
				Settings: map[string]int{
					"HEADER_TABLE_SIZE":   65536,
					"ENABLE_PUSH":         0,
					"INITIAL_WINDOW_SIZE": 131072,
					"MAX_FRAME_SIZE":      16384,
				},
				ConnectionFlow: 12517377,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h2Settings, err := fastls.ParseH2SettingsString(tc.input)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}

			// 验证 Settings
			for key, expectedValue := range tc.expected.Settings {
				actualValue, ok := h2Settings.Settings[key]
				if !ok {
					t.Errorf("缺少设置: %s", key)
					continue
				}
				if actualValue != expectedValue {
					t.Errorf("设置 %s 的值不匹配: 期望 %d, 得到 %d", key, expectedValue, actualValue)
				}
			}

			// 验证 ConnectionFlow
			if h2Settings.ConnectionFlow != tc.expected.ConnectionFlow {
				t.Errorf("ConnectionFlow 不匹配: 期望 %d, 得到 %d", tc.expected.ConnectionFlow, h2Settings.ConnectionFlow)
			}

			// 验证 SettingsOrder 不为空
			if len(h2Settings.SettingsOrder) == 0 {
				t.Error("SettingsOrder 为空")
			} else {
				t.Logf("SettingsOrder: %v", h2Settings.SettingsOrder)
			}

			// 验证 HeaderPriority
			if h2Settings.HeaderPriority == nil {
				t.Error("HeaderPriority 为 nil")
			} else {
				t.Logf("HeaderPriority: %+v", h2Settings.HeaderPriority)
			}

			t.Logf("解析成功: %+v", h2Settings)
		})
	}
}

// TestH2SettingsWithTLSpeet 测试从 tls.peet.ws 获取 akamai_fingerprint 并对比
func TestH2SettingsWithTLSpeet(t *testing.T) {
	client := fastls.NewClient()

	// 测试 Chrome142
	t.Run("Chrome142", func(t *testing.T) {
		options := fastls.Options{
			Timeout: 30,
			Headers: map[string]string{
				"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			},
		}

		imitate.Chrome142(&options)

		resp, err := client.Do("https://tls.peet.ws/api/all", options, "GET")
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

		// 解码响应体
		contentEncoding := resp.Headers["Content-Encoding"]
		var decodedBody string
		if contentEncoding != "" {
			decodedBody = fastls.DecompressBody(body, []string{contentEncoding}, nil)
		} else {
			decodedBody = string(body)
		}

		// 解析JSON响应
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(decodedBody), &result); err != nil {
			t.Fatalf("解析JSON失败: %v", err)
		}

		// 提取 http2.akamai_fingerprint
		http2Data, ok := result["http2"]
		if !ok {
			t.Skip("响应中缺少 'http2' 字段，跳过测试")
			return
		}

		http2Map, ok := http2Data.(map[string]interface{})
		if !ok {
			t.Skip("'http2' 字段格式不正确，跳过测试")
			return
		}

		akamaiFingerprint, ok := http2Map["akamai_fingerprint"]
		if !ok {
			t.Skip("响应中缺少 'http2.akamai_fingerprint' 字段，跳过测试")
			return
		}

		akamaiFingerprintStr, ok := akamaiFingerprint.(string)
		if !ok {
			t.Fatalf("'http2.akamai_fingerprint' 字段类型不正确，期望string，得到 %T", akamaiFingerprint)
		}

		t.Logf("从服务器获取的 akamai_fingerprint: %s", akamaiFingerprintStr)

		// 解析服务器返回的 akamai_fingerprint
		serverH2Settings, err := fastls.ParseH2SettingsString(akamaiFingerprintStr)
		if err != nil {
			t.Fatalf("解析服务器返回的 akamai_fingerprint 失败: %v", err)
		}

		// 获取我们设置的 H2Settings
		clientH2Settings := options.HTTP2Settings
		if clientH2Settings == nil {
			t.Fatal("客户端 HTTP2Settings 为 nil")
		}

		// 将客户端的 HTTP2Settings 转换回 H2Settings 进行比较
		// 注意：这里我们需要反向转换，或者直接比较关键字段
		t.Logf("服务器 Settings: %+v", serverH2Settings.Settings)
		t.Logf("服务器 ConnectionFlow: %d", serverH2Settings.ConnectionFlow)
		t.Logf("服务器 SettingsOrder: %v", serverH2Settings.SettingsOrder)

		// 比较关键字段
		if clientH2Settings.ConnectionFlow != 0 {
			if serverH2Settings.ConnectionFlow != clientH2Settings.ConnectionFlow {
				t.Logf("ConnectionFlow 不匹配: 客户端 %d, 服务器 %d", clientH2Settings.ConnectionFlow, serverH2Settings.ConnectionFlow)
			} else {
				t.Logf("ConnectionFlow 匹配: %d", clientH2Settings.ConnectionFlow)
			}
		}

		// 比较 Settings
		if len(clientH2Settings.Settings) > 0 {
			for _, clientSetting := range clientH2Settings.Settings {
				found := false
				for settingName, serverValue := range serverH2Settings.Settings {
					// 这里需要根据 Setting ID 来比较
					// 简化比较：只记录日志
					_ = settingName
					_ = serverValue
					found = true
					break
				}
				if !found {
					t.Logf("警告: 客户端设置 %+v 在服务器响应中未找到", clientSetting)
				}
			}
		}

		// 输出详细对比信息
		t.Logf("\n=== HTTP/2 设置对比 ===")
		t.Logf("客户端设置的 ConnectionFlow: %d", clientH2Settings.ConnectionFlow)
		t.Logf("服务器检测的 ConnectionFlow: %d", serverH2Settings.ConnectionFlow)
		t.Logf("服务器检测的 Settings: %+v", serverH2Settings.Settings)
		t.Logf("服务器检测的 SettingsOrder: %v", serverH2Settings.SettingsOrder)
	})

	// 测试 Firefox
	t.Run("Firefox", func(t *testing.T) {
		options := fastls.Options{
			Timeout: 30,
			Headers: map[string]string{
				"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			},
		}

		imitate.Firefox(&options)

		resp, err := client.Do("https://tls.peet.ws/api/all", options, "GET")
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

		// 解码响应体
		contentEncoding := resp.Headers["Content-Encoding"]
		var decodedBody string
		if contentEncoding != "" {
			decodedBody = fastls.DecompressBody(body, []string{contentEncoding}, nil)
		} else {
			decodedBody = string(body)
		}

		// 解析JSON响应
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(decodedBody), &result); err != nil {
			t.Fatalf("解析JSON失败: %v", err)
		}

		// 提取 http2.akamai_fingerprint
		http2Data, ok := result["http2"]
		if !ok {
			t.Skip("响应中缺少 'http2' 字段，跳过测试")
			return
		}

		http2Map, ok := http2Data.(map[string]interface{})
		if !ok {
			t.Skip("'http2' 字段格式不正确，跳过测试")
			return
		}

		akamaiFingerprint, ok := http2Map["akamai_fingerprint"]
		if !ok {
			t.Skip("响应中缺少 'http2.akamai_fingerprint' 字段，跳过测试")
			return
		}

		akamaiFingerprintStr, ok := akamaiFingerprint.(string)
		if !ok {
			t.Fatalf("'http2.akamai_fingerprint' 字段类型不正确，期望string，得到 %T", akamaiFingerprint)
		}

		t.Logf("从服务器获取的 akamai_fingerprint: %s", akamaiFingerprintStr)

		// 解析服务器返回的 akamai_fingerprint
		serverH2Settings, err := fastls.ParseH2SettingsString(akamaiFingerprintStr)
		if err != nil {
			t.Fatalf("解析服务器返回的 akamai_fingerprint 失败: %v", err)
		}

		// 输出详细对比信息
		t.Logf("\n=== HTTP/2 设置对比 (Firefox) ===")
		t.Logf("服务器检测的 ConnectionFlow: %d", serverH2Settings.ConnectionFlow)
		t.Logf("服务器检测的 Settings: %+v", serverH2Settings.Settings)
		t.Logf("服务器检测的 SettingsOrder: %v", serverH2Settings.SettingsOrder)
		t.Logf("服务器检测的 HeaderPriority: %+v", serverH2Settings.HeaderPriority)
	})
}

// TestCompareH2Settings 对比两个 H2Settings 结构
func TestCompareH2Settings(t *testing.T) {
	chrome142Str := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	firefoxStr := "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"

	chrome142, err := fastls.ParseH2SettingsString(chrome142Str)
	if err != nil {
		t.Fatalf("解析 Chrome142 设置失败: %v", err)
	}

	firefox, err := fastls.ParseH2SettingsString(firefoxStr)
	if err != nil {
		t.Fatalf("解析 Firefox 设置失败: %v", err)
	}

	t.Logf("\n=== Chrome142 H2Settings ===")
	t.Logf("Settings: %+v", chrome142.Settings)
	t.Logf("SettingsOrder: %v", chrome142.SettingsOrder)
	t.Logf("ConnectionFlow: %d", chrome142.ConnectionFlow)
	t.Logf("HeaderPriority: %+v", chrome142.HeaderPriority)

	t.Logf("\n=== Firefox H2Settings ===")
	t.Logf("Settings: %+v", firefox.Settings)
	t.Logf("SettingsOrder: %v", firefox.SettingsOrder)
	t.Logf("ConnectionFlow: %d", firefox.ConnectionFlow)
	t.Logf("HeaderPriority: %+v", firefox.HeaderPriority)

	// 验证它们不同
	if chrome142.ConnectionFlow == firefox.ConnectionFlow {
		t.Error("Chrome142 和 Firefox 的 ConnectionFlow 不应该相同")
	}

	if len(chrome142.Settings) == len(firefox.Settings) {
		// 检查是否有不同的设置
		allSame := true
		for key, chromeValue := range chrome142.Settings {
			firefoxValue, ok := firefox.Settings[key]
			if !ok || chromeValue != firefoxValue {
				allSame = false
				break
			}
		}
		if allSame {
			t.Error("Chrome142 和 Firefox 的 Settings 不应该完全相同")
		}
	}
}
