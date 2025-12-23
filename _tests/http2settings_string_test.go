package tests

import (
	"testing"

	fastls "github.com/FastTLS/fastls"
)

// TestHTTP2SettingsStringOverride 测试 HTTP2SettingsString 覆盖 HTTP2Settings 和 PHeaderOrderKeys
func TestHTTP2SettingsStringOverride(t *testing.T) {
	testCases := []struct {
		name                string
		http2SettingsString string
		initialHTTP2Settings *fastls.H2Settings
		initialPHeaderOrder  []string
		expectedPHeaderOrder []string
		description         string
	}{
		{
			name:                "基础格式（不包含PHeaderOrderKeys）",
			http2SettingsString: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
			initialHTTP2Settings: nil,
			initialPHeaderOrder:  []string{":method", ":authority", ":scheme", ":path"},
			expectedPHeaderOrder:  []string{":method", ":authority", ":scheme", ":path"}, // 应该保持原值
			description:         "使用基础格式，不包含 PHeaderOrderKeys，应该保持原有的 PHeaderOrderKeys",
		},
		{
			name:                "完整格式（包含PHeaderOrderKeys）",
			http2SettingsString: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p||:method,:authority,:scheme,:path",
			initialHTTP2Settings: nil,
			initialPHeaderOrder:  []string{":method", ":path", ":authority", ":scheme"},
			expectedPHeaderOrder:  []string{":method", ":authority", ":scheme", ":path"}, // 应该被覆盖
			description:         "使用完整格式，包含 PHeaderOrderKeys，应该覆盖原有的 PHeaderOrderKeys",
		},
		{
			name:                "Firefox格式（包含PHeaderOrderKeys）",
			http2SettingsString: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s||:method,:path,:authority,:scheme",
			initialHTTP2Settings: nil,
			initialPHeaderOrder:  []string{":method", ":authority", ":scheme", ":path"},
			expectedPHeaderOrder:  []string{":method", ":path", ":authority", ":scheme"}, // 应该被覆盖为 Firefox 的顺序
			description:         "Firefox 格式，包含 PHeaderOrderKeys，应该覆盖为 Firefox 的顺序",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := &fastls.Options{
				Headers: make(map[string]string),
			}

			// 设置初始值
			if tc.initialHTTP2Settings != nil {
				options.HTTP2Settings = fastls.ToHTTP2Settings(tc.initialHTTP2Settings)
			}
			options.PHeaderOrderKeys = tc.initialPHeaderOrder

			// 设置 HTTP2SettingsString
			options.HTTP2SettingsString = tc.http2SettingsString

			// 模拟 processRequest 中的处理逻辑
			if options.HTTP2SettingsString != "" {
				h2Settings, pHeaderOrderKeys, err := fastls.ParseH2SettingsStringWithPHeaderOrder(options.HTTP2SettingsString)
				if err != nil {
					t.Fatalf("解析 HTTP2SettingsString 失败: %v", err)
				}
				// 覆盖 HTTP2Settings
				options.HTTP2Settings = fastls.ToHTTP2Settings(h2Settings)
				// 如果解析出 PHeaderOrderKeys，则覆盖
				if len(pHeaderOrderKeys) > 0 {
					options.PHeaderOrderKeys = pHeaderOrderKeys
				}
			}

			// 验证 HTTP2Settings 被正确设置
			if options.HTTP2Settings == nil {
				t.Error("HTTP2Settings 应该被设置")
			} else {
				t.Logf("HTTP2Settings 已设置: Settings 数量=%d, ConnectionFlow=%d",
					len(options.HTTP2Settings.Settings),
					options.HTTP2Settings.ConnectionFlow)
			}

			// 验证 PHeaderOrderKeys
			if len(tc.expectedPHeaderOrder) > 0 {
				if len(options.PHeaderOrderKeys) != len(tc.expectedPHeaderOrder) {
					t.Errorf("PHeaderOrderKeys 长度不匹配: 期望 %d，实际 %d",
						len(tc.expectedPHeaderOrder), len(options.PHeaderOrderKeys))
				} else {
					for i, expected := range tc.expectedPHeaderOrder {
						if i < len(options.PHeaderOrderKeys) && options.PHeaderOrderKeys[i] != expected {
							t.Errorf("PHeaderOrderKeys[%d] 不匹配: 期望 %s，实际 %s",
								i, expected, options.PHeaderOrderKeys[i])
						}
					}
				}
			}

			t.Logf("描述: %s", tc.description)
			t.Logf("PHeaderOrderKeys: %v", options.PHeaderOrderKeys)
		})
	}
}

// TestParseH2SettingsStringWithPHeaderOrder 测试解析函数
func TestParseH2SettingsStringWithPHeaderOrder(t *testing.T) {
	testCases := []struct {
		name                string
		input               string
		expectPHeaderOrder  bool
		expectedPHeaderOrder []string
		description         string
	}{
		{
			name:                "不包含PHeaderOrderKeys",
			input:               "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
			expectPHeaderOrder:  false,
			expectedPHeaderOrder: nil,
			description:         "基础格式，不包含 PHeaderOrderKeys",
		},
		{
			name:                "包含PHeaderOrderKeys",
			input:               "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p||:method,:authority,:scheme,:path",
			expectPHeaderOrder:  true,
			expectedPHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
			description:         "完整格式，包含 PHeaderOrderKeys",
		},
		{
			name:                "Firefox格式",
			input:               "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s||:method,:path,:authority,:scheme",
			expectPHeaderOrder:  true,
			expectedPHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
			description:         "Firefox 格式，包含 PHeaderOrderKeys",
		},
		{
			name:                "空PHeaderOrderKeys",
			input:               "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p||",
			expectPHeaderOrder:  false,
			expectedPHeaderOrder: nil,
			description:         "包含 || 但 PHeaderOrderKeys 为空",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h2Settings, pHeaderOrderKeys, err := fastls.ParseH2SettingsStringWithPHeaderOrder(tc.input)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}

			if h2Settings == nil {
				t.Error("H2Settings 不应该为 nil")
			} else {
				t.Logf("H2Settings 解析成功: Settings 数量=%d, ConnectionFlow=%d",
					len(h2Settings.Settings), h2Settings.ConnectionFlow)
			}

			if tc.expectPHeaderOrder {
				if len(pHeaderOrderKeys) == 0 {
					t.Error("期望有 PHeaderOrderKeys，但实际为空")
				} else {
					if len(pHeaderOrderKeys) != len(tc.expectedPHeaderOrder) {
						t.Errorf("PHeaderOrderKeys 长度不匹配: 期望 %d，实际 %d",
							len(tc.expectedPHeaderOrder), len(pHeaderOrderKeys))
					} else {
						for i, expected := range tc.expectedPHeaderOrder {
							if pHeaderOrderKeys[i] != expected {
								t.Errorf("PHeaderOrderKeys[%d] 不匹配: 期望 %s，实际 %s",
									i, expected, pHeaderOrderKeys[i])
							}
						}
					}
				}
			} else {
				if len(pHeaderOrderKeys) > 0 {
					t.Logf("注意: 不期望有 PHeaderOrderKeys，但实际有 %d 个", len(pHeaderOrderKeys))
				}
			}

			t.Logf("描述: %s", tc.description)
			t.Logf("PHeaderOrderKeys: %v", pHeaderOrderKeys)
		})
	}
}

