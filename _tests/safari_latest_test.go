package tests

import (
	"testing"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// TestSafariLatestFingerprint 测试最新版 Safari 指纹
func TestSafariLatestFingerprint(t *testing.T) {
	options := &fastls.Options{
		Headers: make(map[string]string),
	}

	imitate.Safari(options)

	// 验证 JA3 指纹
	expectedJA3 := "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0"
	if ja3, ok := options.Fingerprint.(fastls.Ja3Fingerprint); ok {
		if ja3.FingerprintValue != expectedJA3 {
			t.Errorf("JA3 指纹不匹配: 期望 %s，实际 %s", expectedJA3, ja3.FingerprintValue)
		}
	} else {
		t.Error("Fingerprint 不是 Ja3Fingerprint 类型")
	}

	// 验证 HTTP2SettingsString
	expectedH2String := "2:0;3:100;4:2097152;9:1|10420225|0:256:false|m,s,a,p"
	if options.HTTP2SettingsString != expectedH2String {
		t.Errorf("HTTP2SettingsString 不匹配: 期望 %s，实际 %s", expectedH2String, options.HTTP2SettingsString)
	}

	// 解析并验证 HTTP/2 设置
	h2Settings, pHeaderOrderKeys, err := fastls.ParseH2SettingsStringWithPHeaderOrder(options.HTTP2SettingsString)
	if err != nil {
		t.Fatalf("解析 HTTP2SettingsString 失败: %v", err)
	}

	// 验证设置
	if h2Settings.Settings["ENABLE_PUSH"] != 0 {
		t.Errorf("ENABLE_PUSH 应该是 0，实际是 %d", h2Settings.Settings["ENABLE_PUSH"])
	}
	if h2Settings.Settings["MAX_CONCURRENT_STREAMS"] != 100 {
		t.Errorf("MAX_CONCURRENT_STREAMS 应该是 100，实际是 %d", h2Settings.Settings["MAX_CONCURRENT_STREAMS"])
	}
	if h2Settings.Settings["INITIAL_WINDOW_SIZE"] != 2097152 {
		t.Errorf("INITIAL_WINDOW_SIZE 应该是 2097152，实际是 %d", h2Settings.Settings["INITIAL_WINDOW_SIZE"])
	}
	if h2Settings.Settings["NO_RFC7540_PRIORITIES"] != 1 {
		t.Errorf("NO_RFC7540_PRIORITIES 应该是 1，实际是 %d", h2Settings.Settings["NO_RFC7540_PRIORITIES"])
	}

	// 验证 ConnectionFlow
	if h2Settings.ConnectionFlow != 10420225 {
		t.Errorf("ConnectionFlow 应该是 10420225，实际是 %d", h2Settings.ConnectionFlow)
	}

	// 验证 HeaderPriority
	if h2Settings.HeaderPriority == nil {
		t.Error("HeaderPriority 不应该为 nil")
	} else {
		if h2Settings.HeaderPriority["weight"].(int) != 256 {
			t.Errorf("HeaderPriority.weight 应该是 256，实际是 %v", h2Settings.HeaderPriority["weight"])
		}
		if h2Settings.HeaderPriority["streamDep"].(int) != 0 {
			t.Errorf("HeaderPriority.streamDep 应该是 0，实际是 %v", h2Settings.HeaderPriority["streamDep"])
		}
		if h2Settings.HeaderPriority["exclusive"].(bool) != false {
			t.Errorf("HeaderPriority.exclusive 应该是 false，实际是 %v", h2Settings.HeaderPriority["exclusive"])
		}
	}

	// 验证 PHeaderOrderKeys（应该自动推导）
	expectedPHeaderOrder := []string{":method", ":scheme", ":authority", ":path"}
	if len(pHeaderOrderKeys) != len(expectedPHeaderOrder) {
		t.Errorf("PHeaderOrderKeys 长度不匹配: 期望 %d，实际 %d", len(expectedPHeaderOrder), len(pHeaderOrderKeys))
	} else {
		for i, expected := range expectedPHeaderOrder {
			if pHeaderOrderKeys[i] != expected {
				t.Errorf("PHeaderOrderKeys[%d] 不匹配: 期望 %s，实际 %s", i, expected, pHeaderOrderKeys[i])
			}
		}
	}

	// 验证 UserAgent
	expectedUA := "Mozilla/5.0 (iPad; CPU OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.3 Mobile/15E148 Safari/604.1"
	if options.UserAgent != expectedUA {
		t.Errorf("UserAgent 不匹配: 期望 %s，实际 %s", expectedUA, options.UserAgent)
	}

	// 验证 Accept
	expectedAccept := "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	if options.Headers["Accept"] != expectedAccept {
		t.Errorf("Accept 不匹配: 期望 %s，实际 %s", expectedAccept, options.Headers["Accept"])
	}

	t.Logf("✅ Safari 最新指纹配置验证通过")
	t.Logf("  - JA3: %s", expectedJA3)
	t.Logf("  - HTTP2SettingsString: %s", expectedH2String)
	t.Logf("  - Settings: %+v", h2Settings.Settings)
	t.Logf("  - ConnectionFlow: %d", h2Settings.ConnectionFlow)
	t.Logf("  - HeaderPriority: %+v", h2Settings.HeaderPriority)
	t.Logf("  - PHeaderOrderKeys: %v", pHeaderOrderKeys)
	t.Logf("  - UserAgent: %s", options.UserAgent)
}
