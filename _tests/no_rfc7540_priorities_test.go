package tests

import (
	"testing"

	fastls "github.com/FastTLS/fastls"
	http2 "github.com/FastTLS/fhttp/http2"
)

// TestNO_RFC7540_PRIORITIES 测试 NO_RFC7540_PRIORITIES (设置 ID 9) 是否正确转换
func TestNO_RFC7540_PRIORITIES(t *testing.T) {
	// 测试 Safari 的 HTTP2SettingsString，包含 9:1
	h2SettingsString := "2:0;3:100;4:2097152;9:1|10420225|0:256:false|m,s,a,p"

	// 解析字符串
	h2Settings, _, err := fastls.ParseH2SettingsStringWithPHeaderOrder(h2SettingsString)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 验证 NO_RFC7540_PRIORITIES 在 Settings 中
	if val, ok := h2Settings.Settings["NO_RFC7540_PRIORITIES"]; !ok {
		t.Error("NO_RFC7540_PRIORITIES 不在 Settings 中")
	} else if val != 1 {
		t.Errorf("NO_RFC7540_PRIORITIES 应该是 1，实际是 %d", val)
	}

	// 验证 NO_RFC7540_PRIORITIES 在 SettingsOrder 中
	found := false
	for _, orderKey := range h2Settings.SettingsOrder {
		if orderKey == "NO_RFC7540_PRIORITIES" {
			found = true
			break
		}
	}
	if !found {
		t.Error("NO_RFC7540_PRIORITIES 不在 SettingsOrder 中")
	}

	// 转换为 http2.HTTP2Settings
	http2Settings := fastls.ToHTTP2Settings(h2Settings)

	// 验证 NO_RFC7540_PRIORITIES 是否正确转换为 http2.SettingID(9)
	foundSetting := false
	for _, setting := range http2Settings.Settings {
		if setting.ID == http2.SettingID(9) {
			foundSetting = true
			if setting.Val != 1 {
				t.Errorf("NO_RFC7540_PRIORITIES 的值应该是 1，实际是 %d", setting.Val)
			}
			break
		}
	}
	if !foundSetting {
		t.Error("NO_RFC7540_PRIORITIES (设置 ID 9) 未在 http2.HTTP2Settings.Settings 中找到")
	}

	t.Logf("✅ NO_RFC7540_PRIORITIES 测试通过")
	t.Logf("  - Settings 中的值: %d", h2Settings.Settings["NO_RFC7540_PRIORITIES"])
	for _, setting := range http2Settings.Settings {
		if setting.ID == http2.SettingID(9) {
			t.Logf("  - http2.Setting ID: %d, Val: %d", setting.ID, setting.Val)
			break
		}
	}
}
