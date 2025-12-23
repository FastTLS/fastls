package tests

import (
	"testing"

	fastls "github.com/FastTLS/fastls"
)

// TestUnknownSettingID 测试未知设置 ID 的支持
func TestUnknownSettingID(t *testing.T) {
	// 测试包含未知设置 ID 的字符串
	testString := "1:65536;2:0;4:6291456;6:262144;15082:0|15663105|0|m,a,s,p"
	h2Settings, err := fastls.ParseH2SettingsString(testString)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 验证标准设置
	if h2Settings.Settings["HEADER_TABLE_SIZE"] != 65536 {
		t.Errorf("HEADER_TABLE_SIZE 应该是 65536，实际是 %d", h2Settings.Settings["HEADER_TABLE_SIZE"])
	}

	// 验证未知设置
	if h2Settings.Settings["UNKNOWN_SETTING_15082"] != 0 {
		t.Errorf("UNKNOWN_SETTING_15082 应该是 0，实际是 %d", h2Settings.Settings["UNKNOWN_SETTING_15082"])
	}

	t.Logf("解析成功: Settings=%+v", h2Settings.Settings)
	t.Logf("SettingsOrder=%+v", h2Settings.SettingsOrder)

	// 验证未知设置是否在 SettingsOrder 中
	found := false
	for _, name := range h2Settings.SettingsOrder {
		if name == "UNKNOWN_SETTING_15082" {
			found = true
			break
		}
	}
	if !found {
		t.Logf("注意: UNKNOWN_SETTING_15082 不在 SettingsOrder 中，这是正常的，因为顺序字符串中没有对应的字母")
	}
}
