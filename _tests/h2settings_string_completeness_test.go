package tests

import (
	"testing"

	fastls "github.com/FastTLS/fastls"
)

// TestH2SettingsStringCompleteness 测试字符串格式是否能完全替代 H2Settings
func TestH2SettingsStringCompleteness(t *testing.T) {
	testCases := []struct {
		name        string
		inputString string
		description string
	}{
		{
			name:        "基础格式（推断HeaderPriority）",
			inputString: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
			description: "使用基础格式，HeaderPriority 的 weight 和 exclusive 会被推断",
		},
		{
			name:        "完整格式（精确HeaderPriority）",
			inputString: "1:65536;2:0;4:6291456;6:262144|15663105|0:256:true|m,a,s,p",
			description: "使用完整格式，HeaderPriority 的所有字段都是精确值",
		},
		{
			name:        "Safari格式（weight=255,exclusive=false）",
			inputString: "4:4194304;3:100|10485760|0:255:false|i,c",
			description: "Safari 的特殊 HeaderPriority 配置",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h2Settings, err := fastls.ParseH2SettingsString(tc.inputString)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}

			t.Logf("输入: %s", tc.inputString)
			t.Logf("描述: %s", tc.description)
			t.Logf("\n解析结果:")
			t.Logf("  Settings: %+v", h2Settings.Settings)
			t.Logf("  SettingsOrder: %v", h2Settings.SettingsOrder)
			t.Logf("  ConnectionFlow: %d", h2Settings.ConnectionFlow)
			t.Logf("  HeaderPriority: %+v", h2Settings.HeaderPriority)
			t.Logf("  PriorityFrames: %+v (数量: %d)", h2Settings.PriorityFrames, len(h2Settings.PriorityFrames))

			// 验证字段完整性
			hasSettings := len(h2Settings.Settings) > 0
			hasSettingsOrder := len(h2Settings.SettingsOrder) > 0
			hasConnectionFlow := h2Settings.ConnectionFlow != 0
			hasHeaderPriority := h2Settings.HeaderPriority != nil
			hasPriorityFrames := len(h2Settings.PriorityFrames) > 0

			t.Logf("\n=== 字段完整性检查 ===")
			t.Logf("✓ Settings: %v", hasSettings)
			t.Logf("✓ SettingsOrder: %v", hasSettingsOrder)
			t.Logf("✓ ConnectionFlow: %v", hasConnectionFlow)
			t.Logf("✓ HeaderPriority: %v", hasHeaderPriority)
			t.Logf("%s PriorityFrames: %v", func() string {
				if hasPriorityFrames {
					return "✗"
				}
				return "⚠"
			}(), hasPriorityFrames)

			if !hasSettings {
				t.Error("Settings 为空")
			}
			if !hasSettingsOrder {
				t.Error("SettingsOrder 为空")
			}
			if !hasConnectionFlow {
				t.Error("ConnectionFlow 为 0")
			}
			if !hasHeaderPriority {
				t.Error("HeaderPriority 为 nil")
			}
			if hasPriorityFrames {
				t.Logf("⚠ 注意: PriorityFrames 不为空，但字符串格式无法表示")
			}
		})
	}
}

// TestH2SettingsStringLimitations 测试字符串格式的限制
func TestH2SettingsStringLimitations(t *testing.T) {
	t.Log("=== H2SettingsString 格式支持情况 ===")
	t.Log("\n✅ 完全支持的字段:")
	t.Log("  1. Settings - SETTINGS 帧的所有设置")
	t.Log("  2. SettingsOrder - SETTINGS 帧的顺序")
	t.Log("  3. ConnectionFlow - 连接流控窗口大小")
	t.Log("  4. HeaderPriority - 支持两种格式:")
	t.Log("     - 基础格式: 'streamDep' (推断 weight 和 exclusive)")
	t.Log("     - 完整格式: 'streamDep:weight:exclusive' (精确值)")

	t.Log("\n❌ 不支持的字段:")
	t.Log("  1. PriorityFrames - 无法在字符串格式中表示")
	t.Log("     - 大多数浏览器（Chrome、Firefox、Edge）的 PriorityFrames 都是空的")
	t.Log("     - Safari 有一个 PriorityFrame，但通常也被注释掉")
	t.Log("     - 如果需要支持，可以扩展格式，例如:")
	t.Log("       '1:65536|15663105|0:256:true|m,a,s,p|0:0:0:true'")
	t.Log("       (最后一部分表示 PriorityFrames)")

	t.Log("\n📊 实际使用场景:")
	t.Log("  - Chrome/Chrome142/Edge: ✅ 完全支持（PriorityFrames 为空）")
	t.Log("  - Firefox: ✅ 完全支持（PriorityFrames 为空）")
	t.Log("  - Safari: ⚠️ 部分支持（PriorityFrames 不为空，但通常不需要）")

	t.Log("\n💡 结论:")
	t.Log("  字符串格式可以替代 H2Settings 用于大多数常见场景。")
	t.Log("  如果需要支持 PriorityFrames，可以进一步扩展格式。")
}
