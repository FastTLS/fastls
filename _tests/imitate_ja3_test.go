package tests

import (
	"strings"
	"testing"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

// TestChromeJa3Fingerprint 测试 Chrome 的 JA3 指纹
func TestChromeJa3Fingerprint(t *testing.T) {
	options := &fastls.Options{
		Headers: make(map[string]string),
	}

	imitate.Chrome(options)

	// 验证 Fingerprint 类型
	ja3, ok := options.Fingerprint.(fastls.Ja3Fingerprint)
	if !ok {
		t.Fatal("Fingerprint 应该是 Ja3Fingerprint 类型")
	}

	// Chrome 使用 shuffleExtension，所以指纹值会变化
	// 但应该包含固定的前缀和后缀
	expectedPrefix := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
	expectedSuffix := ",29-23-24,0"

	if !strings.HasPrefix(ja3.FingerprintValue, expectedPrefix) {
		t.Errorf("JA3 指纹应该以 %s 开头，实际是 %s", expectedPrefix, ja3.FingerprintValue)
	}

	if !strings.HasSuffix(ja3.FingerprintValue, expectedSuffix) {
		t.Errorf("JA3 指纹应该以 %s 结尾，实际是 %s", expectedSuffix, ja3.FingerprintValue)
	}

	// 验证 JA3 指纹格式（应该包含 5 个部分，用逗号分隔）
	// 格式：TLS版本,密码套件,扩展,椭圆曲线,椭圆曲线格式
	parts := strings.Split(ja3.FingerprintValue, ",")
	if len(parts) != 5 {
		t.Errorf("JA3 指纹应该有 5 个部分，实际有 %d 个部分: %v", len(parts), parts)
	}

	t.Logf("✅ Chrome JA3 指纹测试通过")
	t.Logf("  - JA3: %s", ja3.FingerprintValue)
}

// TestChromiumJa3Fingerprint 测试 Chromium 的 JA3 指纹
func TestChromiumJa3Fingerprint(t *testing.T) {
	options := &fastls.Options{
		Headers: make(map[string]string),
	}

	imitate.Chromium(options)

	// 验证 Fingerprint 类型
	ja3, ok := options.Fingerprint.(fastls.Ja3Fingerprint)
	if !ok {
		t.Fatal("Fingerprint 应该是 Ja3Fingerprint 类型")
	}

	// Chromium 使用 shuffleExtension，所以指纹值会变化
	// 但应该包含固定的前缀和后缀
	expectedPrefix := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
	expectedSuffix := "-41,29-23-24,0"

	if !strings.HasPrefix(ja3.FingerprintValue, expectedPrefix) {
		t.Errorf("JA3 指纹应该以 %s 开头，实际是 %s", expectedPrefix, ja3.FingerprintValue)
	}

	if !strings.HasSuffix(ja3.FingerprintValue, expectedSuffix) {
		t.Errorf("JA3 指纹应该以 %s 结尾，实际是 %s", expectedSuffix, ja3.FingerprintValue)
	}

	// 验证 JA3 指纹格式（应该包含 5 个部分，用逗号分隔）
	// 格式：TLS版本,密码套件,扩展,椭圆曲线,椭圆曲线格式
	parts := strings.Split(ja3.FingerprintValue, ",")
	if len(parts) != 5 {
		t.Errorf("JA3 指纹应该有 5 个部分，实际有 %d 个部分", len(parts))
	}

	t.Logf("✅ Chromium JA3 指纹测试通过")
	t.Logf("  - JA3: %s", ja3.FingerprintValue)
}

// TestSafariJa3Fingerprint 测试 Safari 的 JA3 指纹
func TestSafariJa3Fingerprint(t *testing.T) {
	options := &fastls.Options{
		Headers: make(map[string]string),
	}

	imitate.Safari(options)

	// 验证 Fingerprint 类型
	ja3, ok := options.Fingerprint.(fastls.Ja3Fingerprint)
	if !ok {
		t.Fatal("Fingerprint 应该是 Ja3Fingerprint 类型")
	}

	// Safari 使用固定指纹值
	expectedJA3 := "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0"

	if ja3.FingerprintValue != expectedJA3 {
		t.Errorf("JA3 指纹不匹配: 期望 %s，实际 %s", expectedJA3, ja3.FingerprintValue)
	}

	// 验证 JA3 指纹格式（应该包含 5 个部分，用逗号分隔）
	// 格式：TLS版本,密码套件,扩展,椭圆曲线,椭圆曲线格式
	parts := strings.Split(ja3.FingerprintValue, ",")
	if len(parts) != 5 {
		t.Errorf("JA3 指纹应该有 5 个部分，实际有 %d 个部分", len(parts))
	}

	t.Logf("✅ Safari JA3 指纹测试通过")
	t.Logf("  - JA3: %s", ja3.FingerprintValue)
}

// TestChrome142Ja3Fingerprint 测试 Chrome142 的 JA3 指纹
func TestChrome142Ja3Fingerprint(t *testing.T) {
	options := &fastls.Options{
		Headers: make(map[string]string),
	}

	imitate.Chrome142(options)

	// 验证 Fingerprint 类型
	ja3, ok := options.Fingerprint.(fastls.Ja3Fingerprint)
	if !ok {
		t.Fatal("Fingerprint 应该是 Ja3Fingerprint 类型")
	}

	// Chrome142 使用固定指纹值
	expectedJA3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-27-51-13-0-11-10-5-18-35-43-45-17613-23-65037-16-41,4588-29-23-24,0"

	if ja3.FingerprintValue != expectedJA3 {
		t.Errorf("JA3 指纹不匹配: 期望 %s，实际 %s", expectedJA3, ja3.FingerprintValue)
	}

	// 验证 JA3 指纹格式（应该包含 5 个部分，用逗号分隔）
	// 格式：TLS版本,密码套件,扩展,椭圆曲线,椭圆曲线格式
	parts := strings.Split(ja3.FingerprintValue, ",")
	if len(parts) != 5 {
		t.Errorf("JA3 指纹应该有 5 个部分，实际有 %d 个部分", len(parts))
	}

	t.Logf("✅ Chrome142 JA3 指纹测试通过")
	t.Logf("  - JA3: %s", ja3.FingerprintValue)
}

// TestChrome120Ja3Fingerprint 测试 Chrome120 的 JA3 指纹
func TestChrome120Ja3Fingerprint(t *testing.T) {
	options := &fastls.Options{
		Headers: make(map[string]string),
	}

	imitate.Chrome120(options)

	// 验证 Fingerprint 类型
	ja3, ok := options.Fingerprint.(fastls.Ja3Fingerprint)
	if !ok {
		t.Fatal("Fingerprint 应该是 Ja3Fingerprint 类型")
	}

	// Chrome120 使用 shuffleExtension，所以指纹值会变化
	// 但应该包含固定的前缀和后缀
	expectedPrefix := "771,4865-4866-4867-49195-49199-49196-49120-52393-52392-49171-49172-156-157-47-53,"
	expectedSuffix := "-41,29-23-24,0"

	if !strings.HasPrefix(ja3.FingerprintValue, expectedPrefix) {
		t.Errorf("JA3 指纹应该以 %s 开头，实际是 %s", expectedPrefix, ja3.FingerprintValue)
	}

	if !strings.HasSuffix(ja3.FingerprintValue, expectedSuffix) {
		t.Errorf("JA3 指纹应该以 %s 结尾，实际是 %s", expectedSuffix, ja3.FingerprintValue)
	}

	// 验证 JA3 指纹格式（应该包含 5 个部分，用逗号分隔）
	// 格式：TLS版本,密码套件,扩展,椭圆曲线,椭圆曲线格式
	parts := strings.Split(ja3.FingerprintValue, ",")
	if len(parts) != 5 {
		t.Errorf("JA3 指纹应该有 5 个部分，实际有 %d 个部分", len(parts))
	}

	t.Logf("✅ Chrome120 JA3 指纹测试通过")
	t.Logf("  - JA3: %s", ja3.FingerprintValue)
}

// TestFirefoxJa3Fingerprint 测试 Firefox 的 JA3 指纹
func TestFirefoxJa3Fingerprint(t *testing.T) {
	options := &fastls.Options{
		Headers: make(map[string]string),
	}

	imitate.Firefox(options)

	// 验证 Fingerprint 类型
	ja3, ok := options.Fingerprint.(fastls.Ja3Fingerprint)
	if !ok {
		t.Fatal("Fingerprint 应该是 Ja3Fingerprint 类型")
	}

	// Firefox 使用固定指纹值
	expectedJA3 := "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0"

	if ja3.FingerprintValue != expectedJA3 {
		t.Errorf("JA3 指纹不匹配: 期望 %s，实际 %s", expectedJA3, ja3.FingerprintValue)
	}

	// 验证 JA3 指纹格式（应该包含 5 个部分，用逗号分隔）
	// 格式：TLS版本,密码套件,扩展,椭圆曲线,椭圆曲线格式
	parts := strings.Split(ja3.FingerprintValue, ",")
	if len(parts) != 5 {
		t.Errorf("JA3 指纹应该有 5 个部分，实际有 %d 个部分", len(parts))
	}

	t.Logf("✅ Firefox JA3 指纹测试通过")
	t.Logf("  - JA3: %s", ja3.FingerprintValue)
}

// TestEdgeJa3Fingerprint 测试 Edge 的 JA3 指纹
// Edge 调用 Chrome142，所以应该使用 Chrome142 的指纹
func TestEdgeJa3Fingerprint(t *testing.T) {
	options := &fastls.Options{
		Headers: make(map[string]string),
	}

	imitate.Edge(options)

	// 验证 Fingerprint 类型
	ja3, ok := options.Fingerprint.(fastls.Ja3Fingerprint)
	if !ok {
		t.Fatal("Fingerprint 应该是 Ja3Fingerprint 类型")
	}

	// Edge 使用 Chrome142 的固定指纹值
	expectedJA3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-27-51-13-0-11-10-5-18-35-43-45-17613-23-65037-16-41,4588-29-23-24,0"

	if ja3.FingerprintValue != expectedJA3 {
		t.Errorf("JA3 指纹不匹配: 期望 %s，实际 %s", expectedJA3, ja3.FingerprintValue)
	}

	// 验证 JA3 指纹格式（应该包含 5 个部分，用逗号分隔）
	// 格式：TLS版本,密码套件,扩展,椭圆曲线,椭圆曲线格式
	parts := strings.Split(ja3.FingerprintValue, ",")
	if len(parts) != 5 {
		t.Errorf("JA3 指纹应该有 5 个部分，实际有 %d 个部分", len(parts))
	}

	t.Logf("✅ Edge JA3 指纹测试通过")
	t.Logf("  - JA3: %s", ja3.FingerprintValue)
}

// TestOperaJa3Fingerprint 测试 Opera 的 JA3 指纹
// Opera 调用 Chrome，所以应该使用 Chrome 的指纹格式（但值会变化）
func TestOperaJa3Fingerprint(t *testing.T) {
	options := &fastls.Options{
		Headers: make(map[string]string),
	}

	imitate.Opera(options)

	// 验证 Fingerprint 类型
	ja3, ok := options.Fingerprint.(fastls.Ja3Fingerprint)
	if !ok {
		t.Fatal("Fingerprint 应该是 Ja3Fingerprint 类型")
	}

	// Opera 使用 Chrome 的指纹格式（使用 shuffleExtension，所以值会变化）
	// 但应该包含固定的前缀和后缀
	expectedPrefix := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
	expectedSuffix := ",29-23-24,0"

	if !strings.HasPrefix(ja3.FingerprintValue, expectedPrefix) {
		t.Errorf("JA3 指纹应该以 %s 开头，实际是 %s", expectedPrefix, ja3.FingerprintValue)
	}

	if !strings.HasSuffix(ja3.FingerprintValue, expectedSuffix) {
		t.Errorf("JA3 指纹应该以 %s 结尾，实际是 %s", expectedSuffix, ja3.FingerprintValue)
	}

	// 验证 JA3 指纹格式（应该包含 5 个部分，用逗号分隔）
	// 格式：TLS版本,密码套件,扩展,椭圆曲线,椭圆曲线格式
	parts := strings.Split(ja3.FingerprintValue, ",")
	if len(parts) != 5 {
		t.Errorf("JA3 指纹应该有 5 个部分，实际有 %d 个部分", len(parts))
	}

	t.Logf("✅ Opera JA3 指纹测试通过")
	t.Logf("  - JA3: %s", ja3.FingerprintValue)
}

// TestAllJa3Fingerprints 测试所有 JA3 指纹的基本格式
func TestAllJa3Fingerprints(t *testing.T) {
	testCases := []struct {
		name     string
		setupFn  func(*fastls.Options)
		validate func(*testing.T, fastls.Ja3Fingerprint)
	}{
		{
			name:    "Chrome",
			setupFn: imitate.Chrome,
			validate: func(t *testing.T, ja3 fastls.Ja3Fingerprint) {
				expectedPrefix := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
				if !strings.HasPrefix(ja3.FingerprintValue, expectedPrefix) {
					t.Errorf("Chrome JA3 指纹格式不正确")
				}
			},
		},
		{
			name:    "Chromium",
			setupFn: imitate.Chromium,
			validate: func(t *testing.T, ja3 fastls.Ja3Fingerprint) {
				expectedPrefix := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
				if !strings.HasPrefix(ja3.FingerprintValue, expectedPrefix) {
					t.Errorf("Chromium JA3 指纹格式不正确")
				}
			},
		},
		{
			name:    "Safari",
			setupFn: imitate.Safari,
			validate: func(t *testing.T, ja3 fastls.Ja3Fingerprint) {
				expected := "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0"
				if ja3.FingerprintValue != expected {
					t.Errorf("Safari JA3 指纹不匹配")
				}
			},
		},
		{
			name:    "Chrome142",
			setupFn: imitate.Chrome142,
			validate: func(t *testing.T, ja3 fastls.Ja3Fingerprint) {
				expected := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-27-51-13-0-11-10-5-18-35-43-45-17613-23-65037-16-41,4588-29-23-24,0"
				if ja3.FingerprintValue != expected {
					t.Errorf("Chrome142 JA3 指纹不匹配")
				}
			},
		},
		{
			name:    "Chrome120",
			setupFn: imitate.Chrome120,
			validate: func(t *testing.T, ja3 fastls.Ja3Fingerprint) {
				expectedPrefix := "771,4865-4866-4867-49195-49199-49196-49120-52393-52392-49171-49172-156-157-47-53,"
				if !strings.HasPrefix(ja3.FingerprintValue, expectedPrefix) {
					t.Errorf("Chrome120 JA3 指纹格式不正确")
				}
			},
		},
		{
			name:    "Firefox",
			setupFn: imitate.Firefox,
			validate: func(t *testing.T, ja3 fastls.Ja3Fingerprint) {
				expected := "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0"
				if ja3.FingerprintValue != expected {
					t.Errorf("Firefox JA3 指纹不匹配")
				}
			},
		},
		{
			name:    "Edge",
			setupFn: imitate.Edge,
			validate: func(t *testing.T, ja3 fastls.Ja3Fingerprint) {
				expected := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-27-51-13-0-11-10-5-18-35-43-45-17613-23-65037-16-41,4588-29-23-24,0"
				if ja3.FingerprintValue != expected {
					t.Errorf("Edge JA3 指纹不匹配")
				}
			},
		},
		{
			name:    "Opera",
			setupFn: imitate.Opera,
			validate: func(t *testing.T, ja3 fastls.Ja3Fingerprint) {
				expectedPrefix := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
				if !strings.HasPrefix(ja3.FingerprintValue, expectedPrefix) {
					t.Errorf("Opera JA3 指纹格式不正确")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := &fastls.Options{
				Headers: make(map[string]string),
			}

			tc.setupFn(options)

			// 验证 Fingerprint 类型
			ja3, ok := options.Fingerprint.(fastls.Ja3Fingerprint)
			if !ok {
				t.Fatal("Fingerprint 应该是 Ja3Fingerprint 类型")
			}

			// 验证 JA3 指纹格式（应该包含 5 个部分，用逗号分隔）
			// 格式：TLS版本,密码套件,扩展,椭圆曲线,椭圆曲线格式
			parts := strings.Split(ja3.FingerprintValue, ",")
			if len(parts) != 5 {
				t.Errorf("JA3 指纹应该有 5 个部分，实际有 %d 个部分: %v", len(parts), parts)
			}

			// 执行自定义验证
			tc.validate(t, ja3)

			t.Logf("✅ %s JA3 指纹测试通过: %s", tc.name, ja3.FingerprintValue)
		})
	}
}
