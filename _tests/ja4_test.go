package tests

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate/ja4r"
)

// TestJa4FingerprintType 测试 JA4 指纹类型
func TestJa4FingerprintType(t *testing.T) {
	fp := fastls.Ja4Fingerprint{
		FingerprintValue: "t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603",
	}

	if fp.Type() != "ja4r" {
		t.Errorf("期望类型 'ja4r', 得到 '%s'", fp.Type())
	}
}

// TestJa4FingerprintValue 测试 JA4 指纹值
func TestJa4FingerprintValue(t *testing.T) {
	expectedValue := "t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603"
	fp := fastls.Ja4Fingerprint{
		FingerprintValue: expectedValue,
	}

	if fp.Value() != expectedValue {
		t.Errorf("期望值 '%s', 得到 '%s'", expectedValue, fp.Value())
	}
}

// TestJa4FingerprintIsEmpty 测试 JA4 指纹是否为空
func TestJa4FingerprintIsEmpty(t *testing.T) {
	// 测试空指纹
	emptyFp := fastls.Ja4Fingerprint{
		FingerprintValue: "",
	}
	if !emptyFp.IsEmpty() {
		t.Error("空指纹应该返回 true")
	}

	// 测试非空指纹
	nonEmptyFp := fastls.Ja4Fingerprint{
		FingerprintValue: "t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603",
	}
	if nonEmptyFp.IsEmpty() {
		t.Error("非空指纹应该返回 false")
	}
}

// TestOptionsIsJa4 测试 Options 的 IsJa4 方法
func TestOptionsIsJa4(t *testing.T) {
	// 测试 JA4 指纹
	options := fastls.Options{
		Fingerprint: fastls.Ja4Fingerprint{
			FingerprintValue: "t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603",
		},
	}
	if !options.IsJa4() {
		t.Error("应该识别为 JA4 指纹")
	}

	// 测试 JA3 指纹
	options.Fingerprint = fastls.Ja3Fingerprint{
		FingerprintValue: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-27-51-13-0-11-10-5-18-35-43-45-17613-23-65037-16-41,4588-29-23-24,0",
	}
	if options.IsJa4() {
		t.Error("JA3 指纹不应该识别为 JA4")
	}

	// 测试空指纹
	options.Fingerprint = nil
	if options.IsJa4() {
		t.Error("空指纹不应该识别为 JA4")
	}
}

// TestOptionsGetFingerprintType 测试获取指纹类型
func TestOptionsGetFingerprintType(t *testing.T) {
	// 测试 JA4 指纹
	options := fastls.Options{
		Fingerprint: fastls.Ja4Fingerprint{
			FingerprintValue: "t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603",
		},
	}
	if options.GetFingerprintType() != "ja4r" {
		t.Errorf("期望类型 'ja4r', 得到 '%s'", options.GetFingerprintType())
	}

	// 测试空指纹
	options.Fingerprint = nil
	if options.GetFingerprintType() != "" {
		t.Errorf("空指纹应该返回空字符串, 得到 '%s'", options.GetFingerprintType())
	}
}

// TestOptionsGetFingerprintValue 测试获取指纹值
func TestOptionsGetFingerprintValue(t *testing.T) {
	expectedValue := "t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603"
	options := fastls.Options{
		Fingerprint: fastls.Ja4Fingerprint{
			FingerprintValue: expectedValue,
		},
	}
	if options.GetFingerprintValue() != expectedValue {
		t.Errorf("期望值 '%s', 得到 '%s'", expectedValue, options.GetFingerprintValue())
	}

	// 测试空指纹
	options.Fingerprint = nil
	if options.GetFingerprintValue() != "" {
		t.Errorf("空指纹应该返回空字符串, 得到 '%s'", options.GetFingerprintValue())
	}
}

// TestJa4FingerprintFormat 测试 JA4R 指纹格式
func TestJa4FingerprintFormat(t *testing.T) {
	// 测试正确的 JA4R 格式
	validFormats := []string{
		"t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603",
		"t13d1717h2_002f,0035,009c,009d,1301,1302,1303_c009,c00a,c013,c014_0005,000a,000b,000d_0403,0503,0603",
		"t13d5911_002f,0032,0033,0035,0038,0039,003c,003d,0040,0067,006a,006b,009c,009d,009e,009f,00a2,00a3,00ff,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,c050,c051,c052,c053,c056,c057,c05c,c05d,c060,c061,c09c,c09d,c09e,c09f,c0a0,c0a1,c0a2,c0a3,c0ac,c0ad,c0ae,c0af,cca8,cca9,ccaa_000a,000b,000d,0016,0017,0023,0029,002b,002d,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602",
	}

	for _, format := range validFormats {
		fp := fastls.Ja4Fingerprint{
			FingerprintValue: format,
		}
		if fp.IsEmpty() {
			t.Errorf("有效格式 '%s' 不应该为空", format)
		}
		if fp.Type() != "ja4r" {
			t.Errorf("格式 '%s' 应该返回类型 'ja4r'", format)
		}
		if !strings.HasPrefix(format, "t") {
			t.Errorf("格式 '%s' 应该以 't' 开头", format)
		}
	}
}

// TestChrome142JA4 测试 Chrome142 JA4 配置
func TestChrome142JA4(t *testing.T) {
	options := fastls.Options{
		Headers: make(map[string]string),
	}

	ja4r.Chrome142JA4(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("Chrome142JA4 应该设置指纹")
	}

	// 验证指纹类型
	if !options.IsJa4() {
		t.Error("Chrome142JA4 应该设置 JA4 指纹")
	}

	// 验证指纹格式
	fpValue := options.Fingerprint.Value()
	if !strings.HasPrefix(fpValue, "t13d") {
		t.Errorf("JA4R 指纹应该以 't13d' 开头, 得到 '%s'", fpValue[:min(10, len(fpValue))])
	}

	// 验证 User-Agent 已设置
	if options.UserAgent == "" {
		t.Error("Chrome142JA4 应该设置 User-Agent")
	}

	// 验证 Headers 已设置
	if len(options.Headers) == 0 {
		t.Error("Chrome142JA4 应该设置 Headers")
	}
}

// TestFirefoxJA4 测试 Firefox JA4 配置
func TestFirefoxJA4(t *testing.T) {
	options := fastls.Options{
		Headers: make(map[string]string),
	}

	ja4r.FirefoxJA4(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("FirefoxJA4 应该设置指纹")
	}

	// 验证指纹类型
	if !options.IsJa4() {
		t.Error("FirefoxJA4 应该设置 JA4 指纹")
	}

	// 验证 User-Agent 已设置
	if options.UserAgent == "" {
		t.Error("FirefoxJA4 应该设置 User-Agent")
	}
}

// TestChrome120JA4 测试 Chrome120 JA4 配置
func TestChrome120JA4(t *testing.T) {
	options := fastls.Options{
		Headers: make(map[string]string),
	}

	ja4r.Chrome120JA4(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("Chrome120JA4 应该设置指纹")
	}

	// 验证指纹类型
	if !options.IsJa4() {
		t.Error("Chrome120JA4 应该设置 JA4 指纹")
	}
}

// TestChromeJA4 测试 Chrome JA4 配置
func TestChromeJA4(t *testing.T) {
	options := fastls.Options{
		Headers: make(map[string]string),
	}

	ja4r.ChromeJA4(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("ChromeJA4 应该设置指纹")
	}

	// 验证指纹类型
	if !options.IsJa4() {
		t.Error("ChromeJA4 应该设置 JA4 指纹")
	}
}

// TestChromiumJA4 测试 Chromium JA4 配置
func TestChromiumJA4(t *testing.T) {
	options := fastls.Options{
		Headers: make(map[string]string),
	}

	ja4r.ChromiumJA4(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("ChromiumJA4 应该设置指纹")
	}

	// 验证指纹类型
	if !options.IsJa4() {
		t.Error("ChromiumJA4 应该设置 JA4 指纹")
	}
}

// TestSafariJA4 测试 Safari JA4 配置
func TestSafariJA4(t *testing.T) {
	options := fastls.Options{
		Headers: make(map[string]string),
	}

	ja4r.SafariJA4(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("SafariJA4 应该设置指纹")
	}

	// 验证指纹类型
	if !options.IsJa4() {
		t.Error("SafariJA4 应该设置 JA4 指纹")
	}
}

// TestWithChrome142JA4Request 测试使用 Chrome142 JA4 指纹发送请求
func TestWithChrome142JA4Request(t *testing.T) {
	client := fastls.NewClient()

	options := fastls.Options{
		Timeout: 30,
		Headers: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		},
	}

	// 使用 Chrome142 JA4 指纹
	ja4r.Chrome142JA4(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("指纹未设置")
	}
	if !options.IsJa4() {
		t.Error("应该使用 JA4 指纹")
	}
	if options.UserAgent == "" {
		t.Error("User-Agent未设置")
	}

	resp, err := client.Do("https://tls.peet.ws/api/all", options, "GET")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.Status != 200 {
		t.Errorf("期望状态码 200, 得到 %d", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}

	// 解析响应，验证 JA4R 指纹
	var apiResp struct {
		TLS struct {
			JA4R string `json:"ja4_r"`
			JA4  string `json:"ja4"`
			JA3  string `json:"ja3"`
		} `json:"tls"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		t.Fatalf("解析 JSON 失败: %v", err)
	}

	// 验证返回了 JA4R 指纹
	if apiResp.TLS.JA4R == "" {
		t.Error("API 应该返回 JA4R 指纹")
	}

	// 验证 JA4R 格式（应该以 t13d 开头）
	if !strings.HasPrefix(apiResp.TLS.JA4R, "t13d") {
		t.Errorf("返回的 JA4R 格式不正确，应该以 't13d' 开头，得到: %s", apiResp.TLS.JA4R)
	}

	// 验证 JA4R 格式包含下划线分隔符
	if strings.Count(apiResp.TLS.JA4R, "_") < 3 {
		t.Errorf("返回的 JA4R 格式不正确，应该包含至少3个下划线分隔符，得到: %s", apiResp.TLS.JA4R)
	}

	// 记录设置的 JA4 指纹和返回的 JA4R
	setFingerprint := options.GetFingerprintValue()
	t.Logf("设置的 JA4 指纹: %s", setFingerprint)
	t.Logf("返回的 JA4R: %s", apiResp.TLS.JA4R)
	if apiResp.TLS.JA4 != "" {
		t.Logf("返回的 JA4: %s", apiResp.TLS.JA4)
	}
	if apiResp.TLS.JA3 != "" {
		t.Logf("返回的 JA3: %s", apiResp.TLS.JA3)
	}

	// 验证确实使用了 JA4 指纹（通过检查返回的 JA4R 不为空）
	if apiResp.TLS.JA4R == "" {
		t.Error("使用 JA4 指纹请求时，API 应该返回 JA4R 指纹")
	}
}

// TestWithFirefoxJA4Request 测试使用 Firefox JA4 指纹发送请求
func TestWithFirefoxJA4Request(t *testing.T) {
	client := fastls.NewClient()

	options := fastls.Options{
		Timeout: 30,
		Headers: make(map[string]string),
	}

	// 使用 Firefox JA4 指纹
	ja4r.FirefoxJA4(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("指纹未设置")
	}
	if !options.IsJa4() {
		t.Error("应该使用 JA4 指纹")
	}

	resp, err := client.Do("https://tls.peet.ws/api/all", options, "GET")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.Status != 200 {
		t.Errorf("期望状态码 200, 得到 %d", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}

	// 解析响应，验证 JA4R 指纹
	var apiResp struct {
		TLS struct {
			JA4R string `json:"ja4_r"`
			JA4  string `json:"ja4"`
			JA3  string `json:"ja3"`
		} `json:"tls"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		t.Fatalf("解析 JSON 失败: %v", err)
	}

	// 验证返回了 JA4R 指纹
	if apiResp.TLS.JA4R == "" {
		t.Error("API 应该返回 JA4R 指纹")
	}

	// 验证 JA4R 格式（应该以 t13d 开头）
	if !strings.HasPrefix(apiResp.TLS.JA4R, "t13d") {
		t.Errorf("返回的 JA4R 格式不正确，应该以 't13d' 开头，得到: %s", apiResp.TLS.JA4R)
	}

	// 验证 JA4R 格式包含下划线分隔符
	if strings.Count(apiResp.TLS.JA4R, "_") < 3 {
		t.Errorf("返回的 JA4R 格式不正确，应该包含至少3个下划线分隔符，得到: %s", apiResp.TLS.JA4R)
	}

	// 记录设置的 JA4 指纹和返回的 JA4R
	setFingerprint := options.GetFingerprintValue()
	t.Logf("设置的 JA4 指纹: %s", setFingerprint)
	t.Logf("返回的 JA4R: %s", apiResp.TLS.JA4R)
	if apiResp.TLS.JA4 != "" {
		t.Logf("返回的 JA4: %s", apiResp.TLS.JA4)
	}
	if apiResp.TLS.JA3 != "" {
		t.Logf("返回的 JA3: %s", apiResp.TLS.JA3)
	}

	// 验证确实使用了 JA4 指纹（通过检查返回的 JA4R 不为空）
	if apiResp.TLS.JA4R == "" {
		t.Error("使用 JA4 指纹请求时，API 应该返回 JA4R 指纹")
	}
}

// TestJa4FingerprintInterface 测试 JA4 指纹接口实现
func TestJa4FingerprintInterface(t *testing.T) {
	var fp fastls.Fingerprint = fastls.Ja4Fingerprint{
		FingerprintValue: "t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603",
	}

	// 测试接口方法
	if fp.Type() != "ja4r" {
		t.Errorf("期望类型 'ja4r', 得到 '%s'", fp.Type())
	}

	expectedValue := "t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603"
	if fp.Value() != expectedValue {
		t.Errorf("期望值 '%s', 得到 '%s'", expectedValue, fp.Value())
	}

	if fp.IsEmpty() {
		t.Error("非空指纹不应该返回 true")
	}
}

// TestValidateFingerprintWithJA4 测试验证 JA4 指纹
func TestValidateFingerprintWithJA4(t *testing.T) {
	options := fastls.Options{
		Fingerprint: fastls.Ja4Fingerprint{
			FingerprintValue: "t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603",
		},
	}

	// ValidateFingerprint 应该不返回错误（JA4R 已支持）
	if err := options.ValidateFingerprint(); err != nil {
		t.Errorf("验证 JA4 指纹不应该返回错误: %v", err)
	}
}

// TestJa4VsJa3 测试 JA4 和 JA3 指纹的区别
func TestJa4VsJa3(t *testing.T) {
	// 测试 JA4 指纹
	ja4Options := fastls.Options{
		Fingerprint: fastls.Ja4Fingerprint{
			FingerprintValue: "t13d5911_002f,0032,0033_000a,000b,000d_0403,0503,0603",
		},
	}

	if !ja4Options.IsJa4() {
		t.Error("应该识别为 JA4 指纹")
	}
	if ja4Options.IsJa3() {
		t.Error("不应该识别为 JA3 指纹")
	}
	if ja4Options.GetFingerprintType() != "ja4r" {
		t.Errorf("期望类型 'ja4r', 得到 '%s'", ja4Options.GetFingerprintType())
	}

	// 测试 JA3 指纹
	ja3Options := fastls.Options{
		Fingerprint: fastls.Ja3Fingerprint{
			FingerprintValue: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-27-51-13-0-11-10-5-18-35-43-45-17613-23-65037-16-41,4588-29-23-24,0",
		},
	}

	if ja3Options.IsJa4() {
		t.Error("不应该识别为 JA4 指纹")
	}
	if !ja3Options.IsJa3() {
		t.Error("应该识别为 JA3 指纹")
	}
	if ja3Options.GetFingerprintType() != "ja3" {
		t.Errorf("期望类型 'ja3', 得到 '%s'", ja3Options.GetFingerprintType())
	}
}

// TestJA4RequestResult 测试 JA4 请求结果的完整性
func TestJA4RequestResult(t *testing.T) {
	client := fastls.NewClient()

	options := fastls.Options{
		Timeout: 30,
		Headers: make(map[string]string),
	}

	// 使用 Chrome142 JA4 指纹
	ja4r.Chrome142JA4(&options)

	// 记录设置的指纹
	setFingerprint := options.GetFingerprintValue()
	t.Logf("设置的 JA4 指纹: %s", setFingerprint)

	resp, err := client.Do("https://tls.peet.ws/api/all", options, "GET")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}

	// 解析完整的响应
	var apiResp struct {
		TLS struct {
			JA4R string `json:"ja4_r"`
			JA4  string `json:"ja4"`
			JA3  string `json:"ja3"`
		} `json:"tls"`
		UserAgent string `json:"user_agent"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		t.Fatalf("解析 JSON 失败: %v", err)
	}

	// 验证 JA4R 结果
	if apiResp.TLS.JA4R == "" {
		t.Error("API 应该返回 JA4R 指纹")
	}

	// 验证 JA4R 格式
	if !strings.HasPrefix(apiResp.TLS.JA4R, "t13d") {
		t.Errorf("JA4R 应该以 't13d' 开头，得到: %s", apiResp.TLS.JA4R)
	}

	// 验证格式：t13d<num>_<cipher_suites>_<extensions>_<signature_algorithms>
	parts := strings.Split(apiResp.TLS.JA4R, "_")
	if len(parts) < 4 {
		t.Errorf("JA4R 格式不正确，应该包含至少4个部分（用下划线分隔），得到: %d 个部分", len(parts))
	}

	// 验证第一部分格式（t13d<num>）
	if len(parts[0]) < 5 {
		t.Errorf("JA4R 第一部分格式不正确，应该至少5个字符（t13d<num>），得到: %s", parts[0])
	}

	// 记录所有结果
	t.Logf("请求结果:")
	t.Logf("  设置的 JA4 指纹: %s", setFingerprint)
	t.Logf("  返回的 JA4R: %s", apiResp.TLS.JA4R)
	if apiResp.TLS.JA4 != "" {
		t.Logf("  返回的 JA4: %s", apiResp.TLS.JA4)
	}
	if apiResp.TLS.JA3 != "" {
		t.Logf("  返回的 JA3: %s", apiResp.TLS.JA3)
	}
	if apiResp.UserAgent != "" {
		t.Logf("  检测到的 User-Agent: %s", apiResp.UserAgent)
	}
}

// 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
