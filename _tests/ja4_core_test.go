package tests

import (
	fastls "github.com/FastTLS/fastls"
	"testing"
)

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
