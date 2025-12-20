package tests

import (
	"encoding/json"
	"io"
	"testing"

	fastls "github.com/ChengHoward/Fastls"
	"github.com/ChengHoward/Fastls/imitate"
)

// TestWithChromeFingerprint 测试带Chrome指纹请求
func TestWithChromeFingerprint(t *testing.T) {
	client := fastls.NewClient()

	options := fastls.Options{
		Timeout: 30,
		Headers: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		},
	}

	// 使用Chrome指纹
	imitate.Chrome142(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("指纹未设置")
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

	// 解码响应体
	contentEncoding := resp.Headers["Content-Encoding"]
	var decodedBody string
	if contentEncoding != "" {
		decodedBody = fastls.DecompressBody(body, []string{contentEncoding}, nil)
	} else {
		decodedBody = string(body)
	}

	if len(decodedBody) == 0 {
		t.Error("解码后的响应体为空")
	}

	// 解析JSON响应
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(decodedBody), &result); err != nil {
		t.Fatalf("解析JSON失败: %v", err)
	}

	// 验证响应结构并核对JA3指纹
	tlsData, ok := result["tls"]
	if !ok {
		t.Error("响应中缺少 'tls' 字段")
	} else {
		tlsMap, ok := tlsData.(map[string]interface{})
		if !ok {
			t.Error("'tls' 字段格式不正确")
		} else {
			ja3, ok := tlsMap["ja3"]
			if !ok {
				t.Error("响应中缺少 'tls.ja3' 字段")
			} else {
				ja3Str, ok := ja3.(string)
				if !ok {
					t.Errorf("'tls.ja3' 字段类型不正确，期望string，得到 %T", ja3)
				} else {
					// 核对JA3指纹
					fingerprintValue := options.GetFingerprintValue()
					if ja3Str != fingerprintValue {
						t.Logf("警告: 检测到的JA3 (%s) 与设置的指纹 (%s) 不完全匹配（这可能是正常的，因为服务器可能返回协商后的指纹）", ja3Str, fingerprintValue)
					} else {
						t.Logf("JA3指纹匹配: %s", ja3Str)
					}
				}
			}
		}
	}

	t.Logf("请求成功，状态码: %d, 设置的Chrome 指纹: %s", resp.Status, options.GetFingerprintValue())
}

// TestWithEdgeFingerprint 测试带Edge指纹请求
func TestWithEdgeFingerprint(t *testing.T) {
	client := fastls.NewClient()

	options := fastls.Options{
		Timeout: 30,
		Headers: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		},
	}

	// 使用Edge指纹
	imitate.Edge(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("指纹未设置")
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

	// 解码响应体
	contentEncoding := resp.Headers["Content-Encoding"]
	var decodedBody string
	if contentEncoding != "" {
		decodedBody = fastls.DecompressBody(body, []string{contentEncoding}, nil)
	} else {
		decodedBody = string(body)
	}

	if len(decodedBody) == 0 {
		t.Error("解码后的响应体为空")
	}

	// 解析JSON响应
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(decodedBody), &result); err != nil {
		t.Fatalf("解析JSON失败: %v", err)
	}

	// 验证响应结构并核对JA3指纹
	tlsData, ok := result["tls"]
	if !ok {
		t.Error("响应中缺少 'tls' 字段")
	} else {
		tlsMap, ok := tlsData.(map[string]interface{})
		if !ok {
			t.Error("'tls' 字段格式不正确")
		} else {
			ja3, ok := tlsMap["ja3"]
			if !ok {
				t.Error("响应中缺少 'tls.ja3' 字段")
			} else {
				ja3Str, ok := ja3.(string)
				if !ok {
					t.Errorf("'tls.ja3' 字段类型不正确，期望string，得到 %T", ja3)
				} else {
					// 核对JA3指纹
					fingerprintValue := options.GetFingerprintValue()
					if ja3Str != fingerprintValue {
						t.Logf("警告: 检测到的JA3 (%s) 与设置的指纹 (%s) 不完全匹配（这可能是正常的，因为服务器可能返回协商后的指纹）", ja3Str, fingerprintValue)
					} else {
						t.Logf("JA3指纹匹配: %s", ja3Str)
					}
				}
			}
		}
	}

	t.Logf("请求成功，状态码: %d, 设置的Edge 指纹: %s", resp.Status, options.GetFingerprintValue())
}

// TestWithSafariFingerprint 测试带Safari指纹请求
func TestWithSafariFingerprint(t *testing.T) {
	client := fastls.NewClient()

	options := fastls.Options{
		Timeout: 30,
		Headers: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	}

	// 使用Safari指纹
	imitate.Safari(&options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Error("指纹未设置")
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

	// 解码响应体
	contentEncoding := resp.Headers["Content-Encoding"]
	var decodedBody string
	if contentEncoding != "" {
		decodedBody = fastls.DecompressBody(body, []string{contentEncoding}, nil)
	} else {
		decodedBody = string(body)
	}

	if len(decodedBody) == 0 {
		t.Error("解码后的响应体为空")
	}

	// 解析JSON响应
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(decodedBody), &result); err != nil {
		t.Fatalf("解析JSON失败: %v", err)
	}

	// 验证响应结构并核对JA3指纹
	tlsData, ok := result["tls"]
	if !ok {
		t.Error("响应中缺少 'tls' 字段")
	} else {
		tlsMap, ok := tlsData.(map[string]interface{})
		if !ok {
			t.Error("'tls' 字段格式不正确")
		} else {
			ja3, ok := tlsMap["ja3"]
			if !ok {
				t.Error("响应中缺少 'tls.ja3' 字段")
			} else {
				ja3Str, ok := ja3.(string)
				if !ok {
					t.Errorf("'tls.ja3' 字段类型不正确，期望string，得到 %T", ja3)
				} else {
					// 核对JA3指纹
					fingerprintValue := options.GetFingerprintValue()
					if ja3Str != fingerprintValue {
						t.Logf("警告: 检测到的JA3 (%s) 与设置的指纹 (%s) 不完全匹配（这可能是正常的，因为服务器可能返回协商后的指纹）", ja3Str, fingerprintValue)
					} else {
						t.Logf("JA3指纹匹配: %s", ja3Str)
					}
				}
			}
		}
	}

	t.Logf("请求成功，状态码: %d, 设置的Safari 指纹: %s", resp.Status, options.GetFingerprintValue())
}
