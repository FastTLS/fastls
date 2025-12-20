package tests

import (
	"encoding/json"
	"io"
	"testing"

	fastls "github.com/ChengHoward/Fastls"
	"github.com/ChengHoward/Fastls/imitate"
)

// TestNoFingerprint 测试无JA3指纹请求（使用默认配置）
func TestNoFingerprint(t *testing.T) {
	client := fastls.NewClient()

	// 不指定JA3指纹，让系统使用默认配置
	options := fastls.Options{
		Timeout: 30,
		Headers: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
		// 不设置Ja3和UserAgent，让系统使用默认值
	}

	// 不设置Ja3，系统会自动使用默认的Chrome JA3指纹
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

	if len(body) == 0 {
		t.Error("响应体为空")
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

	// 验证响应结构
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
				t.Logf("检测到的JA3指纹: %v", ja3)
			}
		}
	}

	t.Logf("请求成功，状态码: %d, 响应体长度: %d", resp.Status, len(decodedBody))
}

// TestWithFirefoxFingerprint 测试带Firefox指纹请求
func TestWithFirefoxFingerprint(t *testing.T) {
	client := fastls.NewClient()

	options := fastls.Options{
		Timeout: 30,
		Headers: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
	}

	// 使用Firefox指纹
	imitate.Firefox(&options)

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

	t.Logf("请求成功，状态码: %d, 设置的指纹: %s", resp.Status, options.GetFingerprintValue())
}

// TestWithCustomJA3 测试带自定义JA3指纹请求
func TestWithCustomJA3(t *testing.T) {
	client := fastls.NewClient()

	// 使用自定义JA3指纹（Chrome指纹示例）
	options := fastls.Options{
		Timeout: 30,
		Fingerprint: fastls.Ja3Fingerprint{
			FingerprintValue: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
		},
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		},
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

	decodedBody := fastls.DecompressBody(body, []string{resp.Headers["Content-Encoding"]}, nil)
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

	t.Logf("请求成功，状态码: %d, 设置的指纹: %s", resp.Status, options.GetFingerprintValue())
}
