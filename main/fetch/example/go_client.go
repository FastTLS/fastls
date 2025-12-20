package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// FetchParams 请求参数
type FetchParams struct {
	URL             string            `json:"url"`
	Method          string            `json:"method,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	Proxy           string            `json:"proxy,omitempty"`
	Timeout         int               `json:"timeout,omitempty"`
	DisableRedirect bool              `json:"disableRedirect,omitempty"`
	UserAgent       string            `json:"userAgent,omitempty"`
	Fingerprint     map[string]string `json:"fingerprint,omitempty"`
	Browser         string            `json:"browser,omitempty"`
	Cookies         []interface{}     `json:"cookies,omitempty"`
}

// FastlsFetchClient Fetch客户端
type FastlsFetchClient struct {
	BaseURL string
	Client  *http.Client
}

// NewFastlsFetchClient 创建新的Fetch客户端
func NewFastlsFetchClient(baseURL string) *FastlsFetchClient {
	return &FastlsFetchClient{
		BaseURL: baseURL,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Health 健康检查
func (c *FastlsFetchClient) Health() (map[string]interface{}, error) {
	resp, err := c.Client.Get(c.BaseURL + "/health")
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %v", err)
	}

	return result, nil
}

// Fetch 发送HTTP请求
func (c *FastlsFetchClient) Fetch(params FetchParams) (map[string]interface{}, error) {
	jsonData, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal request failed: %v", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/fetch", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("create request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %v", err)
	}

	return result, nil
}

func main() {
	// 创建客户端
	client := NewFastlsFetchClient("http://localhost:8800")

	// 1. 健康检查
	fmt.Println("1. 健康检查:")
	health, err := client.Health()
	if err != nil {
		fmt.Printf("   错误: %v\n\n", err)
	} else {
		fmt.Printf("   %v\n\n", health)
	}

	// 2. 简单GET请求
	fmt.Println("2. 简单GET请求:")
	result, err := client.Fetch(FetchParams{
		URL: "https://tls.peet.ws/api/all",
	})
	if err != nil {
		fmt.Printf("   错误: %v\n\n", err)
	} else {
		fmt.Printf("   Status: %.0f\n", result["status"])
		fmt.Printf("   OK: %v\n", result["ok"])
		if body, ok := result["body"].(string); ok {
			fmt.Printf("   Body length: %d bytes\n\n", len(body))
		}
	}

	// 3. 使用浏览器指纹
	fmt.Println("3. 使用Chrome142指纹:")
	result, err = client.Fetch(FetchParams{
		URL:     "https://tls.peet.ws/api/all",
		Browser: "chrome142",
	})
	if err != nil {
		fmt.Printf("   错误: %v\n\n", err)
	} else {
		fmt.Printf("   Status: %.0f\n", result["status"])
		fmt.Printf("   OK: %v\n\n", result["ok"])
	}

	// 4. 使用自定义JA3指纹
	fmt.Println("4. 使用自定义JA3指纹:")
	result, err = client.Fetch(FetchParams{
		URL: "https://tls.peet.ws/api/all",
		Fingerprint: map[string]string{
			"type":  "ja3",
			"value": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
		},
	})
	if err != nil {
		fmt.Printf("   错误: %v\n\n", err)
	} else {
		fmt.Printf("   Status: %.0f\n", result["status"])
		fmt.Printf("   OK: %v\n\n", result["ok"])
	}

	// 5. POST请求
	fmt.Println("5. POST请求:")
	result, err = client.Fetch(FetchParams{
		URL:    "https://httpbin.org/post",
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: `{"key": "value"}`,
	})
	if err != nil {
		fmt.Printf("   错误: %v\n\n", err)
	} else {
		fmt.Printf("   Status: %.0f\n", result["status"])
		fmt.Printf("   OK: %v\n\n", result["ok"])
	}

	// 6. 带自定义请求头
	fmt.Println("6. 带自定义请求头:")
	result, err = client.Fetch(FetchParams{
		URL: "https://httpbin.org/headers",
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"Accept":          "application/json",
		},
	})
	if err != nil {
		fmt.Printf("   错误: %v\n\n", err)
	} else {
		fmt.Printf("   Status: %.0f\n", result["status"])
		fmt.Printf("   OK: %v\n\n", result["ok"])
	}
}
