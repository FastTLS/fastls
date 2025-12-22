package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestFetchAPI 测试HTTP API调用fetch服务
// 注意：此测试需要先启动fetch_server.go服务
func TestFetchAPI(t *testing.T) {
	// 假设fetch服务运行在 http://localhost:8800
	apiURL := "http://localhost:8800/fetch"

	// 构建请求
	requestData := map[string]interface{}{
		"url":    "https://tls.peet.ws/api/all",
		"method": "GET",
		"headers": map[string]string{
			"Accept": "application/json",
		},
		"timeout": 30,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		t.Fatalf("序列化请求失败: %v", err)
	}

	// 发送POST请求
	resp, err := http.Post(apiURL, "application/json",
		bytes.NewBuffer(jsonData))
	if err != nil {
		t.Skipf("无法连接到fetch服务，请先启动fetch_server.go: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("期望状态码 200, 得到 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}

	// 解析响应
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}

	// 验证响应结构
	ok, okExists := result["ok"]
	if !okExists {
		t.Error("响应中缺少 'ok' 字段")
	} else if okBool, ok := ok.(bool); !ok || !okBool {
		t.Error("响应中 'ok' 字段应为 true")
	}

	status, statusExists := result["status"]
	if !statusExists {
		t.Error("响应中缺少 'status' 字段")
	} else if statusFloat, ok := status.(float64); !ok || statusFloat != 200 {
		t.Errorf("期望状态码 200, 得到 %v", status)
	}

	t.Logf("API测试成功，响应: %+v", result)
}

// TestHealthCheck 测试健康检查端点
func TestHealthCheck(t *testing.T) {
	healthURL := "http://localhost:8800/health"

	resp, err := http.Get(healthURL)
	if err != nil {
		t.Skipf("无法连接到fetch服务，请先启动fetch_server.go: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("期望状态码 200, 得到 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}

	if status, ok := result["status"]; !ok || status != "ok" {
		t.Errorf("期望状态 'ok', 得到 %v", status)
	}

	t.Logf("健康检查测试成功")
}
