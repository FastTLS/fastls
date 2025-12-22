package tests

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
	"github.com/gorilla/websocket"
)

// testWebSocketConnection 测试WebSocket连接的通用函数
func testWebSocketConnection(t *testing.T, wsClient *fastls.WebSocketClient, wsURL string) {
	// 连接到WebSocket服务器
	wsConn, resp, err := wsClient.Connect(wsURL)
	if err != nil {
		t.Fatalf("WebSocket连接失败: %v", err)
	}
	defer wsConn.Close()

	if resp == nil {
		t.Fatal("响应为空")
	}

	if resp.StatusCode != 101 {
		t.Errorf("期望状态码 101 (Switching Protocols), 得到 %d", resp.StatusCode)
	}

	// 设置读取超时
	wsConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// 先接收一个消息（如果有）
	wsConn.ReadMessage()

	// 发送消息
	message := []byte("Hello, WebSocket!")
	err = wsConn.WriteMessage(websocket.TextMessage, message)
	if err != nil {
		t.Fatalf("发送消息失败: %v", err)
	}

	// 接收回显消息
	_, received, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("接收消息失败: %v", err)
	}

	if string(received) != string(message) {
		t.Errorf("期望收到消息 %s, 得到 %s", string(message), string(received))
	}

	t.Logf("WebSocket测试成功，发送: %s, 接收: %s", string(message), string(received))
}

// TestWebSocketWithFingerprint 测试使用TLS指纹伪造的WebSocket连接
func TestWebSocketWithFingerprint(t *testing.T) {
	// WebSocket服务器地址（示例使用echo.websocket.org）
	wsURL := "wss://echo.websocket.org"

	// 创建Options并使用imitate.Firefox设置指纹
	options := fastls.Options{
		Headers: make(map[string]string),
	}
	options.Headers["Origin"] = "https://echo.websocket.org"

	// 使用imitate.Firefox设置指纹和User-Agent
	imitate.Firefox(&options)

	// 使用NewWebSocketClientWithOptions创建客户端
	wsClient := fastls.NewWebSocketClientWithOptions(options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Fatal("指纹未设置")
	}

	t.Logf("使用指纹类型: %s, 指纹值: %s", options.Fingerprint.Type(), options.Fingerprint.Value())
	t.Logf("User-Agent: %s", options.UserAgent)

	// 执行测试
	testWebSocketConnection(t, wsClient, wsURL)
}

// TestWebSocketWithoutFingerprint 测试不使用TLS指纹伪造的WebSocket连接（使用标准TLS）
func TestWebSocketWithoutFingerprint(t *testing.T) {
	// WebSocket服务器地址（示例使用echo.websocket.org）
	wsURL := "wss://echo.websocket.org"

	// User-Agent
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"

	// 创建WebSocket客户端，不使用指纹（传入nil）
	headers := http.Header{}
	headers.Set("User-Agent", userAgent)
	headers.Set("Origin", "https://echo.websocket.org")

	// 传入nil指纹，将使用标准TLS
	wsClient := fastls.NewWebSocketClient(nil, userAgent, headers)

	// 验证指纹为空
	if wsClient.Fingerprint != nil && !wsClient.Fingerprint.IsEmpty() {
		t.Fatal("指纹应该为空，但实际已设置")
	}

	t.Logf("使用标准TLS（无指纹伪造）")
	t.Logf("User-Agent: %s", userAgent)

	// 执行测试
	testWebSocketConnection(t, wsClient, wsURL)
}

// TestWebSocketGMGN 测试访问 gmgn.ai 的 WebSocket 并发送订阅消息
func TestWebSocketGMGN(t *testing.T) {
	// WebSocket服务器地址
	wsURL := "wss://gmgn.ai/ws?device_id=280d7602-78db-474d-8f3f-33df34536f1c&fp_did=f743ac1f515d957aebcf069c70abd42f&client_id=gmgn_web_20251210-8614-9648c63&from_app=gmgn&app_ver=20251210-8614-9648c63&tz_name=Asia%2FShanghai&tz_offset=28800&app_lang=zh-CN&os=web&worker=0&uuid=7c8e81976f342c11&reconnect=0"

	// 创建Options并使用imitate.Chrome设置指纹（模拟浏览器）
	options := fastls.Options{
		Headers: make(map[string]string),
	}
	options.Headers["Origin"] = "https://gmgn.ai"

	// 使用Chrome指纹
	imitate.Chrome142(&options)

	// 使用NewWebSocketClientWithOptions创建客户端
	wsClient := fastls.NewWebSocketClientWithOptions(options)

	// 验证指纹已设置
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		t.Fatal("指纹未设置")
	}

	t.Logf("使用指纹类型: %s, 指纹值: %s", options.Fingerprint.Type(), options.Fingerprint.Value())
	t.Logf("User-Agent: %s", options.UserAgent)

	// 连接到WebSocket服务器
	wsConn, resp, err := wsClient.Connect(wsURL)
	if err != nil {
		t.Fatalf("WebSocket连接失败: %v", err.Error())
	}
	defer wsConn.Close()

	if resp == nil {
		t.Fatal("响应为空")
	}

	if resp.StatusCode != 101 {
		t.Errorf("期望状态码 101 (Switching Protocols), 得到 %d", resp.StatusCode)
	}

	// 设置读取超时
	wsConn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 准备要发送的消息
	message := map[string]interface{}{
		"action":  "subscribe",
		"channel": "wallet_balance",
		"id":      "4266787dee4d7ee4",
		"data": map[string]interface{}{
			"chain":   "sol",
			"address": "5G2FGp1aUAFDq1jrQSsvYbjK69vfqGLYyL4b8YZNGAEv",
		},
	}

	// 将消息转换为JSON
	messageJSON, err := json.Marshal(message)
	if err != nil {
		t.Fatalf("JSON序列化失败: %v", err)
	}

	t.Logf("发送消息: %s", string(messageJSON))

	// 发送消息
	err = wsConn.WriteMessage(websocket.TextMessage, messageJSON)
	if err != nil {
		t.Fatalf("发送消息失败: %v", err)
	}

	// 等待并接收响应（可能有多条消息）
	wsConn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 接收第一条响应消息
	_, received, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("接收消息失败: %v", err)
	}

	t.Logf("收到响应: %s", string(received))

	// 解析响应为JSON
	var response map[string]interface{}
	if err := json.Unmarshal(received, &response); err != nil {
		t.Fatalf("响应不是有效的JSON: %v, 原始响应: %s", err, string(received))
	}

	// 验证响应是有效的JSON对象
	if response == nil {
		t.Fatal("解析后的响应为空")
	}

	t.Logf("解析后的响应: %+v", response)

	// 可以继续接收更多消息（如果有）
	// 设置较短的超时，避免无限等待
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, additionalMsg, err := wsConn.ReadMessage()
		if err != nil {
			// 超时或连接关闭是正常的
			break
		}

		var additionalResponse map[string]interface{}
		if err := json.Unmarshal(additionalMsg, &additionalResponse); err == nil {
			t.Logf("收到额外消息: %+v", additionalResponse)
		} else {
			t.Logf("收到额外消息（非JSON）: %s", string(additionalMsg))
		}
	}

	// 验证连接成功
	if resp.StatusCode == 101 {
		t.Logf("WebSocket连接成功，已发送订阅消息并收到JSON响应")
	}
}

// TestWebSocketGMGNWithoutFingerprint 测试不使用TLS指纹伪造访问 gmgn.ai 的 WebSocket
func TestWebSocketGMGNWithoutFingerprint(t *testing.T) {
	// WebSocket服务器地址
	wsURL := "wss://gmgn.ai/ws?device_id=280d7602-78db-474d-8f3f-33df34536f1c&fp_did=f743ac1f515d957aebcf069c70abd42f&client_id=gmgn_web_20251210-8614-9648c63&from_app=gmgn&app_ver=20251210-8614-9648c63&tz_name=Asia%2FShanghai&tz_offset=28800&app_lang=zh-CN&os=web&worker=0&uuid=7c8e81976f342c11&reconnect=0"

	// User-Agent
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"

	// 创建WebSocket客户端，不使用指纹（传入nil）
	headers := http.Header{}
	headers.Set("User-Agent", userAgent)
	headers.Set("Origin", "https://gmgn.ai")

	// 传入nil指纹，将使用标准TLS
	wsClient := fastls.NewWebSocketClient(nil, userAgent, headers)

	// 验证指纹为空
	if wsClient.Fingerprint != nil && !wsClient.Fingerprint.IsEmpty() {
		t.Fatal("指纹应该为空，但实际已设置")
	}

	t.Logf("使用标准TLS（无指纹伪造）")
	t.Logf("User-Agent: %s", userAgent)

	// 连接到WebSocket服务器
	wsConn, resp, err := wsClient.Connect(wsURL)
	if err != nil {
		t.Fatalf("WebSocket连接失败: %v", err.Error())
	}
	defer wsConn.Close()

	if resp == nil {
		t.Fatal("响应为空")
	}

	if resp.StatusCode != 101 {
		t.Errorf("期望状态码 101 (Switching Protocols), 得到 %d", resp.StatusCode)
	}

	// 设置读取超时
	wsConn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 准备要发送的消息
	message := map[string]interface{}{
		"action":  "subscribe",
		"channel": "wallet_balance",
		"id":      "4266787dee4d7ee4",
		"data": map[string]interface{}{
			"chain":   "sol",
			"address": "5G2FGp1aUAFDq1jrQSsvYbjK69vfqGLYyL4b8YZNGAEv",
		},
	}

	// 将消息转换为JSON
	messageJSON, err := json.Marshal(message)
	if err != nil {
		t.Fatalf("JSON序列化失败: %v", err)
	}

	t.Logf("发送消息: %s", string(messageJSON))

	// 发送消息
	err = wsConn.WriteMessage(websocket.TextMessage, messageJSON)
	if err != nil {
		t.Fatalf("发送消息失败: %v", err)
	}

	// 等待并接收响应（可能有多条消息）
	wsConn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 接收第一条响应消息
	_, received, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("接收消息失败: %v", err)
	}

	t.Logf("收到响应: %s", string(received))

	// 解析响应为JSON
	var response map[string]interface{}
	if err := json.Unmarshal(received, &response); err != nil {
		t.Fatalf("响应不是有效的JSON: %v, 原始响应: %s", err, string(received))
	}

	// 验证响应是有效的JSON对象
	if response == nil {
		t.Fatal("解析后的响应为空")
	}

	t.Logf("解析后的响应: %+v", response)

	// 可以继续接收更多消息（如果有）
	// 设置较短的超时，避免无限等待
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, additionalMsg, err := wsConn.ReadMessage()
		if err != nil {
			// 超时或连接关闭是正常的
			break
		}

		var additionalResponse map[string]interface{}
		if err := json.Unmarshal(additionalMsg, &additionalResponse); err == nil {
			t.Logf("收到额外消息: %+v", additionalResponse)
		} else {
			t.Logf("收到额外消息（非JSON）: %s", string(additionalMsg))
		}
	}

	// 验证连接成功
	if resp.StatusCode == 101 {
		t.Logf("WebSocket连接成功（无指纹），已发送订阅消息并收到JSON响应")
	}
}
