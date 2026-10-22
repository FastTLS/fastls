package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	targetURL   = flag.String("url", "", "目标URL (必需)")
	method      = flag.String("method", "GET", "HTTP方法")
	concurrency = flag.Int("c", 10, "并发数")
	duration    = flag.Duration("d", 10*time.Second, "测试持续时间")
	requests    = flag.Int("n", 0, "总请求数 (0表示按持续时间运行)")
	proxyURL    = flag.String("proxy", "", "代理地址 (例如: http://127.0.0.1:8080)")
	timeout     = flag.Duration("timeout", 30*time.Second, "请求超时时间")
	headerStr   = flag.String("H", "", "自定义请求头 (格式: Key:Value, 多个用分号分隔)")
	insecure    = flag.Bool("k", false, "忽略SSL证书错误 (不安全)")
	verbose     = flag.Bool("v", false, "详细输出模式")
	quiet       = flag.Bool("q", false, "安静模式")
)

type Stats struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	TotalDuration   int64 // 纳秒
	MinDuration     int64
	MaxDuration     int64
	TotalBytes      int64
	StatusCodes     map[int]int64
	mu              sync.Mutex
}

func NewStats() *Stats {
	return &Stats{
		StatusCodes: make(map[int]int64),
		MinDuration: int64(time.Hour),
	}
}

func (s *Stats) RecordRequest(duration time.Duration, statusCode int, bytes int64, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	atomic.AddInt64(&s.TotalRequests, 1)
	if success {
		atomic.AddInt64(&s.SuccessRequests, 1)
	} else {
		atomic.AddInt64(&s.FailedRequests, 1)
	}

	durNs := int64(duration)
	atomic.AddInt64(&s.TotalDuration, durNs)

	// 更新最小和最大响应时间
	for {
		oldMin := atomic.LoadInt64(&s.MinDuration)
		if durNs >= oldMin {
			break
		}
		if atomic.CompareAndSwapInt64(&s.MinDuration, oldMin, durNs) {
			break
		}
	}

	for {
		oldMax := atomic.LoadInt64(&s.MaxDuration)
		if durNs <= oldMax {
			break
		}
		if atomic.CompareAndSwapInt64(&s.MaxDuration, oldMax, durNs) {
			break
		}
	}

	atomic.AddInt64(&s.TotalBytes, bytes)
	s.StatusCodes[statusCode]++
}

func (s *Stats) Print(elapsed time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := atomic.LoadInt64(&s.TotalRequests)
	success := atomic.LoadInt64(&s.SuccessRequests)
	failed := atomic.LoadInt64(&s.FailedRequests)
	totalBytes := atomic.LoadInt64(&s.TotalBytes)
	totalDur := atomic.LoadInt64(&s.TotalDuration)

	if total == 0 || elapsed <= 0 {
		fmt.Println("没有完成任何请求")
		return
	}

	avgDuration := time.Duration(totalDur / total)
	minDuration := time.Duration(atomic.LoadInt64(&s.MinDuration))
	maxDuration := time.Duration(atomic.LoadInt64(&s.MaxDuration))
	successRate := float64(success) / float64(total) * 100
	qps := float64(total) / elapsed.Seconds()
	elapsed = elapsed.Round(time.Millisecond)

	fmt.Println("\n=== 压力测试统计 ===")
	fmt.Printf("总请求数:     %d\n", total)
	fmt.Printf("成功请求:     %d (%.2f%%)\n", success, successRate)
	fmt.Printf("失败请求:     %d (%.2f%%)\n", failed, 100-successRate)
	fmt.Printf("测试耗时:     %v\n", elapsed)
	fmt.Printf("QPS:          %.2f\n", qps)
	fmt.Printf("平均响应时间: %v\n", avgDuration)
	fmt.Printf("最小响应时间: %v\n", minDuration)
	fmt.Printf("最大响应时间: %v\n", maxDuration)
	fmt.Printf("总传输字节:   %d (%.2f KB)\n", totalBytes, float64(totalBytes)/1024)

	fmt.Println("\n状态码分布:")
	for code, count := range s.StatusCodes {
		percentage := float64(count) / float64(total) * 100
		fmt.Printf("  %d: %d (%.2f%%)\n", code, count, percentage)
	}
}

func makeRequest(client *http.Client, req *http.Request, stats *Stats) {
	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	var statusCode int
	var bytes int64
	success := false

	if err != nil {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "请求失败: %v\n", err)
		}
		statusCode = 0
	} else {
		defer resp.Body.Close()
		statusCode = resp.StatusCode
		bodyBytes, _ := io.ReadAll(resp.Body)
		bytes = int64(len(bodyBytes))
		success = statusCode >= 200 && statusCode < 400

		if *verbose {
			fmt.Printf("[%d] %s - %v - %d bytes\n", statusCode, req.URL.String(), duration, bytes)
		}
	}

	stats.RecordRequest(duration, statusCode, bytes, success)
}

func main() {
	flag.Parse()

	if *targetURL == "" {
		fmt.Fprintf(os.Stderr, "错误: 必须指定目标URL\n")
		fmt.Fprintf(os.Stderr, "使用 -h 查看帮助信息\n")
		os.Exit(1)
	}

	// 创建 HTTP 客户端
	client := &http.Client{
		Timeout: *timeout,
	}

	// 创建 Transport
	transport := &http.Transport{
		// 强制使用 HTTP/1.1，避免通过代理时 HTTP/2 协议问题
		ForceAttemptHTTP2:  false,
		DisableCompression: false,
	}

	// 设置代理
	if *proxyURL != "" {
		proxy, err := url.Parse(*proxyURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 无效的代理地址: %v\n", err)
			os.Exit(1)
		}
		transport.Proxy = http.ProxyURL(proxy)
		// 通过代理时强制使用 HTTP/1.1
		transport.ForceAttemptHTTP2 = false
	}

	// 配置 TLS（忽略证书错误并强制使用 HTTP/1.1）
	transport.TLSClientConfig = &tls.Config{
		// 强制使用 HTTP/1.1（在 TLS ALPN 中只声明 http/1.1，不声明 h2）
		// 这样可以避免通过代理时服务器协商 HTTP/2 导致的问题
		NextProtos: []string{"http/1.1"},
	}

	// 忽略证书错误
	if *insecure {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	client.Transport = transport

	// 创建请求
	req, err := http.NewRequest(*method, *targetURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 创建请求失败: %v\n", err)
		os.Exit(1)
	}

	// 设置请求头
	if *headerStr != "" {
		headers := splitHeaders(*headerStr)
		for _, h := range headers {
			parts := splitHeader(h)
			if len(parts) == 2 {
				req.Header.Set(parts[0], parts[1])
			}
		}
	}

	// 如果使用代理，添加请求头强制 MITM 使用 HTTP/1.1
	// 这样可以避免 MITM 代理尝试使用 HTTP/2 导致的问题
	if *proxyURL != "" {
		// 通过 CONNECT 请求头告诉 MITM 代理强制使用 HTTP/1.1
		// 注意：这个请求头需要在 CONNECT 阶段设置，但标准库的 http.Client
		// 会自动处理 CONNECT，我们无法直接设置 CONNECT 请求的头部
		// 所以我们在实际请求中设置，MITM 会在 CONNECT 阶段读取
		req.Header.Set("X-Mitm-Force-HTTP11", "true")
		// 移除可能触发 HTTP/2 的头部
		req.Header.Del("Upgrade")
		req.Header.Del("HTTP2-Settings")
	}

	// 统计信息
	stats := NewStats()

	// 控制并发
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *concurrency)

	// 控制测试时间或请求数
	stopChan := make(chan struct{})
	var done int64

	// 如果指定了请求数，设置停止条件
	if *requests > 0 {
		go func() {
			for atomic.LoadInt64(&done) < int64(*requests) {
				time.Sleep(10 * time.Millisecond)
			}
			close(stopChan)
		}()
	} else {
		// 按持续时间运行
		go func() {
			time.Sleep(*duration)
			close(stopChan)
		}()
	}

	if !*quiet {
		fmt.Printf("开始压力测试...\n")
		fmt.Printf("目标URL: %s\n", *targetURL)
		fmt.Printf("HTTP方法: %s\n", *method)
		fmt.Printf("并发数: %d\n", *concurrency)
		if *requests > 0 {
			fmt.Printf("总请求数: %d\n", *requests)
		} else {
			fmt.Printf("持续时间: %v\n", *duration)
		}
		if *proxyURL != "" {
			fmt.Printf("代理: %s\n", *proxyURL)
		}
		if *insecure {
			fmt.Printf("SSL证书验证: 已禁用 (不安全)\n")
		}
		fmt.Println()
	}

	startTime := time.Now()

	// 启动工作协程
	for {
		select {
		case <-stopChan:
			// 等待所有请求完成
			wg.Wait()
			stats.Print(time.Since(startTime))
			return
		default:
			// 获取信号量
			semaphore <- struct{}{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				defer func() { <-semaphore }()

				// 检查是否达到请求数限制
				if *requests > 0 {
					current := atomic.AddInt64(&done, 1)
					if current > int64(*requests) {
						return
					}
				}

				// 创建新的请求（复用请求对象）
				newReq := req.Clone(req.Context())
				makeRequest(client, newReq, stats)
			}()
		}
	}
}

// splitHeaders 分割多个请求头字符串 "Key1:Value1;Key2:Value2"
func splitHeaders(headers string) []string {
	if headers == "" {
		return []string{}
	}
	var result []string
	current := ""
	for _, char := range headers {
		if char == ';' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// splitHeader 分割请求头字符串 "Key:Value"
func splitHeader(header string) []string {
	for i, char := range header {
		if char == ':' {
			key := header[:i]
			value := header[i+1:]
			// 去除前导空格
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
			return []string{key, value}
		}
	}
	return []string{header}
}
