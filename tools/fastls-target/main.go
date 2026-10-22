package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	addr     = flag.String("addr", ":8080", "监听地址")
	response = flag.String("response", "200", "默认响应状态码")
	body     = flag.String("body", "", "响应体内容")
	delay    = flag.Duration("delay", 0, "响应延迟时间")
	verbose  = flag.Bool("v", false, "详细输出模式")
	quiet    = flag.Bool("q", false, "安静模式")
	tlsCert  = flag.String("cert", "", "TLS 证书文件路径（如果指定，将启用 HTTPS）")
	tlsKey   = flag.String("key", "", "TLS 私钥文件路径（必须与 -cert 一起使用）")
	tlsAuto  = flag.Bool("tls", false, "自动生成自签名证书并启用 HTTPS")
)

type Stats struct {
	TotalRequests    int64
	RequestsByMethod map[string]int64
	RequestsByPath   map[string]int64
	mu               sync.Mutex
}

func NewStats() *Stats {
	return &Stats{
		RequestsByMethod: make(map[string]int64),
		RequestsByPath:   make(map[string]int64),
	}
}

func (s *Stats) Record(method, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalRequests++
	s.RequestsByMethod[method]++
	s.RequestsByPath[path]++
}

func (s *Stats) Print() {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Println("\n=== 请求统计 ===")
	fmt.Printf("总请求数: %d\n", s.TotalRequests)

	fmt.Println("\n按方法统计:")
	for method, count := range s.RequestsByMethod {
		fmt.Printf("  %s: %d\n", method, count)
	}

	fmt.Println("\n按路径统计:")
	for path, count := range s.RequestsByPath {
		fmt.Printf("  %s: %d\n", path, count)
	}
}

var stats = NewStats()

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// 记录请求
	logRequest(r)

	// 延迟响应
	if *delay > 0 {
		time.Sleep(*delay)
	}

	// 解析状态码
	statusCode, err := strconv.Atoi(*response)
	if err != nil {
		statusCode = 200
	}

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Server", "fastls-target")
	w.Header().Set("X-Timestamp", time.Now().Format(time.RFC3339))

	// 读取请求体
	var requestBody string
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		requestBody = string(bodyBytes)
	}

	// 构建响应
	responseData := map[string]interface{}{
		"status":    statusCode,
		"message":   "OK",
		"method":    r.Method,
		"path":      r.URL.Path,
		"query":     r.URL.RawQuery,
		"headers":   convertHeaders(r.Header),
		"body":      requestBody,
		"remote":    r.RemoteAddr,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	// 记录统计
	stats.Record(r.Method, r.URL.Path)

	// 如果指定了自定义响应体，使用它
	if *body != "" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(*body))
		return
	}

	// 返回 JSON 响应
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(responseData)
}

func logRequest(r *http.Request) {
	if *quiet {
		return
	}

	// 读取请求体
	var requestBody string
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		requestBody = string(bodyBytes)
		r.Body = io.NopCloser(strings.NewReader(requestBody)) // 重新设置 Body，以便后续读取
	}

	if *verbose {
		fmt.Printf("\n[%s] %s %s\n", time.Now().Format("15:04:05"), r.Method, r.URL.String())
		fmt.Printf("  Remote: %s\n", r.RemoteAddr)
		fmt.Printf("  User-Agent: %s\n", r.UserAgent())
		fmt.Printf("  Headers:\n")
		for key, values := range r.Header {
			fmt.Printf("    %s: %s\n", key, strings.Join(values, ", "))
		}
		if requestBody != "" {
			fmt.Printf("  Body: %s\n", requestBody)
		}
	} else {
		fmt.Printf("[%s] %s %s - %s\n", time.Now().Format("15:04:05"), r.Method, r.URL.Path, r.RemoteAddr)
	}
}

func convertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		result[key] = strings.Join(values, ", ")
	}
	return result
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_requests": stats.TotalRequests,
		"by_method":      stats.RequestsByMethod,
		"by_path":        stats.RequestsByPath,
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"uptime":    time.Since(startTime).String(),
	})
}

var startTime = time.Now()

// generateSelfSignedCert 生成自签名证书
func generateSelfSignedCert() (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			Organization: []string{"Fastls Target Server"},
			Country:      []string{"CN"},
			CommonName:   "localhost",
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("创建证书失败: %v", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return cert, nil
}

// loadTLSCert 加载 TLS 证书
func loadTLSCert(certFile, keyFile string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %v", err)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("读取私钥文件失败: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %v", err)
	}

	return &cert, nil
}

func main() {
	flag.Parse()

	// 检查 TLS 参数
	useTLS := *tlsAuto || (*tlsCert != "" && *tlsKey != "")
	if (*tlsCert != "" && *tlsKey == "") || (*tlsCert == "" && *tlsKey != "") {
		log.Fatal("错误: -cert 和 -key 必须同时指定")
	}

	if !*quiet {
		fmt.Printf("Fastls Target Server\n")
		if useTLS {
			fmt.Printf("协议: HTTPS\n")
		} else {
			fmt.Printf("协议: HTTP\n")
		}
		fmt.Printf("监听地址: %s\n", *addr)
		fmt.Printf("默认响应: %s\n", *response)
		if *delay > 0 {
			fmt.Printf("响应延迟: %v\n", *delay)
		}
		fmt.Printf("\n端点:\n")
		fmt.Printf("  GET  /          - 返回请求信息\n")
		fmt.Printf("  GET  /health    - 健康检查\n")
		fmt.Printf("  GET  /stats     - 请求统计\n")
		fmt.Printf("  POST /          - 接收 POST 请求\n")
		fmt.Printf("  *    /*         - 接收所有请求\n")
		fmt.Println()
	}

	// 设置路由
	http.HandleFunc("/", handleRequest)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/stats", handleStats)

	// 配置 TLS
	var tlsConfig *tls.Config
	if useTLS {
		var cert *tls.Certificate
		var err error

		if *tlsAuto {
			if !*quiet {
				fmt.Printf("正在生成自签名证书...\n")
			}
			cert, err = generateSelfSignedCert()
			if err != nil {
				log.Fatalf("生成自签名证书失败: %v", err)
			}
			if !*quiet {
				fmt.Printf("自签名证书已生成（有效期1年）\n")
			}
		} else {
			if !*quiet {
				fmt.Printf("正在加载 TLS 证书: %s, %s\n", *tlsCert, *tlsKey)
			}
			cert, err = loadTLSCert(*tlsCert, *tlsKey)
			if err != nil {
				log.Fatalf("加载 TLS 证书失败: %v", err)
			}
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
		}
	}

	// 启动服务器
	if !*quiet {
		if useTLS {
			fmt.Printf("HTTPS 服务器启动在 %s\n", *addr)
			fmt.Printf("注意: 使用自签名证书时，客户端需要添加 -k 参数忽略证书验证\n")
		} else {
			fmt.Printf("HTTP 服务器启动在 %s\n", *addr)
		}
		fmt.Printf("按 Ctrl+C 停止服务器\n\n")
	}

	server := &http.Server{
		Addr:      *addr,
		TLSConfig: tlsConfig,
	}

	errCh := make(chan error, 1)
	go func() {
		if useTLS {
			errCh <- server.ListenAndServeTLS("", "")
			return
		}
		errCh <- server.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	select {
	case <-sigCh:
		stats.Print()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}
