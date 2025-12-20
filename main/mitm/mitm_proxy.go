package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	fastls "github.com/ChengHoward/Fastls"
	"github.com/ChengHoward/Fastls/imitate"
	utls "github.com/refraction-networking/utls"
)

// MITMProxy 中间人代理服务器
type MITMProxy struct {
	caCert         *x509.Certificate
	caKey          *rsa.PrivateKey
	caCertPEM      []byte
	caKeyPEM       []byte
	server         *http.Server
	certCache      map[string]*tls.Certificate
	certMutex      sync.RWMutex
	fingerprint    fastls.Fingerprint
	browser        string
	listenAddr     string
	disableConnect bool // 是否禁用 CONNECT 隧道请求
}

// NewMITMProxy 创建新的中间人代理
func NewMITMProxy(listenAddr string, fingerprint fastls.Fingerprint, browser string, disableConnect bool) (*MITMProxy, error) {
	proxy := &MITMProxy{
		certCache:      make(map[string]*tls.Certificate),
		listenAddr:     listenAddr,
		fingerprint:    fingerprint,
		browser:        browser,
		disableConnect: disableConnect,
	}

	// 生成或加载CA证书
	if err := proxy.generateCA(); err != nil {
		return nil, fmt.Errorf("生成CA证书失败: %v", err)
	}

	return proxy, nil
}

// generateCA 生成CA根证书（有效期15年）
func (p *MITMProxy) generateCA() error {
	// 检查是否已存在CA证书
	caCertPath := "mitm-ca-cert.pem"
	caKeyPath := "mitm-ca-key.pem"

	if certData, err := os.ReadFile(caCertPath); err == nil {
		if keyData, err := os.ReadFile(caKeyPath); err == nil {
			// 加载现有证书
			block, _ := pem.Decode(certData)
			if block != nil {
				p.caCert, _ = x509.ParseCertificate(block.Bytes)
			}
			keyBlock, _ := pem.Decode(keyData)
			if keyBlock != nil {
				p.caKey, _ = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			}
			p.caCertPEM = certData
			p.caKeyPEM = keyData
			log.Printf("已加载现有CA证书: %s", caCertPath)
			return nil
		}
	}

	// 生成新的CA证书
	log.Println("正在生成新的CA根证书（有效期15年）...")

	// 生成私钥
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// 创建证书模板
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Fastls MITM Proxy"},
			Country:       []string{"CN"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(15, 0, 0), // 15年有效期
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	// 自签名证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	// 编码证书和私钥
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// 保存到文件
	if err := os.WriteFile(caCertPath, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(caKeyPath, keyPEM, 0600); err != nil {
		return err
	}

	p.caCert, _ = x509.ParseCertificate(certDER)
	p.caKey = key
	p.caCertPEM = certPEM
	p.caKeyPEM = keyPEM

	log.Printf("CA证书已生成并保存: %s", caCertPath)
	log.Printf("CA证书有效期: %s 至 %s", template.NotBefore.Format("2006-01-02"), template.NotAfter.Format("2006-01-02"))
	log.Printf("请将 %s 添加到系统信任的根证书颁发机构", caCertPath)

	return nil
}

// getCertForHost 为指定主机生成证书
func (p *MITMProxy) getCertForHost(host string) (*tls.Certificate, error) {
	// 检查缓存
	p.certMutex.RLock()
	if cert, ok := p.certCache[host]; ok {
		p.certMutex.RUnlock()
		return cert, nil
	}
	p.certMutex.RUnlock()

	// 生成新证书
	p.certMutex.Lock()
	defer p.certMutex.Unlock()

	// 再次检查（可能其他goroutine已经生成）
	if cert, ok := p.certCache[host]; ok {
		return cert, nil
	}

	// 生成私钥
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// 创建证书模板
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Fastls MITM Proxy"},
		},
		NotBefore:   now,
		NotAfter:    now.AddDate(1, 0, 0), // 1年有效期
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host, "*." + host},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// 使用CA签名
	certDER, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	// 缓存证书
	p.certCache[host] = cert

	return cert, nil
}

// dialTLSWithFingerprint 使用指纹连接到目标服务器
func (p *MITMProxy) dialTLSWithFingerprint(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// 建立TCP连接
	rawConn, err := net.DialTimeout(network, addr, 30*time.Second)
	if err != nil {
		return nil, err
	}

	// 应用 imitate 配置
	options := fastls.Options{
		Headers: make(map[string]string),
	}
	fingerprint, userAgent := p.applyImitateConfig(&options)

	if p.fingerprint != nil && !p.fingerprint.IsEmpty() {
		log.Printf("使用自定义指纹连接到: %s", host)
	} else {
		browserType := p.browser
		if browserType == "" {
			browserType = "firefox"
		}
		log.Printf("使用浏览器指纹 (%s) 连接到: %s, UserAgent: %s", browserType, host, userAgent)
		if fingerprint == nil || fingerprint.IsEmpty() {
			log.Printf("警告: 浏览器指纹 (%s) 未设置成功，将使用标准TLS", browserType)
		} else {
			log.Printf("指纹类型: %s, 指纹值: %s", fingerprint.Type(), fingerprint.Value())
		}
	}

	// 如果指定了指纹，使用uTLS
	if fingerprint != nil && !fingerprint.IsEmpty() {
		// 使用StringToSpec将指纹字符串转换为TLS规范
		spec, err := fastls.StringToSpec(fingerprint.Value(), userAgent)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("创建TLS规范失败: %v", err)
		}

		// 创建uTLS客户端连接
		conn := utls.UClient(rawConn, &utls.Config{
			ServerName:         host,
			OmitEmptyPsk:       true,
			InsecureSkipVerify: true,
		}, utls.HelloCustom)

		// 应用TLS规范
		if err := conn.ApplyPreset(spec); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("应用TLS预设失败: %v", err)
		}

		// 执行TLS握手
		if err := conn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS握手失败: %v", err)
		}

		return conn, nil
	}

	// 如果没有指定指纹，使用标准TLS
	conn := tls.Client(rawConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})

	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS握手失败: %v", err)
	}

	return conn, nil
}

// applyImitateConfig 应用 imitate 配置到 options，返回指纹和 UserAgent
func (p *MITMProxy) applyImitateConfig(options *fastls.Options) (fastls.Fingerprint, string) {
	var fingerprint fastls.Fingerprint
	var userAgent string

	if p.fingerprint != nil && !p.fingerprint.IsEmpty() {
		// 使用自定义指纹
		options.Fingerprint = p.fingerprint
		fingerprint = p.fingerprint
	} else {
		// 使用浏览器指纹
		browserType := p.browser
		if browserType == "" {
			browserType = "firefox" // 默认使用Firefox
		}

		switch browserType {
		case "chrome":
			imitate.Chrome(options)
		case "chrome120":
			imitate.Chrome120(options)
		case "chrome142":
			imitate.Chrome142(options)
		case "chromium":
			imitate.Chromium(options)
		case "edge":
			imitate.Edge(options)
		case "firefox":
			imitate.Firefox(options)
		case "safari":
			imitate.Safari(options)
		case "opera":
			imitate.Opera(options)
		default:
			imitate.Firefox(options)
		}

		fingerprint = options.Fingerprint
		userAgent = options.UserAgent

		// 如果不是自定义指纹，且 UserAgent 不为空，则覆盖 User-Agent 请求头
		if userAgent != "" {
			options.Headers["User-Agent"] = userAgent
		}
	}

	return fingerprint, userAgent
}

// handleConnect 处理CONNECT请求（HTTPS代理）
func (p *MITMProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// 获取目标主机
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	log.Printf("收到CONNECT请求: %s -> %s", r.RemoteAddr, host)

	// 如果禁用了 CONNECT 请求，返回错误提示
	if p.disableConnect {
		log.Printf("CONNECT 请求被禁用，返回 405 Method Not Allowed")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Proxy-Error", "CONNECT method not supported")
		w.WriteHeader(http.StatusMethodNotAllowed)
		errorMsg := fmt.Sprintf(
			"405 Method Not Allowed\r\n\r\n"+
				"此代理服务器不支持 CONNECT 隧道请求。\r\n"+
				"请使用 HTTP 代理方式发送请求，而不是 HTTPS 隧道模式。\r\n\r\n"+
				"示例:\r\n"+
				"  curl -x http://%s http://example.com/api\r\n"+
				"  而不是: curl -x http://%s https://example.com/api\r\n\r\n"+
				"注意: 禁用 CONNECT 后，无法通过代理访问 HTTPS 网站。\r\n",
			p.listenAddr, p.listenAddr)
		w.Write([]byte(errorMsg))
		return
	}

	// 检查是否支持Hijack
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("错误: 不支持Hijack")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Hijack连接（必须在WriteHeader之前调用）
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Hijack失败: %v", err)
		// 注意：Hijack失败后不能使用http.Error，因为连接可能已经被hijack
		// 尝试直接写入错误响应
		if clientConn != nil {
			clientConn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
			clientConn.Close()
		}
		return
	}
	defer clientConn.Close()

	// 发送200 Connection Established响应
	// Python requests 库要求严格的HTTP响应格式
	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	n, err := clientConn.Write([]byte(response))
	if err != nil {
		log.Printf("发送CONNECT响应失败: %v (已写入 %d 字节)", err, n)
		return
	}
	log.Printf("已发送CONNECT响应: %d 字节", n)

	// 解析主机名
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}

	// 为这个主机生成证书
	cert, err := p.getCertForHost(hostname)
	if err != nil {
		log.Printf("生成证书失败 %s: %v", hostname, err)
		return
	}

	// 创建TLS配置（服务器端，用于与客户端通信）
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := clientHello.ServerName
			if sni == "" {
				sni = hostname
			}
			return p.getCertForHost(sni)
		},
	}

	// 在客户端连接上启动TLS（服务器端）
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("客户端TLS握手失败: %v", err)
		return
	}

	// 建立到目标的TLS连接（客户端，使用指纹）
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	targetConn, err := p.dialTLSWithFingerprint(ctx, "tcp", host)
	if err != nil {
		log.Printf("连接到目标服务器失败 %s: %v", host, err)
		return
	}
	defer targetConn.Close()

	// 创建 HTTP 请求拦截器，用于修改请求头
	// 从客户端读取 HTTP 请求，修改请求头后转发到目标服务器
	go func() {
		// 读取客户端发送的 HTTP 请求
		reader := bufio.NewReader(tlsConn)
		for {
			// 解析 HTTP 请求
			req, err := http.ReadRequest(reader)
			if err != nil {
				if err != io.EOF {
					log.Printf("读取客户端请求失败: %v", err)
				}
				targetConn.Close()
				return
			}

			// 应用 imitate 的请求头修改
			modifiedReq := p.modifyRequestHeaders(req, hostname)

			// 将修改后的请求写入目标服务器
			if err := modifiedReq.Write(targetConn); err != nil {
				log.Printf("写入目标服务器请求失败: %v", err)
				targetConn.Close()
				return
			}

			// 读取目标服务器的响应
			respReader := bufio.NewReader(targetConn)
			resp, err := http.ReadResponse(respReader, modifiedReq)
			if err != nil {
				if err != io.EOF {
					log.Printf("读取目标服务器响应失败: %v", err)
				}
				targetConn.Close()
				return
			}

			// 将响应写回客户端
			if err := resp.Write(tlsConn); err != nil {
				log.Printf("写入客户端响应失败: %v", err)
				tlsConn.Close()
				return
			}

			// 如果不是 keep-alive，关闭连接
			if !strings.EqualFold(req.Header.Get("Connection"), "keep-alive") {
				targetConn.Close()
				return
			}
		}
	}()

	// 等待连接关闭
	<-make(chan struct{})
}

// modifyRequestHeaders 修改请求头，应用 imitate 的配置
func (p *MITMProxy) modifyRequestHeaders(req *http.Request, hostname string) *http.Request {
	// 创建 Options 来应用 imitate 配置
	options := fastls.Options{
		Timeout: 30,
		Headers: make(map[string]string),
	}

	// 先复制用户的请求头到options
	for key, values := range req.Header {
		if len(values) > 0 {
			options.Headers[key] = values[0]
		}
	}

	// 应用 imitate 配置
	p.applyImitateConfig(&options)

	// 创建新的请求，使用修改后的请求头
	newReq := req.Clone(req.Context())

	// 清空原有请求头
	newReq.Header = make(http.Header)

	// 应用 imitate 修改后的请求头
	for key, value := range options.Headers {
		newReq.Header.Set(key, value)
	}

	// 保留一些必要的请求头（如果 imitate 没有设置）
	if newReq.Header.Get("Host") == "" {
		newReq.Header.Set("Host", req.Host)
	}
	if newReq.Header.Get("Connection") == "" {
		if conn := req.Header.Get("Connection"); conn != "" {
			newReq.Header.Set("Connection", conn)
		}
	}

	// 设置正确的 URL
	newReq.URL.Scheme = "https"
	newReq.URL.Host = hostname
	if newReq.URL.Path == "" {
		newReq.URL.Path = "/"
	}

	// 确保请求体被正确设置
	if req.Body != nil {
		newReq.Body = req.Body
		newReq.ContentLength = req.ContentLength
	}

	return newReq
}

// handleHTTP 处理HTTP请求
func (p *MITMProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// 检查是否是误判的CONNECT请求（URL格式为 host:port）
	// 某些客户端可能将CONNECT请求的URL设置为目标地址
	if r.URL.Host != "" && r.URL.Scheme == "" && r.URL.Path == "" {
		log.Printf("检测到可能的CONNECT请求（URL格式: %s），重定向到handleConnect", r.URL.Host)
		// 这可能是CONNECT请求，但Method不是CONNECT
		// 检查Host头
		if r.Host != "" {
			p.handleConnect(w, r)
			return
		}
	}

	// 构建目标URL
	targetURL := r.URL.String()
	// 如果URL没有scheme，尝试添加
	if r.URL.Scheme == "" {
		if r.URL.Host != "" {
			// 如果URL包含host，假设是HTTP
			targetURL = "http://" + r.URL.Host
			if r.URL.Path != "" {
				targetURL += r.URL.Path
			}
			if r.URL.RawQuery != "" {
				targetURL += "?" + r.URL.RawQuery
			}
		} else if r.Host != "" {
			// 使用Host头构建URL
			targetURL = "http://" + r.Host + r.URL.Path
			if r.URL.RawQuery != "" {
				targetURL += "?" + r.URL.RawQuery
			}
		}
	}

	log.Printf("处理HTTP请求: %s %s", r.Method, targetURL)

	// 创建新的请求
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Printf("创建请求失败: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// 设置指纹
	options := fastls.Options{
		Timeout: 30,
		Headers: make(map[string]string),
	}

	// 先复制用户的请求头到options
	for key, values := range r.Header {
		if len(values) > 0 {
			options.Headers[key] = values[0]
		}
	}

	// 应用 imitate 配置（会自动覆盖 User-Agent 如果设置了）
	p.applyImitateConfig(&options)

	// 执行请求
	client := fastls.NewClient()
	resp, err := client.Do(targetURL, options, r.Method)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for key, value := range resp.Headers {
		w.Header().Set(key, value)
	}

	// 设置状态码
	w.WriteHeader(resp.Status)

	// 复制响应体
	io.Copy(w, resp.Body)
}

// Start 启动代理服务器
func (p *MITMProxy) Start() error {
	// 使用自定义Handler而不是ServeMux，避免CONNECT请求被重定向
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 记录所有请求（用于调试）
		log.Printf("收到请求: %s %s (Method: %s, Host: %s, URL: %s)", r.Method, r.URL.Path, r.Method, r.Host, r.URL.String())

		// 检查是否是CONNECT请求
		if r.Method == http.MethodConnect {
			log.Printf("处理CONNECT请求: %s", r.Host)
			p.handleConnect(w, r)
			return
		}

		// 对于非CONNECT请求，如果是代理测试请求，返回200 OK
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			log.Printf("收到代理测试请求，返回200 OK")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Fastls MITM Proxy is running"))
			return
		}

		// 处理其他HTTP请求
		p.handleHTTP(w, r)
	})

	p.server = &http.Server{
		Addr:    p.listenAddr,
		Handler: handler,
	}

	log.Printf("中间人代理服务器启动在 %s", p.listenAddr)
	log.Printf("CA证书文件: mitm-ca-cert.pem")
	log.Printf("请将CA证书添加到系统信任的根证书颁发机构")
	if p.disableConnect {
		log.Printf("⚠️  CONNECT 隧道请求已禁用，只支持 HTTP 代理方式")
		log.Printf("   注意: 禁用 CONNECT 后，无法通过代理访问 HTTPS 网站")
	}
	if p.fingerprint != nil && !p.fingerprint.IsEmpty() {
		log.Printf("使用自定义指纹: %s", p.fingerprint.Value())
	} else if p.browser != "" {
		log.Printf("使用浏览器指纹: %s", p.browser)
	} else {
		log.Printf("使用默认指纹: Firefox")
	}

	return p.server.ListenAndServe()
}

// Stop 停止代理服务器
func (p *MITMProxy) Stop() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

func main() {
	// 命令行参数
	var (
		listenAddr     = flag.String("addr", ":8888", "监听地址 (例如: :8888 或 0.0.0.0:8888)")
		browser        = flag.String("browser", "chrome142", "浏览器类型 (chrome, chrome120, chrome142, chromium, edge, firefox, safari, opera)")
		ja3            = flag.String("ja3", "", "自定义JA3指纹字符串 (如果指定，将忽略browser参数)")
		ja4r           = flag.String("ja4r", "", "自定义JA4R指纹字符串 (如果指定，将忽略browser参数)")
		caCertPath     = flag.String("ca-cert", "mitm-ca-cert.pem", "CA证书文件路径")
		caKeyPath      = flag.String("ca-key", "mitm-ca-key.pem", "CA私钥文件路径")
		disableConnect = flag.Bool("disable-connect", false, "禁用 CONNECT 隧道请求，只支持 HTTP 代理方式")
	)
	flag.Parse()

	var fingerprint fastls.Fingerprint = nil
	browserType := ""

	// 设置指纹
	if *ja3 != "" {
		fingerprint = fastls.Ja3Fingerprint{
			FingerprintValue: *ja3,
		}
		log.Printf("使用自定义JA3指纹: %s", *ja3)
	} else if *ja4r != "" {
		fingerprint = fastls.Ja4Fingerprint{
			FingerprintValue: *ja4r,
		}
		log.Printf("使用自定义JA4R指纹: %s", *ja4r)
	} else {
		browserType = *browser
		log.Printf("使用浏览器指纹: %s", browserType)
	}

	// 创建代理服务器
	proxy, err := NewMITMProxy(*listenAddr, fingerprint, browserType, *disableConnect)
	if err != nil {
		log.Fatalf("创建代理服务器失败: %v", err)
	}

	// 显示CA证书信息
	log.Println("=" + strings.Repeat("=", 60))
	log.Println("中间人代理服务器配置:")
	log.Printf("  监听地址: %s", *listenAddr)
	log.Printf("  CA证书: %s", *caCertPath)
	log.Printf("  CA私钥: %s", *caKeyPath)
	log.Println("=" + strings.Repeat("=", 60))
	log.Println("使用说明:")
	log.Println("  1. 将CA证书添加到系统信任的根证书颁发机构")
	log.Printf("  2. 配置代理: HTTP代理 -> %s", *listenAddr)
	log.Println("  3. 开始使用代理")
	log.Println("=" + strings.Repeat("=", 60))

	// 启动服务器
	if err := proxy.Start(); err != nil {
		log.Fatalf("代理服务器启动失败: %v", err)
	}
}
