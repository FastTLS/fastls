package main

import (
	"io"
	"log"
	"net/http"
	"runtime"

	fastls "github.com/ChengHoward/Fastls"
	"github.com/ChengHoward/Fastls/imitate"
	"github.com/gin-gonic/gin"
)

// FetchRequest 请求结构体
type FetchRequest struct {
	URL             string            `json:"url" binding:"required"`
	Method          string            `json:"method"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	Proxy           string            `json:"proxy"`
	Timeout         int               `json:"timeout"`
	DisableRedirect bool              `json:"disableRedirect"`
	UserAgent       string            `json:"userAgent"`
	Fingerprint     map[string]string `json:"fingerprint"` // {"type": "ja3", "value": "..."} 或 {"type": "ja4r", "value": "..."}
	Browser         string            `json:"browser"`     // 浏览器类型: "chrome", "chrome120", "chrome142", "chromium", "edge", "firefox", "safari", "opera"
	Cookies         []fastls.Cookie   `json:"cookies"`
}

// FetchResponse 响应结构体
type FetchResponse struct {
	OK      bool              `json:"ok"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Error   string            `json:"error,omitempty"`
}

func main() {
	// 设置最大CPU核心数
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 初始化Fastls客户端（全局单例，支持高并发）
	client := fastls.NewClient()

	// 创建gin路由（生产环境建议使用gin.ReleaseMode）
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// 添加CORS中间件（如果需要跨域访问）
	r.Use(corsMiddleware())

	// 健康检查端点
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// 主要的fetch端点
	r.POST("/fetch", func(c *gin.Context) {
		handleFetch(c, client)
	})

	// 启动服务器
	port := ":8800"
	log.Printf("Fetch服务启动在端口 %s", port)
	if err := r.Run(port); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}

// handleFetch 处理fetch请求
func handleFetch(c *gin.Context, client fastls.Fastls) {
	var req FetchRequest

	// 绑定JSON请求体
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, FetchResponse{
			OK:    false,
			Error: "请求参数错误: " + err.Error(),
		})
		return
	}

	// 设置默认值
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.Timeout == 0 {
		req.Timeout = 30 // 默认30秒超时
	}
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}

	// 构建Fastls选项
	options := fastls.Options{
		Headers:         make(map[string]string),
		Body:            req.Body,
		Proxy:           req.Proxy,
		Timeout:         req.Timeout,
		DisableRedirect: req.DisableRedirect,
		Cookies:         req.Cookies,
	}

	// 先复制用户的请求头到options
	for key, value := range req.Headers {
		options.Headers[key] = value
	}

	// 处理指纹（优先级：fingerprint > browser > 默认Firefox）
	if req.Fingerprint != nil {
		fpType, hasType := req.Fingerprint["type"]
		fpValue, hasValue := req.Fingerprint["value"]
		if hasType && hasValue {
			switch fpType {
			case "ja3":
				options.Fingerprint = fastls.Ja3Fingerprint{
					FingerprintValue: fpValue,
				}
			case "ja4", "ja4r":
				options.Fingerprint = fastls.Ja4Fingerprint{
					FingerprintValue: fpValue,
				}
			}
		}
	}

	// 如果没有指定指纹，根据浏览器类型设置指纹
	if (options.Fingerprint == nil || options.Fingerprint.IsEmpty()) && req.Browser != "" {
		switch req.Browser {
		case "chrome":
			imitate.Chrome(&options)
		case "chrome120":
			imitate.Chrome120(&options)
		case "chrome142":
			imitate.Chrome142(&options)
		case "chromium":
			imitate.Chromium(&options)
		case "edge":
			imitate.Edge(&options)
		case "firefox":
			imitate.Firefox(&options)
		case "safari":
			imitate.Safari(&options)
		case "opera":
			imitate.Opera(&options)
		default:
			imitate.Firefox(&options)
		}

		// 如果设置了 Browser，使用 imitate 设置的 UserAgent（覆盖用户的 UserAgent）
		if options.UserAgent != "" {
			options.Headers["User-Agent"] = options.UserAgent
		}
	} else if req.UserAgent != "" {
		// 如果没有设置 Browser，使用用户提供的 UserAgent
		options.UserAgent = req.UserAgent
		options.Headers["User-Agent"] = req.UserAgent
	}

	// 如果既没有指定指纹也没有指定浏览器，使用默认Firefox指纹
	if options.Fingerprint == nil || options.Fingerprint.IsEmpty() {
		imitate.Firefox(&options)
		// 使用 imitate 设置的 UserAgent
		if options.UserAgent != "" {
			options.Headers["User-Agent"] = options.UserAgent
		}
	}
	// 执行请求
	resp, err := client.Do(req.URL, options, req.Method)

	// 处理错误（在关闭Body之前检查）
	if err != nil {
		status := resp.Status
		if resp.Body != nil {
			resp.Body.Close()
		}
		c.JSON(http.StatusOK, FetchResponse{
			OK:     false,
			Status: status,
			Error:  err.Error(),
		})
		return
	}

	// 确保响应体被关闭
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	// 读取响应体
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusOK, FetchResponse{
			OK:     false,
			Status: resp.Status,
			Error:  "读取响应体失败: " + err.Error(),
		})
		return
	}

	// 解码响应体（处理gzip、br等压缩）
	contentEncoding := resp.Headers["Content-Encoding"]
	var decodedBody string
	if contentEncoding != "" {
		decodedBody = fastls.DecompressBody(bodyBytes, []string{contentEncoding}, nil)
	} else {
		// 如果没有Content-Encoding，检查Content-Type来决定是否需要base64编码
		contentType := resp.Headers["Content-Type"]
		if contentType != "" {
			decodedBody = fastls.DecompressBody(bodyBytes, nil, []string{contentType})
		} else {
			decodedBody = string(bodyBytes)
		}
	}

	// 返回成功响应
	c.JSON(http.StatusOK, FetchResponse{
		OK:      true,
		Status:  resp.Status,
		Headers: resp.Headers,
		Body:    decodedBody,
	})
}

// corsMiddleware CORS中间件
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
