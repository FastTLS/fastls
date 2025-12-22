package fastls

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"

	http "github.com/FastTLS/fhttp"
	"github.com/FastTLS/fhttp/http2"
)

// Options 设置 Fastls 客户端选项
type Options struct {
	URL              string               `json:"url"`
	Method           string               `json:"method"`
	Headers          map[string]string    `json:"headers"`
	Body             string               `json:"body"`
	Fingerprint      Fingerprint          `json:"fingerprint"` // 指纹接口，支持 Ja3、Ja4 等
	TLSExtensions    *TLSExtensions       `json:"-"`
	HTTP2Settings    *http2.HTTP2Settings `json:"-"`
	PHeaderOrderKeys []string             `json:"-"`
	HeaderOrderKeys  []string             `json:"-"`
	UserAgent        string               `json:"userAgent"`
	Proxy            string               `json:"proxy"`
	Cookies          []Cookie             `json:"cookies"`
	Timeout          int                  `json:"timeout"`
	DisableRedirect  bool                 `json:"disableRedirect"`
	HeaderOrder      []string             `json:"headerOrder"`
}

// requestContext 包含请求、客户端和选项的完整上下文
type requestContext struct {
	req     *http.Request
	client  http.Client
	options Options
}

// Response 包含 Fastls 响应数据
type Response struct {
	Status  int
	Body    io.ReadCloser
	Headers map[string]string
	Client  http.Client
}

// JSONBody 将响应体转换为 JSON，如果转换失败则返回错误
func (re Response) JSONBody() (map[string]interface{}, error) {
	body, err := io.ReadAll(re.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("JSON解析失败: %w", err)
	}
	return data, nil
}

// Fastls 创建完整的请求和响应
type Fastls struct {
}

// processRequest 创建并准备请求上下文
func processRequest(options *Options) (*requestContext, error) {
	// 验证指纹类型，如果是 Ja4 则返回错误
	if err := options.ValidateFingerprint(); err != nil {
		return nil, fmt.Errorf("指纹验证失败: %w", err)
	}

	var browser = browser{
		Fingerprint:   options.Fingerprint,
		UserAgent:     options.UserAgent,
		Cookies:       options.Cookies,
		HTTP2Settings: options.HTTP2Settings,
	}

	client, err := newClient(
		browser,
		options.Timeout,
		options.DisableRedirect,
		options.UserAgent,
		options.Proxy,
	)
	if err != nil {
		return nil, fmt.Errorf("创建客户端失败: %w", err)
	}

	req, err := http.NewRequest(strings.ToUpper(options.Method), options.URL, strings.NewReader(options.Body))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	// 排序伪头部和普通头部
	if options.PHeaderOrderKeys == nil {
		options.PHeaderOrderKeys = []string{":method", ":authority", ":scheme", ":path"}
	}

	req.Header = http.Header{
		http.HeaderOrderKey:  options.HeaderOrderKeys,
		http.PHeaderOrderKey: options.PHeaderOrderKeys,
	}
	// 设置 Host 头部
	u, err := url.Parse(options.URL)
	if err != nil {
		return nil, fmt.Errorf("无效的URL: %w", err)
	}

	// 追加普通头部
	for k, v := range options.Headers {
		if k != "Content-Length" {
			req.Header.Set(k, v)
		}
	}
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", u.Host)
	}
	req.Header.Set("user-agent", options.UserAgent)
	return &requestContext{req: req, client: client, options: *options}, nil
}

func dispatcher(res *requestContext) (response Response, err error) {
	//defer res.client.CloseIdleConnections()

	resp, err := res.client.Do(res.req)
	if err != nil {
		parsedError := parseError(err)

		headers := make(map[string]string)
		// parsedError.ErrorMsg + "-> \n" + string(err.Error())
		return Response{
			parsedError.StatusCode, io.NopCloser(bytes.NewBufferString(parsedError.ErrorMsg)), headers, res.client,
		}, err

	}

	headers := make(map[string]string)

	for name, values := range resp.Header {
		if name == "Set-Cookie" {
			headers[name] = strings.Join(values, "/,/")
		} else {
			headers[name] = values[0]
		}
	}
	return Response{resp.StatusCode, resp.Body, headers, res.client}, nil

}

// Do 创建单个请求
func (client Fastls) Do(URL string, options Options, Method string) (response Response, err error) {
	options.URL = URL
	options.Method = Method

	reqCtx, err := processRequest(&options)
	if err != nil {
		return response, fmt.Errorf("处理请求失败: %w", err)
	}

	response, err = dispatcher(reqCtx)
	if err != nil {
		log.Print("Request Failed: " + err.Error())
		return response, err
	}

	return response, nil
}

// NewClient 创建新的 Fastls 客户端实例
func NewClient() Fastls {
	return Fastls{}
}

// Init 已弃用，请使用 NewClient 代替
// Deprecated: 请使用 NewClient() 代替
func Init() Fastls {
	return NewClient()
}
