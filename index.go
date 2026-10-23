package fastls

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/FastTLS/fastls/profile"
	"io"
	"log"
	"maps"
	"net/url"
	"strings"

	http "github.com/FastTLS/fhttp"
	"github.com/FastTLS/fhttp/http2"
)

// Options 设置 Fastls 客户端选项
type Options struct {
	reuseConnections     bool
	lifetime             context.Context
	FingerprintUserAgent string               `json:"-"` // Protocol parser identity; request headers never change it.
	FingerprintProvider  profile.Provider     `json:"-"`
	Profile              *profile.Spec        `json:"profile,omitempty"`
	HeaderValues         map[string][]string  `json:"-"`
	URL                  string               `json:"url"`
	Method               string               `json:"method"`
	Headers              map[string]string    `json:"headers"`
	Body                 string               `json:"body"`
	Fingerprint          Fingerprint          `json:"fingerprint"` // 指纹接口，支持 Ja3、Ja4 等
	TLSExtensions        *TLSExtensions       `json:"-"`
	HTTP2Settings        *http2.HTTP2Settings `json:"-"`
	HTTP2SettingsString  string               `json:"http2SettingsString"` // HTTP/2 设置字符串，如果设置则覆盖 HTTP2Settings 和 PHeaderOrderKeys
	PHeaderOrderKeys     []string             `json:"-"`
	HeaderOrderKeys      []string             `json:"-"`
	UserAgent            string               `json:"userAgent"`
	Proxy                string               `json:"proxy"`
	Cookies              []Cookie             `json:"cookies"`
	Timeout              int                  `json:"timeout"`
	DisableRedirect      bool                 `json:"disableRedirect"`
	// VerifyTLS enables certificate verification for fingerprinted TCP TLS requests.
	// The zero value preserves historical behavior; new integrations should set true.
	VerifyTLS bool `json:"verifyTLS"`
	// TLSRootCAs optionally replaces system roots for fingerprinted TCP TLS.
	TLSRootCAs  *x509.CertPool `json:"-"`
	HeaderOrder []string       `json:"headerOrder"`
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
func processRequest(options *Options, shared ...http.Client) (*requestContext, error) {
	if options.Profile != nil {
		if err := ApplyProfile(options, *options.Profile); err != nil {
			return nil, err
		}
	}
	options.Headers = maps.Clone(options.Headers)
	options.UserAgent = options.requestUserAgent()
	for k := range options.Headers {
		if strings.EqualFold(k, "User-Agent") {
			options.Headers[k] = options.UserAgent
		}
	}
	// 验证指纹类型，如果是 Ja4 则返回错误
	if err := options.ValidateFingerprint(); err != nil {
		return nil, fmt.Errorf("指纹验证失败: %w", err)
	}

	// 如果 HTTP2SettingsString 不为空，则解析并覆盖 HTTP2Settings 和 PHeaderOrderKeys
	if options.HTTP2SettingsString != "" {
		h2Settings, pHeaderOrderKeys, err := ParseH2SettingsStringWithPHeaderOrder(options.HTTP2SettingsString)
		if err != nil {
			return nil, fmt.Errorf("解析 HTTP2SettingsString 失败: %w", err)
		}
		// 覆盖 HTTP2Settings
		options.HTTP2Settings = ToHTTP2Settings(h2Settings)
		// 如果解析出 PHeaderOrderKeys，则覆盖
		if len(pHeaderOrderKeys) > 0 {
			options.PHeaderOrderKeys = pHeaderOrderKeys
		}
	}

	var browser = browser{
		KeepAlive:            options.reuseConnections,
		Lifetime:             options.lifetime,
		VerifyTLS:            options.VerifyTLS,
		TLSRootCAs:           options.TLSRootCAs,
		Fingerprint:          options.Fingerprint,
		Profile:              options.Profile,
		UserAgent:            options.UserAgent,
		FingerprintUserAgent: options.FingerprintUserAgent,
		Cookies:              options.Cookies,
		HTTP2Settings:        options.HTTP2Settings,
	}

	var client http.Client
	var err error
	if len(shared) != 0 {
		client = shared[0]
	} else {
		client, err = newClient(
			browser,
			options.Timeout,
			options.DisableRedirect,
			options.UserAgent,
			options.Proxy,
		)
	}
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
	for k, values := range options.HeaderValues {
		req.Header[k] = append([]string(nil), values...)
	}
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", u.Host)
	}
	if _, exists := req.Header["User-Agent"]; !exists {
		req.Header.Set("User-Agent", options.UserAgent)
	}
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
	return client.DoContext(context.Background(), URL, options, Method)
}

// DoContext keeps cancellation active until the response body is closed or read.
func (client Fastls) DoContext(ctx context.Context, URL string, options Options, Method string) (response Response, err error) {
	if ctx == nil {
		return response, fmt.Errorf("nil request context")
	}
	if err := ctx.Err(); err != nil {
		return response, err
	}
	options.URL = URL
	options.Method = Method

	reqCtx, err := processRequest(&options)
	if err != nil {
		return response, fmt.Errorf("处理请求失败: %w", err)
	}
	reqCtx.req = reqCtx.req.WithContext(ctx)

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

// requestUserAgent permits either public UA input to be edited after applying a recipe.
// A changed header wins; otherwise a changed Options.UserAgent wins over its generated default.
func (o Options) requestUserAgent() string {
	for k, values := range o.HeaderValues {
		if strings.EqualFold(k, "User-Agent") && len(values) > 0 {
			return values[0]
		}
	}
	for k, value := range o.Headers {
		if strings.EqualFold(k, "User-Agent") {
			if o.FingerprintUserAgent != "" && value == o.FingerprintUserAgent && o.UserAgent != value {
				return o.UserAgent
			}
			return value
		}
	}
	return o.UserAgent
}
