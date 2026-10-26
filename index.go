package fastls

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/FastTLS/fastls/profile"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/FastTLS/ftransport"
)

// Options 设置 Fastls 客户端选项
type Options struct {
	// HTTPVersion3 requires H3 on every hop; zero preserves existing selection.
	HTTPVersion HTTPVersion `json:"httpVersion,omitempty"`
	// AddressPolicy is an optional, immutable direct HTTP destination policy.
	// It cannot be supplied through request JSON. Nil preserves existing behavior.
	AddressPolicy                  *AddressPolicy `json:"-"`
	reuseConnections               bool
	lifetime                       context.Context
	FingerprintUserAgent           string              `json:"-"` // Protocol parser identity; request headers never change it.
	FingerprintSignatureAlgorithms []uint16            `json:"-"` // Explicit wire declarations omitted by JA3; does not add cryptographic implementations.
	FingerprintProvider            profile.Provider    `json:"-"`
	Profile                        *profile.Spec       `json:"profile,omitempty"`
	HeaderValues                   map[string][]string `json:"-"`
	URL                            string              `json:"url"`
	Method                         string              `json:"method"`
	Headers                        map[string]string   `json:"headers"`
	Body                           string              `json:"body"`
	// Trailers contains request trailers for one-shot requests.
	Trailers            http.Header             `json:"-"`
	Fingerprint         Fingerprint             `json:"fingerprint"` // 指纹接口，支持 Ja3、Ja4 等
	TLSExtensions       *TLSExtensions          `json:"-"`
	HTTP2Settings       *ftransport.HTTP2Config `json:"-"`
	HTTP2SettingsString string                  `json:"http2SettingsString"` // HTTP/2 设置字符串，如果设置则覆盖 HTTP2Settings 和 PHeaderOrderKeys
	PHeaderOrderKeys    []string                `json:"-"`
	HeaderOrderKeys     []string                `json:"-"`
	UserAgent           string                  `json:"userAgent"`
	Proxy               string                  `json:"proxy"`
	// ProxyTLSRootCAs replaces system roots for HTTPS proxy TLS only.
	ProxyTLSRootCAs *x509.CertPool `json:"-"`
	Cookies         []Cookie       `json:"cookies"`
	CookieJar       http.CookieJar `json:"-"`
	Timeout         int            `json:"timeout"`
	DisableRedirect bool           `json:"disableRedirect"`
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
	// RequestHasBody describes the final request after redirects.
	RequestHasBody bool
	Status         int
	Protocol       string
	FinalURL       string
	Body           io.ReadCloser
	Headers        map[string]string
	// Trailer is populated while Body is read and is complete after EOF.
	Trailer          http.Header
	Client           http.Client
	HeaderValues     map[string][]string
	WireHeaderValues map[string][]string
	Decoded          bool
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
	addressPolicy *AddressPolicy
}

// processRequest 创建并准备请求上下文
func processRequest(options *Options, shared ...http.Client) (*requestContext, error) {
	if err := options.validateHTTPVersion(); err != nil {
		return nil, err
	}
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
	if options.AddressPolicy != nil {
		if options.Proxy != "" {
			return nil, addressDenied("proxy_unsupported")
		}
		if options.HTTPVersion == HTTPVersion3 || options.Fingerprint != nil && !options.Fingerprint.IsEmpty() && strings.HasPrefix(options.Fingerprint.Value(), "q") {
			return nil, addressDenied("http3_unsupported")
		}
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
	if options.PHeaderOrderKeys == nil && options.HTTPVersion != HTTPVersion3 {
		options.PHeaderOrderKeys = []string{":method", ":authority", ":scheme", ":path"}
	}

	var browser = browser{
		HTTPVersion:                    options.HTTPVersion,
		AddressPolicy:                  options.AddressPolicy,
		KeepAlive:                      options.reuseConnections,
		Lifetime:                       options.lifetime,
		ProxyConfigured:                options.Proxy != "",
		VerifyTLS:                      options.VerifyTLS,
		TLSRootCAs:                     options.TLSRootCAs,
		ProxyTLSRootCAs:                options.ProxyTLSRootCAs,
		Fingerprint:                    options.Fingerprint,
		Profile:                        options.Profile,
		UserAgent:                      options.UserAgent,
		FingerprintUserAgent:           options.FingerprintUserAgent,
		FingerprintSignatureAlgorithms: append([]uint16(nil), options.FingerprintSignatureAlgorithms...),
		Cookies:                        options.Cookies,
		CookieJar:                      options.CookieJar,
		HTTP2Settings:                  options.HTTP2Settings,
		HeaderOrderKeys:                options.HeaderOrderKeys,
		PHeaderOrderKeys:               options.PHeaderOrderKeys,
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

	req.Header = make(http.Header)
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
	var hostValues []string
	for name, values := range req.Header {
		if strings.EqualFold(name, "Host") {
			hostValues = append(hostValues, values...)
			delete(req.Header, name)
		}
	}
	if len(hostValues) > 1 {
		return nil, fmt.Errorf("Host requires exactly one value")
	}
	if len(hostValues) == 1 {
		if hostValues[0] == "" {
			return nil, fmt.Errorf("Host cannot be empty")
		}
		req.Host = hostValues[0]
	} else {
		req.Host = u.Host
	}
	if options.Trailers != nil {
		req.Trailer = options.Trailers.Clone()
		// HTTP/1.1 request trailers require chunked framing. Keeping an exact
		// Content-Length would cause net/http to omit the trailer block.
		req.ContentLength = -1
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
		return Response{Status: parsedError.StatusCode, Body: io.NopCloser(bytes.NewBufferString(parsedError.ErrorMsg)), Headers: headers, Client: res.client}, err

	}

	headers := make(map[string]string)
	headerValues := make(map[string][]string)

	for name, values := range resp.Header {
		headerValues[name] = append([]string{}, values...)
		if len(values) == 0 {
			continue
		}
		if name == "Set-Cookie" {
			headers[name] = strings.Join(values, "/,/")
		} else {
			headers[name] = values[0]
		}
	}
	hasBody := resp.Request != nil && resp.Request.Body != nil && resp.Request.Body != http.NoBody
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return Response{
		Status: resp.StatusCode, Protocol: resp.Proto, FinalURL: finalURL,
		Body: resp.Body, Headers: headers, Trailer: resp.Trailer, Client: res.client,
		HeaderValues: headerValues, RequestHasBody: hasBody,
	}, nil

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
	if client.addressPolicy != nil {
		// A trusted client-level policy cannot be cleared or replaced by a
		// request's Options, including options assembled from an RPC DTO.
		options.AddressPolicy = client.addressPolicy
	}

	reqCtx, err := processRequest(&options)
	if err != nil {
		return response, fmt.Errorf("处理请求失败: %w", err)
	}
	reqCtx.req = reqCtx.req.WithContext(ctx)

	response, err = dispatcher(reqCtx)
	if err != nil {
		var denied *AddressPolicyError
		if errors.As(err, &denied) {
			log.Print("Request Failed: " + denied.Error())
		} else {
			log.Print("Request Failed: " + err.Error())
		}
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
