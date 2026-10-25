package fastls

import (
	"context"
	"crypto/x509"
	"errors"
	"github.com/FastTLS/fastls/profile"
	"github.com/FastTLS/ftransport"
	"net/http"
	"net/url"

	"time"

	"golang.org/x/net/proxy"
)

type browser struct {
	KeepAlive                      bool
	Lifetime                       context.Context
	ProxyConfigured                bool
	VerifyTLS                      bool
	TLSRootCAs                     *x509.CertPool
	ProxyTLSRootCAs                *x509.CertPool
	Profile                        *profile.Spec
	FingerprintUserAgent           string
	FingerprintSignatureAlgorithms []uint16
	Fingerprint                    Fingerprint
	UserAgent                      string
	Cookies                        []Cookie
	CookieJar                      http.CookieJar
	HTTP2Settings                  *ftransport.HTTP2Config
	HeaderOrderKeys                []string
	PHeaderOrderKeys               []string
}

var disabledRedirect = func(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func clientBuilder(browser browser, dialer proxy.ContextDialer, timeout int, disableRedirect bool) http.Client {
	//if timeout is not set in call default to 15
	if timeout == 0 {
		timeout = 15
	}
	client := http.Client{
		Jar:       browser.CookieJar,
		Transport: newRoundTripper(browser, dialer),
		Timeout:   time.Duration(timeout) * time.Second,
	}
	//if disableRedirect is set to true httpclient will not redirect
	if disableRedirect {
		client.CheckRedirect = disabledRedirect
	}
	return client
}

// newClient creates a new http client
func newClient(browser browser, timeout int, disableRedirect bool, UserAgent string, proxyURL ...string) (http.Client, error) {
	var dialer proxy.ContextDialer
	// Check if a valid proxyURL is provided.
	if len(proxyURL) > 0 && len(proxyURL[0]) > 0 {
		var err error
		parsed, parseErr := url.Parse(proxyURL[0])
		if parseErr != nil {
			err = errors.New("invalid proxy URL")
		} else if parsed.Scheme == "http" || parsed.Scheme == "https" || parsed.Scheme == "socks5" || parsed.Scheme == "socks5h" {
			endpoint, validationErr := parseTunnelProxy(proxyURL[0])
			err = validationErr
			if err == nil {
				dialer = &tunnelProxyDialer{endpoint: endpoint, roots: browser.ProxyTLSRootCAs}
			}
		} else {
			dialer, err = newConnectDialer(proxyURL[0], UserAgent)
		}
		if err != nil {
			return http.Client{
				Timeout:       time.Duration(timeout) * time.Second,
				CheckRedirect: disabledRedirect,
			}, err
		}
	} else {
		dialer = proxy.Direct
	}

	return clientBuilder(browser, dialer, timeout, disableRedirect), nil
}
