package integration

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
	"github.com/FastTLS/fastls/profile"
	generators "github.com/FastTLS/imitate"
)

// GOST_BIN opts into real local proxy tests. No external destination is used.
func TestGOSTProxy(t *testing.T) {
	bin := os.Getenv("GOST_BIN")
	if bin == "" {
		t.Skip("set GOST_BIN to run the real GOST proxy matrix")
	}
	dir, err := os.MkdirTemp(filepath.Join(workspace, "reports"), "gost-proxy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("proxy logs:", dir)
	providers := []struct {
		name string
		p    profile.Provider
	}{{"generator", generators.New()}}
	bundle, err := generators.New().Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	offline, err := imitate.Register(data)
	if err != nil {
		t.Fatal(err)
	}
	providers = append(providers, struct {
		name string
		p    profile.Provider
	}{"offline", offline})
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		for _, auth := range []bool{false, true} {
			name := scheme + "-anonymous"
			if auth {
				name = scheme + "-authenticated"
			}
			t.Run(name, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr := listener.Addr().String()
				listener.Close()
				serverScheme := scheme
				if scheme == "https" {
					serverScheme = "http+tls"
				}
				if scheme == "socks5h" {
					serverScheme = "socks5"
				}
				endpoint := &url.URL{Scheme: serverScheme, Host: addr}
				if auth {
					endpoint.User = url.UserPassword("fastls-test", "local-only-pass")
				}
				log, err := os.Create(filepath.Join(dir, name+".log"))
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(bin, "-L", endpoint.String())
				cmd.Stdout, cmd.Stderr = log, log
				if err = cmd.Start(); err != nil {
					log.Close()
					t.Fatal(err)
				}
				t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); log.Close() })
				deadline := time.Now().Add(10 * time.Second)
				for {
					conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
					if dialErr == nil {
						conn.Close()
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("GOST did not start")
					}
					time.Sleep(20 * time.Millisecond)
				}
				endpoint.Scheme = scheme
				for _, provider := range providers {
					for _, target := range []struct{ name, address string }{{"http1", lab.HTTP}, {"tls-http1", lab.HTTPS}, {"tls-http2", lab.HTTPS2}} {
						t.Run(provider.name+"/"+target.name, func(t *testing.T) {
							o := fastls.Options{FingerprintProvider: provider.p}
							if _, err := imitate.Use(&o, "chrome/156/windows"); err != nil {
								t.Fatal(err)
							}
							o.Headers["User-Agent"] = "proxy-caller/1.0"
							o.Headers["Sec-Ch-Ua"] = "caller-hints"
							o.Headers["Sec-Fetch-Mode"] = "cors"
							var direct protocolObservation
							if target.address != lab.HTTP {
								before := len(events(t))
								request(t, o, target.address)
								direct = inspectOverride(t, events(t)[before:], "proxy-caller/1.0")
							}
							o.Proxy = endpoint.String()
							before := len(events(t))
							request(t, o, target.address)
							captured := events(t)[before:]
							if target.address != lab.HTTP {
								proxied := inspectOverride(t, captured, "proxy-caller/1.0")
								if !reflect.DeepEqual(direct, proxied) {
									t.Fatalf("proxy changed selected protocol/order: direct=%+v proxy=%+v", direct, proxied)
								}
							}
							sawHeaders := false
							for _, event := range captured {
								if event.Type != "http1.headers" && event.Type != "http2.headers" {
									continue
								}
								sawHeaders = true
								if strings.Contains(strings.ToLower(string(event.Data)), "proxy-authorization") {
									t.Fatal("proxy credentials leaked to destination")
								}
								if !strings.Contains(string(event.Data), "proxy-caller/1.0") || !strings.Contains(string(event.Data), "caller-hints") {
									t.Fatal("caller headers lost")
								}
							}
							if !sawHeaders {
								t.Fatal("missing destination capture")
							}
						})
					}
				}
				if auth {
					for _, credential := range []string{"missing", "wrong"} {
						t.Run(credential, func(t *testing.T) {
							bad := *endpoint
							bad.User = nil
							if credential == "wrong" {
								bad.User = url.UserPassword("fastls-test", "wrong")
							}
							o := fastls.Options{Proxy: bad.String(), Timeout: 3, FingerprintProvider: generators.New()}
							if _, err := imitate.Use(&o, "chrome/156/windows"); err != nil {
								t.Fatal(err)
							}
							before := len(events(t))
							r, err := fastls.NewClient().Do(strings.Replace(lab.HTTPS, "127.0.0.1", "localhost", 1)+"/inspect", o, "GET")
							if r.Body != nil {
								io.Copy(io.Discard, r.Body)
								r.Body.Close()
							}
							r.Client.CloseIdleConnections()
							if err == nil {
								t.Fatal("proxy accepted invalid credentials")
							}
							if (scheme == "http" || scheme == "https") && !strings.Contains(err.Error(), "407") {
								t.Fatalf("expected proxy authentication rejection: %v", err)
							}
							if strings.HasPrefix(scheme, "socks5") && !strings.Contains(err.Error(), "authentication") {
								t.Fatalf("expected SOCKS authentication rejection: %v", err)
							}
							if len(events(t)) != before {
								t.Fatal("rejected request reached destination")
							}
						})
					}
				}
			})
		}
	}
}
