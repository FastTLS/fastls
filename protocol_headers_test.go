package fastls

import (
	"github.com/FastTLS/fastls/profile"
	"github.com/FastTLS/ftransport"
	"net/http"
	"testing"
)

func TestProtocolHeaderDefaultsRespectCallerAndWireCase(t *testing.T) {
	h := profile.HeaderConfig{HTTP1Defaults: []profile.Header{{Name: "Connection", Values: []string{"keep-alive"}}}, HTTP2Defaults: []profile.Header{{Name: "priority", Values: []string{"u=0, i"}}}, HTTP1Order: []string{"Host", "Connection", "sec-ch-ua", "User-Agent"}}
	for _, h2 := range []bool{false, true} {
		req, _ := http.NewRequest("GET", "https://localhost/", nil)
		req.Header.Set("Sec-Ch-Ua", "caller-hints")
		req.Header["Priority"] = []string{""}
		req.Header.Set("Connection", "close")
		protocol := ftransport.ProtocolHTTP1
		if h2 {
			protocol = ftransport.ProtocolHTTP2
		}
		req, err := applyProtocolHeaders(req, h, protocol)
		if err != nil {
			t.Fatal(err)
		}
		if req.Header.Get("Connection") != "close" || req.Header.Get("Priority") != "" {
			t.Fatal("caller value overwritten", req.Header)
		}
		if !h2 {
			if req.Header["sec-ch-ua"][0] != "caller-hints" {
				t.Fatal("HTTP1 wire case missing")
			}
			options, ok := ftransport.RequestOptionsFromRequest(req)
			if !ok || len(options.HeaderOrder) != len(h.HTTP1Order) {
				t.Fatal("HTTP1 wire order missing", options.HeaderOrder)
			}
			if req.Header.Get("Priority") != "" {
				t.Fatal("H2 default leaked to HTTP1")
			}
		}
	}
	for _, h2 := range []bool{false, true} {
		req, _ := http.NewRequest("GET", "https://localhost/", nil)
		protocol := ftransport.ProtocolHTTP1
		if h2 {
			protocol = ftransport.ProtocolHTTP2
		}
		req, err := applyProtocolHeaders(req, h, protocol)
		if err != nil {
			t.Fatal(err)
		}
		if h2 {
			if req.Header.Get("Priority") != "u=0, i" || req.Header.Get("Connection") != "" {
				t.Fatal(req.Header)
			}
		} else if req.Header.Get("Connection") != "keep-alive" || req.Header.Get("Priority") != "" {
			t.Fatal(req.Header)
		}
	}
}
