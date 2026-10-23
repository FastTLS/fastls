package fastls

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

const regressionJA4R = "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
const regressionUA = "Mozilla/5.0 Chrome/142.0.0.0 Safari/537.36"

func TestJA4RLocalHandshake(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("HTTP2=%t", h2), func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, r.Proto)
			}))
			srv.EnableHTTP2 = h2
			srv.StartTLS()
			defer srv.Close()
			o := Options{Fingerprint: Ja4Fingerprint{FingerprintValue: regressionJA4R}, UserAgent: regressionUA, Timeout: 5}
			resp, err := NewClient().Do(srv.URL, o, "GET")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			defer resp.Client.CloseIdleConnections()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			want := "HTTP/1.1"
			if h2 {
				want = "HTTP/2.0"
			}
			if resp.Status != 200 || string(body) != want {
				t.Fatalf("status=%d protocol=%q, want %s", resp.Status, body, want)
			}
		})
	}
}

func TestJA4RPrefixExtensions(t *testing.T) {
	for _, protocol := range []string{"t", "q"} {
		for _, explicit := range []bool{false, true} {
			value := protocol + regressionJA4R[1:]
			if explicit {
				value = strings.Replace(value, "_0005,", "_0000,0010,0005,", 1)
			}
			spec, err := ParseJA4R(value, regressionUA)
			if err != nil {
				t.Fatal(err)
			}
			sni, alpn := 0, 0
			for _, ext := range spec.Extensions {
				switch ext := ext.(type) {
				case *utls.SNIExtension:
					sni++
				case *utls.ALPNExtension:
					alpn++
					if len(ext.AlpnProtocols) == 0 || ext.AlpnProtocols[0] != "h2" {
						t.Fatalf("unexpected ALPN: %v", ext.AlpnProtocols)
					}
				}
			}
			if sni != 1 || alpn != 1 {
				t.Fatalf("protocol=%s explicit=%t SNI=%d ALPN=%d", protocol, explicit, sni, alpn)
			}
			if _, ok := spec.Extensions[len(spec.Extensions)-1].(*utls.FakePreSharedKeyExtension); !ok {
				t.Fatal("PSK must remain last")
			}
		}
	}
	// Legacy prefixes without ALPN information must not gain an ALPN extension.
	spec, err := ParseJA4R(strings.Replace(regressionJA4R, "1517h2", "1517", 1), regressionUA)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			t.Fatal("legacy prefix unexpectedly gained ALPN")
		}
	}
}
