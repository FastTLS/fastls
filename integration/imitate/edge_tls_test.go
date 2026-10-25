package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	fastls "github.com/FastTLS/fastls"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The observation lab uses ECDSA. Exercise RSA server authentication as well,
// including TLS1.3 RSA-PSS selection in the presence of advertised ML-DSA IDs.
func TestEdgeCompleteSpecsWithRSAServers(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, h2 := range []bool{false, true} {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
			srv.EnableHTTP2 = h2
			srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: version, MaxVersion: version}
			srv.StartTLS()
			for _, selector := range []string{"edge/151/windows", "edge/156/windows"} {
				o := fastls.Options{Timeout: 5, VerifyTLS: true, TLSRootCAs: roots}
				if _, err := useGenerated(&o, selector); err != nil {
					t.Fatal(err)
				}
				response, err := fastls.NewClient().Do(strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), o, "GET")
				if err != nil {
					t.Fatal(selector, version, h2, err)
				}
				response.Body.Close()
				response.Client.CloseIdleConnections()
				if response.Status != 200 {
					t.Fatal(response.Status)
				}
			}
			srv.Close()
		}
	}
}
