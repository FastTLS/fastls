package tests

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
	"testing/iotest"
)

func TestPeetValidation(t *testing.T) {
	valid := func() peetResponse {
		p := peetResponse{HTTPVersion: "HTTP/1.1", Method: "GET", UserAgent: peetUserAgent}
		p.TLS.JA3 = "771,4865,0-10,29,"
		hash := md5.Sum([]byte(p.TLS.JA3))
		p.TLS.JA3Hash = hex.EncodeToString(hash[:])
		p.TLS.JA4, p.TLS.JA4R, p.TLS.Negotiated = "ja4", "ja4r", "772"
		return p
	}
	for _, tc := range []struct {
		name string
		edit func(*peetResponse)
	}{
		{"missing_ja3", func(p *peetResponse) { p.TLS.JA3 = "" }},
		{"short_ja3", func(p *peetResponse) { p.TLS.JA3 = "771,4865" }},
		{"bad_hash", func(p *peetResponse) { p.TLS.JA3Hash = "wrong" }},
		{"wrong_ua", func(p *peetResponse) { p.UserAgent = "rewritten" }},
		{"wrong_method", func(p *peetResponse) { p.Method = "POST" }},
		{"missing_ja4", func(p *peetResponse) { p.TLS.JA4 = "" }},
		{"h2_without_settings", func(p *peetResponse) { p.HTTPVersion = "h2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid()
			tc.edit(&p)
			body, _ := json.Marshal(p)
			if _, err := validatePeet(body, "", peetUserAgent); err == nil {
				t.Fatal("invalid observation accepted")
			}
		})
	}
	p := valid()
	body, _ := json.Marshal(p)
	if _, err := validatePeet(body, p.TLS.JA3, peetUserAgent); err != nil {
		t.Fatal(err)
	}
	if _, err := validatePeet(body, "771,4866,0-10,29,", peetUserAgent); err == nil {
		t.Fatal("JA3 mismatch accepted")
	}
	if _, err := validatePeet([]byte("not JSON"), "", peetUserAgent); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	t.Run("truncated_body_evidence", func(t *testing.T) {
		o := &peetObservation{RequestedUA: peetUserAgent}
		capturePeetStdResponse(o, &stdhttp.Response{Proto: "HTTP/2.0", ContentLength: 100, Header: stdhttp.Header{"Content-Type": {"application/json"}}})
		partial := `{"tls":`
		err := readPeetResponse(o, 200, io.MultiReader(strings.NewReader(partial), iotest.ErrReader(io.ErrUnexpectedEOF)))
		if !errors.Is(err, io.ErrUnexpectedEOF) || o.ErrorStage != "body_read" || !o.UnexpectedEOF || o.ReadComplete {
			t.Fatalf("lost read failure classification: %+v, err=%v", o, err)
		}
		if o.ResponseText != partial || o.BodyBytes != len(partial) || o.HTTPStatus != 200 || o.Protocol != "HTTP/2.0" || o.ContentLength == nil || *o.ContentLength != 100 {
			t.Fatalf("lost partial response evidence: %+v", o)
		}
	})
}
