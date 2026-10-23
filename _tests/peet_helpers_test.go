package tests

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const peetURL = "https://tls.peet.ws/api/all"
const peetUserAgent = "fastls-peet-test/1.0"

type peetResponse struct {
	HTTPVersion string `json:"http_version"`
	Method      string `json:"method"`
	UserAgent   string `json:"user_agent"`
	TLS         struct {
		JA3        string `json:"ja3"`
		JA3Hash    string `json:"ja3_hash"`
		JA4        string `json:"ja4"`
		JA4R       string `json:"ja4_r"`
		Negotiated string `json:"tls_version_negotiated"`
	} `json:"tls"`
	HTTP2 struct {
		Akamai string `json:"akamai_fingerprint"`
	} `json:"http2"`
}

type peetObservation struct {
	Test        string          `json:"test"`
	Endpoint    string          `json:"endpoint"`
	StartedAt   string          `json:"started_at"`
	DurationMS  int64           `json:"duration_ms"`
	Status      string          `json:"status"`
	HTTPStatus  int             `json:"http_status"`
	InputJA3    string          `json:"input_ja3,omitempty"`
	ExpectedJA3 string          `json:"expected_ja3,omitempty"`
	RequestedUA string          `json:"requested_user_agent"`
	Observed    peetResponse    `json:"observed"`
	Response    json.RawMessage `json:"response,omitempty"`
	Error       string          `json:"error,omitempty"`
}

func startPeet(t *testing.T, input, expected string) *peetObservation {
	t.Helper()
	if os.Getenv("FASTLS_PEET_NETWORK") != "1" {
		t.Skip("public network test: run python scripts/check-peet.py")
	}
	started := time.Now()
	o := &peetObservation{Test: t.Name(), Endpoint: peetURL, StartedAt: started.UTC().Format(time.RFC3339Nano), InputJA3: input, ExpectedJA3: expected, RequestedUA: peetUserAgent}
	t.Cleanup(func() {
		o.DurationMS = time.Since(started).Milliseconds()
		o.Status = "pass"
		if t.Failed() {
			o.Status = "fail"
		}
		dir := os.Getenv("FASTLS_PEET_OUTPUT")
		if dir == "" {
			return
		}
		data, err := json.MarshalIndent(o, "", "  ")
		if err == nil {
			err = os.MkdirAll(dir, 0755)
		}
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+".json"), append(data, '\n'), 0600)
		}
		if err != nil {
			t.Errorf("save peet evidence: %v", err)
		}
	})
	return o
}

func validatePeet(body []byte, expected, ua string) (peetResponse, error) {
	var p peetResponse
	if err := json.Unmarshal(body, &p); err != nil {
		return p, fmt.Errorf("invalid peet JSON: %w", err)
	}
	parts := strings.Split(p.TLS.JA3, ",")
	if len(parts) != 5 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return p, fmt.Errorf("missing or malformed tls.ja3: %q", p.TLS.JA3)
	}
	hash := md5.Sum([]byte(p.TLS.JA3))
	if p.TLS.JA3Hash != hex.EncodeToString(hash[:]) {
		return p, fmt.Errorf("JA3 hash does not match JA3: %q", p.TLS.JA3Hash)
	}
	if expected != "" && p.TLS.JA3 != expected {
		return p, fmt.Errorf("JA3 mismatch: got %q, want %q", p.TLS.JA3, expected)
	}
	if p.Method != "GET" || p.UserAgent != ua {
		return p, fmt.Errorf("request mismatch: method=%q, user_agent=%q", p.Method, p.UserAgent)
	}
	if p.TLS.JA4 == "" || p.TLS.JA4R == "" || p.TLS.Negotiated == "" {
		return p, fmt.Errorf("missing JA4/JA4R or negotiated TLS version")
	}
	if p.HTTPVersion != "h2" && p.HTTPVersion != "HTTP/1.1" {
		return p, fmt.Errorf("unexpected HTTP version %q", p.HTTPVersion)
	}
	if p.HTTPVersion == "h2" && p.HTTP2.Akamai == "" {
		return p, fmt.Errorf("HTTP2 response missing Akamai fingerprint")
	}
	return p, nil
}

func finishPeet(t *testing.T, o *peetObservation, status int, reader io.Reader) {
	t.Helper()
	o.HTTPStatus = status
	body, err := io.ReadAll(io.LimitReader(reader, 2*1024*1024+1))
	if err != nil {
		o.Error = err.Error()
		t.Fatal(err)
	}
	if len(body) > 2*1024*1024 {
		o.Error = "peet response exceeds 2 MiB"
		t.Fatal(o.Error)
	}
	if json.Valid(body) {
		o.Response = append([]byte(nil), body...)
	}
	if status != 200 {
		o.Error = fmt.Sprintf("peet returned HTTP %d", status)
		t.Fatal(o.Error)
	}
	o.Observed, err = validatePeet(body, o.ExpectedJA3, o.RequestedUA)
	if err != nil {
		o.Error = err.Error()
		t.Fatal(err)
	}
	t.Logf("endpoint=%s HTTP=%s TLS=%s JA3=%s JA3_HASH=%s JA4=%s JA4R=%s Akamai=%s", peetURL, o.Observed.HTTPVersion, o.Observed.TLS.Negotiated, o.Observed.TLS.JA3, o.Observed.TLS.JA3Hash, o.Observed.TLS.JA4, o.Observed.TLS.JA4R, o.Observed.HTTP2.Akamai)
}
