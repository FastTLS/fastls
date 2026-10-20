package tests

import (
	"strings"
	"testing"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
)

func TestGenerateSecChUaKnownSeeds(t *testing.T) {
	cases := []struct {
		seed   int
		brand  string
		expect string
	}{
		{150, "Google Chrome", `"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"`},
		{150, "Microsoft Edge", `"Not;A=Brand";v="8", "Chromium";v="150", "Microsoft Edge";v="150"`},
		{152, "Google Chrome", `"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`},
		{160, "Google Chrome", `"Chromium";v="160", "Google Chrome";v="160", "Not)A;Brand";v="99"`},
		{160, "Microsoft Edge", `"Chromium";v="160", "Microsoft Edge";v="160", "Not)A;Brand";v="99"`},
	}
	for _, tc := range cases {
		got := imitate.GenerateSecChUa(tc.seed, tc.brand)
		if got != tc.expect {
			t.Errorf("seed=%d brand=%s\n  expect: %s\n  got:    %s", tc.seed, tc.brand, tc.expect, got)
		}
	}
}

func TestChromeVersion160(t *testing.T) {
	options := &fastls.Options{Headers: make(map[string]string)}
	imitate.ChromeVersion(options, 160)

	if options.Fingerprint.Value() != imitate.Chrome150JA3 {
		t.Errorf("TLS 应使用 Chrome150 JA3")
	}
	if !strings.Contains(options.UserAgent, "Chrome/160.0.0.0") {
		t.Errorf("UA 应含 Chrome/160: %s", options.UserAgent)
	}
	if options.Headers["Sec-Ch-Ua"] != imitate.GenerateSecChUa(160, "Google Chrome") {
		t.Errorf("Sec-Ch-Ua 不匹配: %s", options.Headers["Sec-Ch-Ua"])
	}
}

func TestEdgeVersion160(t *testing.T) {
	options := &fastls.Options{Headers: make(map[string]string)}
	imitate.EdgeVersion(options, 160)

	if !strings.Contains(options.UserAgent, "Chrome/160.0.0.0") || !strings.Contains(options.UserAgent, "Edg/160.0.0.0") {
		t.Errorf("UA 应含 Chrome/160 与 Edg/160: %s", options.UserAgent)
	}
	expect := imitate.GenerateSecChUa(160, "Microsoft Edge")
	if options.Headers["Sec-Ch-Ua"] != expect {
		t.Errorf("Sec-Ch-Ua 不匹配\n  expect: %s\n  got:    %s", expect, options.Headers["Sec-Ch-Ua"])
	}
}

func TestChromeAndEdgeDefaultAre160(t *testing.T) {
	chrome := &fastls.Options{Headers: make(map[string]string)}
	imitate.Chrome(chrome)
	if !strings.Contains(chrome.UserAgent, "Chrome/160") {
		t.Errorf("Chrome() 默认应为 160: %s", chrome.UserAgent)
	}

	edge := &fastls.Options{Headers: make(map[string]string)}
	imitate.Edge(edge)
	if !strings.Contains(edge.UserAgent, "Edg/160") {
		t.Errorf("Edge() 默认应为 160: %s", edge.UserAgent)
	}
}
