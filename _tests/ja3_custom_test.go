package tests

import (
	fastls "github.com/FastTLS/fastls"
	"testing"
)

func requestPeetJA3(t *testing.T, input, expected string) {
	t.Helper()
	o := startPeet(t, input, expected)
	resp, err := fastls.NewClient().Do(peetURL, fastls.Options{
		Fingerprint: fastls.Ja3Fingerprint{FingerprintValue: input},
		UserAgent:   peetUserAgent, Timeout: 20, DisableRedirect: true,
		Headers: map[string]string{"Accept": "application/json"},
	}, "GET")
	defer resp.Client.CloseIdleConnections()
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		o.Error = err.Error()
		t.Fatal(err)
	}
	finishPeet(t, o, resp.Status, resp.Body)
}

func TestCustomJA3Fingerprint(t *testing.T) {
	requestPeetJA3(t,
		"771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,0",
		"771,4865-4866-4867,0-10-11-13-16-43-45-51,29-23-24,0")
}

func TestJA3PointFormatsVariation(t *testing.T) {
	for _, tc := range []struct{ name, input, expected string }{
		{"with_zero", "771,4865-4866-4867,43-10-51-13-0-16-45,29-23-24,0", "771,4865-4866-4867,43-10-11-51-13-0-16-45,29-23-24,0"},
		{"empty", "771,4865-4866-4867,43-10-51-13-0-16-45,29-23-24,", "771,4865-4866-4867,43-10-51-13-0-16-45,29-23-24,"},
	} {
		t.Run(tc.name, func(t *testing.T) { requestPeetJA3(t, tc.input, tc.expected) })
	}
}
