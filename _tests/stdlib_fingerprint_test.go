package tests

import (
	fastls "github.com/FastTLS/fastls"
	"net/http"
	"testing"
	"time"
)

func TestGoStdlibFingerprint(t *testing.T) {
	o := startPeet(t, "", "")
	// Direct TLS baseline: environment proxy settings are intentionally not used.
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest("GET", peetURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", peetUserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		o.Error = err.Error()
		t.Fatal(err)
	}
	defer resp.Body.Close()
	finishPeet(t, o, resp.StatusCode, resp.Body)
}

func TestFastlsStdlibFingerprint(t *testing.T) {
	o := startPeet(t, "", "")
	resp, err := fastls.NewClient().Do(peetURL, fastls.Options{UserAgent: peetUserAgent, Timeout: 20, DisableRedirect: true}, "GET")
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
