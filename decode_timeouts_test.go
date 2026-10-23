package fastls

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStreamingDecodeLimitChecksumAndCancellation(t *testing.T) {
	data := bytes.Repeat([]byte("native decode\x00"), 10000)
	var encoded bytes.Buffer
	z := gzip.NewWriter(&encoded)
	z.Write(data)
	z.Close()
	for _, maximum := range []int64{int64(len(data)), int64(len(data) - 1)} {
		r := Response{Status: 200, Body: io.NopCloser(bytes.NewReader(encoded.Bytes())), HeaderValues: map[string][]string{"Content-Encoding": {"gzip"}}}
		if err := decodeResponse(context.Background(), &r, "GET", maximum); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r.Body)
		r.Body.Close()
		if maximum == int64(len(data)) {
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("data=%d err=%v", len(got), err)
			}
		} else {
			var decoding *DecodeError
			if !errors.As(err, &decoding) || int64(len(got)) > maximum {
				t.Fatalf("limit: bytes=%d err=%v", len(got), err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := Response{Status: 200, Body: io.NopCloser(bytes.NewReader(encoded.Bytes())), HeaderValues: map[string][]string{"Content-Encoding": {"gzip"}}}
	if err := decodeResponse(ctx, &r, "GET", 0); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := r.Body.Read(make([]byte, 16)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
	r.Body.Close()
}

func TestPhaseTimeoutsStdlibAndFingerprint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/body" {
			w.Write([]byte("first"))
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	for _, fingerprint := range []bool{false, true} {
		opts := Options{}
		if fingerprint {
			opts.Fingerprint = Ja3Fingerprint{FingerprintValue: "771,4865-4866-4867,0-10-13-16-43-45-51,29-23-24,"}
		}
		s, err := NewSession(opts)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err = s.DoContext(ctx, server.URL+"/headers", RequestOptions{Timeouts: Timeouts{Connect: time.Second, Headers: 50 * time.Millisecond}}, "GET")
		var timeout *TimeoutError
		if !errors.As(err, &timeout) || timeout.Phase != "headers" {
			t.Fatalf("headers fingerprint=%t err=%v", fingerprint, err)
		}
		r, err := s.DoContext(ctx, server.URL+"/body", RequestOptions{Timeouts: Timeouts{Read: 50 * time.Millisecond}}, "GET")
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(r.Body)
		r.Body.Close()
		s.Close()
		cancel()
		if !errors.As(err, &timeout) || timeout.Phase != "read" {
			t.Fatalf("body fingerprint=%t err=%v", fingerprint, err)
		}
	}
}
