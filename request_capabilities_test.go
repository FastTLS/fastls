package fastls

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStandardRequestMethodMatrixAndMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Seen-Method", r.Method)
		w.Header().Set("X-Seen-Body", string(body))
		fmt.Fprint(w, "response")
	}))
	defer server.Close()
	session, err := NewSession(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "x-custom"} {
		t.Run(method, func(t *testing.T) {
			body := ""
			if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" || method == "x-custom" {
				body = "payload"
			}
			response, err := session.DoContext(context.Background(), server.URL+"/method", RequestOptions{Body: body}, method)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			responseBody, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			wantMethod := strings.ToUpper(method)
			headers := http.Header(response.HeaderValues)
			if headers.Get("X-Seen-Method") != wantMethod || headers.Get("X-Seen-Body") != body {
				t.Fatalf("method/body = %q/%q, want %q/%q", headers.Get("X-Seen-Method"), headers.Get("X-Seen-Body"), wantMethod, body)
			}
			if method == "HEAD" && len(responseBody) != 0 {
				t.Fatalf("HEAD returned body %q", responseBody)
			}
			if response.Protocol != "HTTP/1.1" || response.FinalURL != server.URL+"/method" {
				t.Fatalf("protocol/final URL = %q/%q", response.Protocol, response.FinalURL)
			}
		})
	}
}

func TestExplicitHostAndDuplicateHostValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Host)
	}))
	defer server.Close()

	response, err := NewClient().Do(server.URL, Options{Headers: map[string]string{"Host": "virtual.example"}}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	response.Client.CloseIdleConnections()
	if err != nil || string(body) != "virtual.example" {
		t.Fatalf("host response = %q, err = %v", body, err)
	}

	response, err = NewClient().Do(server.URL, Options{HeaderValues: map[string][]string{"Host": {"one.example", "two.example"}}}, "GET")
	if response.Body != nil {
		response.Body.Close()
	}
	response.Client.CloseIdleConnections()
	if err == nil || !strings.Contains(err.Error(), "Host requires exactly one value") {
		t.Fatalf("duplicate Host error = %v", err)
	}
}

func TestRequestAndResponseTrailersHTTP1AndHTTP2(t *testing.T) {
	for _, protocol := range []string{"http1", "http2"} {
		for _, bodyMode := range []string{"buffered", "reader"} {
			t.Run(protocol+"/"+bodyMode, func(t *testing.T) {
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					w.Header().Set("Trailer", "X-Response-Trailer")
					fmt.Fprintf(w, "%s|%s", body, r.Trailer.Get("X-Request-Trailer"))
					w.Header().Set("X-Response-Trailer", "response-value")
				}))
				if protocol == "http2" {
					server.EnableHTTP2 = true
					server.StartTLS()
				} else {
					server.Start()
				}
				defer server.Close()

				session, err := NewSession(Options{})
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				request := RequestOptions{Trailers: http.Header{"X-Request-Trailer": {"request-value"}}}
				if bodyMode == "reader" {
					request.BodyReader = io.NopCloser(strings.NewReader("payload"))
				} else {
					request.Body = "payload"
				}
				response, err := session.DoContext(context.Background(), server.URL, request, "POST")
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != "payload|request-value" || response.Trailer.Get("X-Response-Trailer") != "response-value" {
					t.Fatalf("body/trailer = %q/%q", body, response.Trailer.Get("X-Response-Trailer"))
				}
				wantProtocol := "HTTP/1.1"
				if protocol == "http2" {
					wantProtocol = "HTTP/2.0"
				}
				if response.Protocol != wantProtocol {
					t.Fatalf("protocol = %q, want %q", response.Protocol, wantProtocol)
				}
			})
		}
	}
}

func TestOneShotRequestTrailers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_, _ = fmt.Fprint(w, r.Trailer.Get("X-Request-Trailer"))
	}))
	defer server.Close()

	response, err := NewClient().Do(server.URL, Options{
		Body:     "payload",
		Trailers: http.Header{"X-Request-Trailer": {"one-shot"}},
	}, "POST")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Client.CloseIdleConnections()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "one-shot" {
		t.Fatalf("request trailer = %q", body)
	}
}
