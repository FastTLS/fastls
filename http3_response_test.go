package fastls

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestH3ResponseTrailersSurviveEOF(t *testing.T) {
	for _, announced := range []bool{true, false} {
		t.Run(map[bool]string{true: "announced", false: "unannounced"}[announced], func(t *testing.T) {
			session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if announced {
					w.Header().Set("Trailer", "X-Checksum")
				}
				_, _ = io.WriteString(w, "payload")
				w.(http.Flusher).Flush()
				if announced {
					w.Header().Set("X-Checksum", "complete")
				} else {
					w.Header().Set(http.TrailerPrefix+"X-Checksum", "complete")
				}
			}))
			response, err := session.DoContext(context.Background(), url, RequestOptions{}, "GET")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "payload" {
				t.Fatalf("body=%q err=%v", body, err)
			}
			if got := response.Trailer.Get("X-Checksum"); got != "complete" {
				t.Fatalf("trailer after EOF = %q, want complete", got)
			}
		})
	}
}

func TestH3RejectsRequestTrailersBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	response, err := session.DoContext(context.Background(), url, RequestOptions{Body: "body", Trailers: http.Header{"X-Checksum": []string{"value"}}}, "POST")
	if response.Body != nil {
		response.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "request trailers") {
		t.Fatalf("unsupported trailers error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("unsupported request reached the network")
	}
}

func TestH3TruncatedResponseIsNotEOF(t *testing.T) {
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "20")
		_, _ = io.WriteString(w, "short")
	}))
	response, err := session.DoContext(context.Background(), url, RequestOptions{}, "GET")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err == nil || string(body) != "short" {
		t.Fatalf("truncated body=%q error=%v", body, err)
	}
}

func TestH3HeadDoesNotRequireContentLengthBytes(t *testing.T) {
	session, url := localH3Session(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "20")
		w.WriteHeader(http.StatusOK)
	}))
	response, err := session.DoContext(context.Background(), url, RequestOptions{}, http.MethodHead)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || len(body) != 0 {
		t.Fatalf("HEAD body=%q error=%v", body, err)
	}
}
