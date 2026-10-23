// fastls-probe is a small real client for exercising the official client profile.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	fastls "github.com/FastTLS/fastls"
	"github.com/FastTLS/fastls/imitate"
	generators "github.com/FastTLS/imitate"
)

func main() {
	url := flag.String("url", "", "request URL (required)")
	selector := flag.String("profile", "client/fastls-probe/1/any/portable-h1", "finite provider selector")
	flag.Parse()
	if *url == "" {
		fmt.Fprintln(os.Stderr, "-url is required")
		os.Exit(2)
	}
	o := fastls.Options{Timeout: 30}
	m, err := imitate.Use(&o, *selector, imitate.WithProvider(generators.New()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	r, err := fastls.NewClient().Do(*url, o, "GET")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer r.Client.CloseIdleConnections()
	defer r.Body.Close()
	_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"status": r.Status, "match": m})
	if _, err = io.Copy(os.Stdout, r.Body); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
