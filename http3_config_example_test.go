package fastls_test

import (
	"fmt"
	fastls "github.com/FastTLS/fastls"
	"time"
)

func ExampleHTTP3Config() {
	disabled := time.Duration(0)
	config := &fastls.HTTP3Config{KeepAlivePeriod: &disabled, MaxResponseHeaderBytes: 64 << 10}
	session, err := fastls.NewSession(fastls.Options{HTTPVersion: fastls.HTTPVersion3, HTTP3: config, VerifyTLS: true})
	if err != nil {
		panic(err)
	}
	defer session.Close()
	config.MaxResponseHeaderBytes = 128 << 10
	effective, ok := session.EffectiveHTTP3Config()
	fmt.Println(ok, effective.MaxResponseHeaderBytes, effective.KeepAlivePeriod, len(fastls.HTTP3Capabilities()))
	// Output: true 65536 0s 7
}
