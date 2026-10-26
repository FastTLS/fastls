# Fastls

[中文](README.md) · [Documentation](https://fasttls.github.io/fastls/)

Go HTTP client with configurable TLS/HTTP fingerprints, ordered headers, browser profiles, JA3/JA4R and complete profile.Spec support. Stable core: `v0.1.1`; module path: `github.com/FastTLS/fastls` (no `/v2`). Requires Go 1.26+.

```sh
go get github.com/FastTLS/fastls@v0.1.1
go get github.com/FastTLS/imitate@v0.1.0
```

## Complete example

```go
package main

import (
    "context"
    "fmt"
    "io"
    "log"
    "time"

    fastls "github.com/FastTLS/fastls"
    "github.com/FastTLS/fastls/imitate"
    generators "github.com/FastTLS/imitate"
)

func main() {
    options := fastls.Options{
        FingerprintProvider: generators.New(),
        VerifyTLS: true,
    }
    if _, err := imitate.Use(&options, "chrome/156/windows"); err != nil {
        log.Fatal(err)
    }
    if err := fetch(options); err != nil {
        log.Fatal(err)
    }
}

func fetch(options fastls.Options) error {
    session, err := fastls.NewSession(options)
    if err != nil { return err }
    defer session.Close()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    response, err := session.DoContext(ctx, "https://example.com/", fastls.RequestOptions{}, "GET")
    if err != nil {
        if response.Body != nil { response.Body.Close() }
        return err
    }
    defer response.Body.Close()
    fmt.Println(response.Status, response.Protocol, response.FinalURL)
    _, err = io.Copy(io.Discard, response.Body)
    return err
}
```

## Capabilities and limits

HTTP/1.1 and HTTP/2, profiles, JA3/JA4R, ordered headers, cookies, HTTP/HTTPS CONNECT and SOCKS5 proxies, reusable sessions, streaming, cancellation, phase timeouts, trailers, decoding and H2 duplex are supported. Close response bodies and sessions. Read errors can occur after headers arrive. Session total deadlines come from the request context, not Options.Timeout.

Explicitly enable `VerifyTLS: true` for fingerprinted Go TCP TLS requests; the historical zero value does not verify certificates. Python and Node SDKs verify by default. Complete Spec support covers H1/H2. HTTP/3 cannot reproduce arbitrary ClientHello ordering and rejects proxies. WS/WSS uses HTTP/1.1 Upgrade; compression, arbitrary Upgrade header order, redirects and H2/H3 Extended CONNECT are unsupported. Browser identities are configuration labels, not full-browser equivalence or vendor certification. This library does not execute page JavaScript or handle CAPTCHAs. Unreleased development changes are not stable-release guarantees.

## Documentation, license and disclaimer

See the [Chinese README](README.md), [fingerprint guide](imitate/README.md), [development guide](DEVELOPMENT.md), [release policy](RELEASE.md) and [issues](https://github.com/FastTLS/fastls/issues). Remove credentials and personal data before sharing examples.

FastTLS-owned code is [Apache-2.0](LICENSE); retain [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES.md). Use only systems and data you are authorized to access and follow applicable laws and service terms. Provided as-is under the license, without guarantees of availability, anonymity, browser equivalence or acceptance by third-party services. Browser names do not imply affiliation. The license and applicable law govern warranty and liability; this notice does not change license rights.
