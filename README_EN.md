# Fastls

English · [中文](README.md)

A Go request library for custom JA3/JA4R fingerprints, complete profile.Spec execution, ordered HTTP headers, and HTTP/HTTPS/SOCKS5 proxies. The optional [FastTLS/imitate](https://github.com/FastTLS/imitate) library generates browser configurations; Fastls applies them and sends requests.

The current v2 worktree is an unpublished development candidate. Public module installation does not establish availability of these changes.

## Usage

```go
import (
    "context"
    "io"

    fastls "github.com/FastTLS/fastls"
    "github.com/FastTLS/fastls/imitate"
    generators "github.com/FastTLS/imitate"
)

var fingerprints = generators.New() // Safe to share between requests.

func fetch(ctx context.Context, target string) ([]byte, error) {
    options := fastls.Options{
        FingerprintProvider: fingerprints,
        Headers: map[string]string{"User-Agent": "my-client/1.0"},
        Timeout: 15,
    }
    if _, err := imitate.Use(&options, "chrome/156/windows"); err != nil {
        return nil, err
    }
    resp, err := fastls.NewClient().DoContext(ctx, target, options, "GET")
    if err != nil {
        if resp.Body != nil {
            resp.Body.Close()
        }
        return nil, err
    }
    defer resp.Client.CloseIdleConnections()
    defer resp.Body.Close()
    return io.ReadAll(resp.Body)
}
```

`Use` requires an explicit Provider. Caller header values override generated defaults. Downstream adapters handle legacy names and UA inference. Custom JA3/JA4R, `imitate.Apply`, and `Options.Profile` work without a generator. Consult the provider's List, Match and evidence for supported IDs and verification coverage; generating a version identity does not verify a real browser's complete fingerprint.

Close response bodies after use. Requests without a fingerprint return after response headers arrive; cancellation, timeouts and network errors can occur while reading Body. Complete Spec execution supports HTTP1/HTTP2. One-shot requests and `Session` support request trailers; `Session` also supports streaming uploads, H2 duplex, phase timeouts, and opt-in content decoding. Response trailers are complete after EOF, and responses report the final protocol and post-redirect URL.

H3 accepts a q-prefixed JA4R value as a validated protocol selector and honors `VerifyTLS` and `TLSRootCAs`. Go's standard QUIC TLS stack cannot reproduce arbitrary ClientHello extension order, so this is not a claim of complete browser H3 fingerprint fidelity. H3 explicitly rejects configured proxies instead of silently connecting directly. WS/WSS uses HTTP/1.1 Upgrade; arbitrary Upgrade header order, compression, redirects, and HTTP/2 Extended CONNECT are outside the current scope. Cancellation during subsequent H2 dialing remains a bounded capability; see the integration notes.

## Documentation and tools

- [Fingerprint application, offline registration and capability limits](imitate/README.md)
- [Development, tests and directory guide](DEVELOPMENT.md)
- [Shared profile specification](profile/README.md)
- [Command-line probe source](integration/imitate/cmd/fastls-probe/main.go)
- [Test tools](tools/README.md)
- [Independent services and lab](services/README.md)
- [Release prerequisites](RELEASE.md)

## License

FastTLS-authored Fastls code is licensed under the [Apache License 2.0](LICENSE); see [NOTICE](NOTICE). Independent Go submodules carry the same license. Third-party code and dependencies retain their original terms; see [third-party notices and remaining provenance checks](THIRD_PARTY_NOTICES.md). This license selection does not relicense third-party works or constitute release approval.
