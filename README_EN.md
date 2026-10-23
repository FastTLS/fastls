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

Close response bodies after use. Requests without a fingerprint return after response headers arrive; cancellation, timeouts and network errors can occur while reading Body. Complete Spec execution supports HTTP1/HTTP2. H3, arbitrary WS Upgrade header ordering, and cancellation during subsequent H2 dialing remain bounded capabilities; see the integration notes.

## Documentation and tools

- [Fingerprint application, offline registration and capability limits](imitate/README.md)
- [Development, tests and directory guide](DEVELOPMENT.md)
- [Shared profile specification](profile/README.md)
- [Command-line probe source](integration/imitate/cmd/fastls-probe/main.go)
- [Test tools](tools/README.md)
- [Independent services and lab](services/README.md)
- [Release prerequisites](RELEASE.md)

## License

This repository currently has no LICENSE file. Authorization and licensing must be confirmed before publication.
