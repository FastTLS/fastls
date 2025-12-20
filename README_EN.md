<div align="center">
  <img src="logo.png" alt="Fastls Logo" width="200">
  
  # Fastls
  
  High-performance TLS fingerprint spoofing library with support for JA3/JA4R fingerprints and browser emulation.
  
  > English | [中文](./README.md)
</div>

## Features

- ✅ High Performance - Built-in goroutine pool for asynchronous request handling
- ✅ TLS Fingerprint Spoofing - Support for JA3 fingerprints, JA4R fingerprints (experimental)
- ✅ Browser Emulation - Support for Chrome, Firefox, Edge, and other browsers
- ✅ Custom Header Ordering - Implemented via [fhttp](https://github.com/useflyent/fhttp)
- ✅ Proxy Support - HTTP, HTTPS, SOCKS5
- ✅ Multiple Service Modes - Fetch service, MITM proxy, RPC service (JSON-RPC/gRPC)

## Quick Start

### Go

```bash
go get github.com/ChengHoward/Fastls
```

```go
package main

import (
    "fmt"
    fastls "github.com/ChengHoward/Fastls"
    "github.com/ChengHoward/Fastls/imitate"
)

func main() {
    client := fastls.NewClient()
    
    options := fastls.Options{
        URL:    "https://tls.peet.ws/api/all",
        Method: "GET",
    }
    
    // Use Chrome142 fingerprint
    imitate.Chrome142(&options)
    
    resp, err := client.Do(options.URL, options, options.Method)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

## Service Modes

### Fetch Service

RESTful API service based on HTTP.

```bash
cd main/fetch
go run fetch_server.go
```

### MITM Proxy

Man-in-the-middle proxy with dynamic SSL certificate generation.

```bash
cd main/mitm
go run mitm_proxy.go -addr :8888 -browser chrome142
```

### RPC Service

Provides both JSON-RPC 2.0 and gRPC implementations.

**JSON-RPC:**
```bash
cd main/rpc/jsonrpc
go run rpc_server.go
```

**gRPC:**
```bash
cd main/rpc/grpc
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/fastls.proto
go run grpc_server.go
```

## Supported Browsers

- Chrome / Chrome120 / Chrome142
- Chromium
- Edge
- Firefox
- Safari
- Opera

## Documentation

- [Fetch Service Documentation](./main/fetch/README.md)
- [MITM Proxy Documentation](./main/mitm/README.md)
- [RPC Service Documentation](./main/rpc/README.md)

## License

See [LICENSE](./LICENSE) file for details.

