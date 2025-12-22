<div align="center">
  <img src="logo.png" alt="Fastls Logo" width="200">
  
  # Fastls
  
  High-performance TLS fingerprint simulation library, supporting JA3/JA4R and browser TLS fingerprint simulation.
  
  > English | [中文](./README.md)
</div>

## Features

- ✅ High Performance - Built-in goroutine pool for asynchronous request handling
- ✅ TLS Fingerprint Simulation - Support for JA3, JA4R (experimental), and various browser TLS fingerprint simulation
- ✅ Browser Support - Support for mainstream browsers including Chrome, Firefox, Edge, Safari, Opera, etc.
- ✅ Custom Header Ordering - Implemented via [fhttp](https://github.com/Wuhan-Dongce/fhttp)
- ✅ Proxy Support - HTTP, HTTPS, SOCKS5
- ✅ Multiple Service Modes - Fetch service, MITM proxy, RPC service (JSON-RPC/gRPC)

## Quick Start

### Go

```bash
go get github.com/FastTLS/fastls
```

```go
package main

import (
    "fmt"
    fastls "github.com/FastTLS/fastls"
    "github.com/FastTLS/fastls/imitate"
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
cd services/fastls-fetch
go run fetch_server.go
```

### MITM Proxy

Man-in-the-middle proxy with dynamic SSL certificate generation.

```bash
cd services/fastls-mitm
go run main.go -addr :8888 -browser chrome142
```

### RPC Service

Provides both JSON-RPC 2.0 and gRPC implementations.

**JSON-RPC:**
```bash
cd services/fastls-rpc/jsonrpc
go run rpc_server.go
```

**gRPC:**
```bash
cd services/fastls-rpc/grpc
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

- [Fastls Usage Examples](./_examples/)
- [Fetch Service Documentation](./services/fastls-fetch/README.md)
- [MITM Proxy Documentation](./services/fastls-mitm/README.md)
- [RPC Service Documentation](./services/fastls-rpc/README.md)

## License

See [LICENSE](./LICENSE) file for details.

