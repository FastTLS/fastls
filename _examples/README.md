# Fastls 使用示例

本目录包含 Fastls 库的各种使用示例。

## 示例列表

### TLS 指纹测试示例

- **example_browserleaks_firefox.go** - 使用 Firefox 指纹访问 browserleaks.com
- **example_browserleaks_firefox2.go** - Firefox 指纹的另一种用法示例
- **example_tls_peet_chrome.go** - 使用 Chrome 指纹访问 tls.peet.ws
- **example_tls_peet_chrome142.go** - 使用 Chrome142 指纹访问 tls.peet.ws
- **example_tls_peet_edge.go** - 使用 Edge 指纹访问 tls.peet.ws
- **go_net.go** - 使用标准 Go net/http 库的代理示例

## 运行示例

```bash
# 进入示例目录
cd _examples

# 运行示例
go run example_browserleaks_firefox.go
go run example_tls_peet_chrome.go
```

## 更多示例

- [Fetch 服务客户端示例](./services/fastls-fetch/example/)
- [MITM 代理客户端示例](./services/fastls-mitm/example/)
- [RPC 服务客户端示例](./services/fastls-rpc/grpc/grpc_example/) 和 [JSON-RPC 示例](./services/fastls-rpc/jsonrpc/example/)

