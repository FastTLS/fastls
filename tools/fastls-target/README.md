# Fastls Target - HTTP 靶场工具

一个简单的 HTTP 靶场服务器，用于测试和验证 HTTP 请求。

## 功能特性

- ✅ 接收所有 HTTP/HTTPS 请求（GET、POST、PUT、DELETE 等）
- ✅ 返回请求详细信息（方法、路径、头部、请求体等）
- ✅ 可配置响应状态码和响应体
- ✅ 支持响应延迟（模拟慢速服务器）
- ✅ 请求统计功能
- ✅ 健康检查端点
- ✅ 详细/安静模式
- ✅ 支持 HTTPS（自动生成自签名证书或使用自定义证书）

## 安装

```bash
cd tools/fastls-target
go build -o fastls-target
```

## 使用方法

### 基本用法

```bash
# 启动服务器（默认监听 :8080）
./fastls-target

# 指定监听地址
./fastls-target -addr :9090

# 指定默认响应状态码
./fastls-target -response 404

# 指定响应体内容
./fastls-target -body "Hello, World!"

# 添加响应延迟（模拟慢速服务器）
./fastls-target -delay 2s
```

### 输出模式

```bash
# 详细输出模式（显示完整的请求信息）
./fastls-target -v

# 安静模式（只显示基本日志）
./fastls-target -q
```

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-addr` | 监听地址 | `:8080` |
| `-response` | 默认响应状态码 | `200` |
| `-body` | 响应体内容（如果设置，将覆盖默认 JSON 响应） | - |
| `-delay` | 响应延迟时间 | `0` |
| `-v` | 详细输出模式 | `false` |
| `-q` | 安静模式 | `false` |
| `-tls` | 自动生成自签名证书并启用 HTTPS | `false` |
| `-cert` | TLS 证书文件路径（必须与 `-key` 一起使用） | - |
| `-key` | TLS 私钥文件路径（必须与 `-cert` 一起使用） | - |

## API 端点

### GET / - 返回请求信息

返回请求的详细信息（JSON 格式）：

```json
{
  "status": 200,
  "message": "OK",
  "method": "GET",
  "path": "/",
  "query": "",
  "headers": {
    "Accept": "*/*",
    "User-Agent": "curl/7.68.0"
  },
  "body": "",
  "remote": "127.0.0.1:54321",
  "timestamp": "2025-12-23T14:30:00Z"
}
```

### GET /health - 健康检查

返回服务器健康状态：

```json
{
  "status": "healthy",
  "timestamp": "2025-12-23T14:30:00Z",
  "uptime": "5m30s"
}
```

### GET /stats - 请求统计

返回请求统计信息：

```json
{
  "total_requests": 150,
  "by_method": {
    "GET": 100,
    "POST": 50
  },
  "by_path": {
    "/": 80,
    "/api": 70
  }
}
```

### 其他端点

所有其他路径都会返回请求信息，例如：
- `GET /api/users`
- `POST /api/data`
- `PUT /api/update`
- `DELETE /api/delete`

## 使用示例

### 基本测试

```bash
# 启动 HTTP 服务器
./fastls-target -addr :8080

# 在另一个终端测试
curl http://localhost:8080/
curl http://localhost:8080/api/test
curl -X POST http://localhost:8080/api/data -d '{"key":"value"}'

# 启动 HTTPS 服务器（自动生成自签名证书）
./fastls-target -addr :8443 -tls

# 测试 HTTPS（需要忽略证书验证）
curl -k https://localhost:8443/
curl -k https://localhost:8443/api/test
```

### 使用压力测试工具测试

```bash
# 启动靶场服务器
./fastls-target -addr :8080

# 使用 fastls-bench 进行压力测试
cd ../fastls-bench
./fastls-bench -url http://localhost:8080/ -c 50 -d 30s
```

### 模拟慢速服务器

```bash
# 启动服务器，每个请求延迟 1 秒
./fastls-target -addr :8080 -delay 1s

# 测试
curl http://localhost:8080/
```

### 返回自定义响应

```bash
# 启动服务器，返回自定义响应体
./fastls-target -addr :8080 -body "Custom Response" -response 200

# 测试
curl http://localhost:8080/
# 输出: Custom Response
```

### 模拟错误响应

```bash
# 启动服务器，返回 404 错误
./fastls-target -addr :8080 -response 404

# 测试
curl http://localhost:8080/
# 返回 404 状态码
```

### 查看请求统计

```bash
# 启动服务器
./fastls-target -addr :8080

# 发送一些请求
curl http://localhost:8080/
curl http://localhost:8080/api
curl -X POST http://localhost:8080/api/data

# 查看统计
curl http://localhost:8080/stats
```

## 使用场景

### 1. API 测试

测试各种 HTTP 方法和路径：

```bash
./fastls-target -v

# 测试 GET
curl http://localhost:8080/api/users

# 测试 POST
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"John","age":30}'

# 测试 PUT
curl -X PUT http://localhost:8080/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"Jane","age":25}'

# 测试 DELETE
curl -X DELETE http://localhost:8080/api/users/1
```

### 2. 压力测试

配合 `fastls-bench` 进行压力测试：

```bash
# 启动 HTTP 靶场服务器
./fastls-target -addr :8080

# 进行 HTTP 压力测试
../fastls-bench/fastls-bench -url http://localhost:8080/ -c 100 -d 60s

# 启动 HTTPS 靶场服务器
./fastls-target -addr :8443 -tls

# 进行 HTTPS 压力测试（需要 -k 参数忽略证书验证）
../fastls-bench/fastls-bench -url https://localhost:8443/ -c 100 -d 60s -k
```

### 3. 代理测试

通过 MITM 代理测试：

```bash
# 启动 MITM 代理
cd ../../../fastls-mitm
./fastls-mitm -addr :8888

# 启动 HTTP 靶场服务器
cd ../fastls/tools/fastls-target
./fastls-target -addr :8080

# 通过代理测试 HTTP
curl -x http://127.0.0.1:8888 http://localhost:8080/

# 启动 HTTPS 靶场服务器
./fastls-target -addr :8443 -tls

# 通过代理测试 HTTPS
curl -x http://127.0.0.1:8888 -k https://localhost:8443/
```

### 4. 调试请求

使用详细模式查看完整的请求信息：

```bash
./fastls-target -v

# 发送请求
curl -X POST http://localhost:8080/api/test \
  -H "Authorization: Bearer token" \
  -H "X-Custom-Header: value" \
  -d '{"test":"data"}'
```

## HTTPS 支持

### 自动生成自签名证书

最简单的方式是使用 `-tls` 参数自动生成自签名证书：

```bash
./fastls-target -addr :8443 -tls
```

证书会自动生成，有效期1年，适用于 `localhost` 和 `127.0.0.1`。

### 使用自定义证书

如果你有自己的证书和私钥文件：

```bash
./fastls-target -addr :8443 -cert server.crt -key server.key
```

### 客户端访问

使用自签名证书时，客户端需要忽略证书验证：

```bash
# curl
curl -k https://localhost:8443/

# fastls-bench
./fastls-bench -url https://localhost:8443/ -k
```

## HTTPS 支持

### 自动生成自签名证书

最简单的方式是使用 `-tls` 参数自动生成自签名证书：

```bash
./fastls-target -addr :8443 -tls
```

证书会自动生成，有效期1年，适用于 `localhost` 和 `127.0.0.1`。

### 使用自定义证书

如果你有自己的证书和私钥文件：

```bash
./fastls-target -addr :8443 -cert server.crt -key server.key
```

### 客户端访问

使用自签名证书时，客户端需要忽略证书验证：

```bash
# curl
curl -k https://localhost:8443/

# fastls-bench
./fastls-bench -url https://localhost:8443/ -k
```

## 注意事项

1. **响应体**: 如果设置了 `-body` 参数，将返回纯文本响应，而不是 JSON
2. **延迟**: `-delay` 参数会影响所有请求的响应时间，用于模拟慢速服务器
3. **统计**: 统计信息在服务器运行期间累积，重启后会重置
4. **并发**: 服务器支持并发请求，统计信息使用互斥锁保护
5. **HTTPS 证书**: 使用 `-tls` 自动生成的证书是自签名证书，客户端需要添加 `-k` 参数忽略证书验证
5. **HTTPS 证书**: 使用 `-tls` 自动生成的证书是自签名证书，客户端需要添加 `-k` 参数忽略证书验证

## 与 fastls-bench 配合使用

```bash
# 终端1: 启动靶场服务器
./fastls-target -addr :8080 -v

# 终端2: 进行压力测试
../fastls-bench/fastls-bench \
  -url http://localhost:8080/ \
  -c 50 \
  -d 30s \
  -v

# 终端3: 查看统计
watch -n 1 'curl -s http://localhost:8080/stats | jq'
```

