# Fastls Bench - HTTP 压力测试工具

一个简单高效的 HTTP 压力测试工具，支持代理和并发测试。

## 功能特性

- ✅ 支持设置代理（HTTP/HTTPS）
- ✅ 可配置并发数和持续时间
- ✅ 支持指定总请求数
- ✅ 详细的统计信息（QPS、响应时间、成功率等）
- ✅ 状态码分布统计
- ✅ 使用标准 Go net/http 库

## 安装

```bash
cd tools/fastls-bench
go build -o fastls-bench
```

## 使用方法

### 基本用法

```bash
# 基本压力测试（10并发，持续10秒）
./fastls-bench -url https://example.com

# 指定并发数和持续时间
./fastls-bench -url https://example.com -c 50 -d 30s

# 指定总请求数
./fastls-bench -url https://example.com -c 20 -n 1000
```

### 使用代理

```bash
# 通过 HTTP 代理
./fastls-bench -url https://example.com -proxy http://127.0.0.1:8080

# 带认证的代理
./fastls-bench -url https://example.com -proxy http://user:pass@proxy.com:8080
```

### 自定义请求

```bash
# POST 请求
./fastls-bench -url https://api.example.com/data -method POST

# 自定义请求头
./fastls-bench -url https://example.com -H "Authorization: Bearer token;Content-Type: application/json"

# 设置超时时间
./fastls-bench -url https://example.com -timeout 60s

# 忽略SSL证书错误（用于测试自签名证书）
./fastls-bench -url https://example.com -k
```

### 输出模式

```bash
# 详细输出（显示每个请求）
./fastls-bench -url https://example.com -v

# 安静模式（只显示最终统计）
./fastls-bench -url https://example.com -q
```

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-url` | 目标URL (必需) | - |
| `-method` | HTTP方法 | GET |
| `-c` | 并发数 | 10 |
| `-d` | 测试持续时间 | 10s |
| `-n` | 总请求数 (0表示按持续时间运行) | 0 |
| `-proxy` | 代理地址 | - |
| `-timeout` | 请求超时时间 | 30s |
| `-H` | 自定义请求头 (多个用分号分隔) | - |
| `-k` | 忽略SSL证书错误 (不安全) | false |
| `-v` | 详细输出模式 | false |
| `-q` | 安静模式 | false |

## 输出示例

```
开始压力测试...
目标URL: https://example.com
HTTP方法: GET
并发数: 50
持续时间: 30s
代理: http://127.0.0.1:8080

=== 压力测试统计 ===
总请求数:     15234
成功请求:     15001 (98.47%)
失败请求:     233 (1.53%)
测试耗时:     30.12s
QPS:          505.23
平均响应时间: 98.5ms
最小响应时间: 45.2ms
最大响应时间: 1.2s
总传输字节:   45678901 (44569.24 KB)

状态码分布:
  200: 15001 (98.47%)
  404: 100 (0.66%)
  500: 133 (0.87%)
```

## 使用场景

### 1. API 压力测试

```bash
./fastls-bench -url https://api.example.com/endpoint \
  -c 100 \
  -d 60s \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 2. 通过代理测试

```bash
./fastls-bench -url https://example.com \
  -c 50 \
  -d 30s \
  -proxy http://127.0.0.1:8080
```

### 3. 指定请求数测试

```bash
./fastls-bench -url https://example.com \
  -c 20 \
  -n 1000
```

### 4. POST 请求测试

```bash
./fastls-bench -url https://api.example.com/data \
  -method POST \
  -c 30 \
  -d 20s \
  -H "Content-Type: application/json"
```

## 注意事项

1. **代理格式**: 支持 `http://`, `https://` 协议
2. **并发数**: 建议根据目标服务器性能调整，过高可能导致连接失败
3. **超时时间**: 如果请求经常超时，可以增加 `-timeout` 值
4. **请求头**: 多个请求头用分号分隔，格式为 `Key1:Value1;Key2:Value2`
5. **SSL证书**: 使用 `-k` 参数可以忽略SSL证书错误，但仅用于测试环境，生产环境不建议使用

## 性能优化建议

1. 使用合适的并发数（通常 50-200 之间）
2. 如果使用代理，确保代理服务器性能足够
3. 对于长时间测试，使用 `-d` 参数而不是 `-n` 参数
4. 使用 `-q` 模式可以减少输出开销，提高性能
