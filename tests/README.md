# Fastls 单元测试

本目录包含 Fastls 库的完整单元测试套件，涵盖 HTTP 请求、WebSocket、指纹伪装、API 调用等核心功能。

## 📁 测试文件说明

### 核心功能测试

- **`fetch_test.go`** - HTTP 请求基础测试
  - 无指纹请求测试
  - Firefox 指纹测试
  - 自定义 JA3 指纹测试

- **`fetch_browser_test.go`** - 浏览器指纹模拟测试
  - Chrome 指纹测试
  - Edge 指纹测试
  - Safari 指纹测试

- **`ja4_test.go`** - JA4R 指纹测试（实验性功能）
  - JA4 指纹类型和值测试
  - 各浏览器 JA4 配置测试（Chrome142、Chrome120、Chrome、Firefox、Chromium、Safari）
  - JA4 请求结果验证
  - JA4 vs JA3 对比测试

- **`stdlib_fingerprint_test.go`** - Go 标准库指纹对比测试
  - 测试 Go 标准库 `net/http` 的默认 TLS 指纹

### 协议测试

- **`websocket_test.go`** - WebSocket 连接测试
  - 带指纹的 WebSocket 连接测试
  - 无指纹的 WebSocket 连接测试
  - GMGN WebSocket 测试

### 服务测试

- **`api_test.go`** - HTTP API 服务测试
  - Fetch API 调用测试
  - 健康检查端点测试
  - ⚠️ 需要先启动 `main/fetch/fetch_server.go` 服务

## 🚀 运行测试

### 运行所有测试

```bash
# 在项目根目录
go test ./tests/... -v

# 或在 tests 目录下
cd tests
go test -v
```

### 运行特定测试文件

```bash
# 运行 HTTP 请求测试
go test -v -run TestNoFingerprint|TestWithFirefoxFingerprint|TestWithCustomJA3

# 运行浏览器指纹测试
go test -v -run "TestWith.*Fingerprint"

# 运行 JA4 指纹测试
go test -v -run TestJa4

# 运行 WebSocket 测试
go test -v -run TestWebSocket

# 运行 API 测试（需要先启动服务）
go test -v -run TestFetchAPI|TestHealthCheck
```

### 运行特定测试用例

```bash
# 运行单个测试
go test -v -run TestNoFingerprint

# 运行多个测试（使用正则）
go test -v -run "TestWithChrome.*"

# 运行所有 JA4 相关测试
go test -v -run "Test.*JA4"
```

### 测试覆盖率

```bash
# 显示测试覆盖率
go test -v -cover ./tests/...

# 生成详细的覆盖率报告
go test -coverprofile=coverage.out ./tests/...
go tool cover -html=coverage.out
```

## 📋 测试用例详情

### HTTP 请求测试 (`fetch_test.go`)

| 测试用例 | 说明 |
|---------|------|
| `TestNoFingerprint` | 测试无指纹配置的 HTTP 请求 |
| `TestWithFirefoxFingerprint` | 测试使用 Firefox 指纹的请求 |
| `TestWithCustomJA3` | 测试使用自定义 JA3 指纹的请求 |

### 浏览器指纹测试 (`fetch_browser_test.go`)

| 测试用例 | 说明 |
|---------|------|
| `TestWithChromeFingerprint` | 测试 Chrome 浏览器指纹模拟 |
| `TestWithEdgeFingerprint` | 测试 Edge 浏览器指纹模拟 |
| `TestWithSafariFingerprint` | 测试 Safari 浏览器指纹模拟 |

### JA4 指纹测试 (`ja4_test.go`) - 实验性

| 测试用例 | 说明 |
|---------|------|
| `TestJa4FingerprintType` | 测试 JA4 指纹类型返回 |
| `TestJa4FingerprintValue` | 测试 JA4 指纹值获取 |
| `TestJa4FingerprintIsEmpty` | 测试 JA4 指纹空值检查 |
| `TestOptionsIsJa4` | 测试 Options 中的 JA4 检查方法 |
| `TestChrome142JA4` | 测试 Chrome142 JA4 配置 |
| `TestFirefoxJA4` | 测试 Firefox JA4 配置 |
| `TestChrome120JA4` | 测试 Chrome120 JA4 配置 |
| `TestChromeJA4` | 测试 Chrome JA4 配置 |
| `TestChromiumJA4` | 测试 Chromium JA4 配置 |
| `TestSafariJA4` | 测试 Safari JA4 配置 |
| `TestWithChrome142JA4Request` | 测试使用 Chrome142 JA4 的实际请求 |
| `TestWithFirefoxJA4Request` | 测试使用 Firefox JA4 的实际请求 |
| `TestJA4RequestResult` | 测试 JA4 请求结果的完整性 |

### WebSocket 测试 (`websocket_test.go`)

| 测试用例 | 说明 |
|---------|------|
| `TestWebSocketWithFingerprint` | 测试带指纹的 WebSocket 连接 |
| `TestWebSocketWithoutFingerprint` | 测试无指纹的 WebSocket 连接 |
| `TestWebSocketGMGN` | 测试 GMGN WebSocket 连接（带指纹） |
| `TestWebSocketGMGNWithoutFingerprint` | 测试 GMGN WebSocket 连接（无指纹） |

### API 服务测试 (`api_test.go`)

| 测试用例 | 说明 | 前置条件 |
|---------|------|---------|
| `TestFetchAPI` | 测试 Fetch API 服务调用 | 需要启动 fetch_server |
| `TestHealthCheck` | 测试健康检查端点 | 需要启动 fetch_server |

### 标准库对比测试 (`stdlib_fingerprint_test.go`)

| 测试用例 | 说明 |
|---------|------|
| `TestGoStdlibFingerprint` | 测试 Go 标准库的默认 TLS 指纹，用于对比 |

## ⚙️ 测试配置

### 环境要求

- Go 1.24+
- 网络连接（测试使用真实网络请求）
- 对于 API 测试，需要启动 Fetch 服务

### 启动 Fetch 服务（用于 API 测试）

```bash
# 终端 1：启动服务
cd main/fetch
go run fetch_server.go

# 终端 2：运行测试
cd tests
go test -v -run TestFetchAPI
```

## ⚠️ 注意事项

1. **网络依赖**：所有测试都需要网络连接，测试会发送真实的 HTTP/WebSocket 请求
2. **服务依赖**：API 测试（`api_test.go`）需要先启动 Fetch 服务，否则测试会被跳过
3. **网络稳定性**：测试结果可能受到网络状况影响，如果网络不稳定可能导致测试失败
4. **实验性功能**：JA4 相关测试标记为实验性，API 可能会在未来版本中发生变化
5. **测试超时**：某些测试可能需要较长时间，请耐心等待

## 🔧 测试最佳实践

1. **运行前检查**：
   ```bash
   # 检查网络连接
   curl https://tls.peet.ws/api/all
   
   # 检查服务是否运行（API 测试）
   curl http://localhost:8800/health
   ```

2. **运行特定测试**：
   ```bash
   # 只运行快速测试（跳过需要服务的测试）
   go test -v -run "Test.*" -skip "TestFetchAPI|TestHealthCheck"
   ```

3. **查看详细输出**：
   ```bash
   # 使用 -v 参数查看详细日志
   go test -v -run TestWithChromeFingerprint
   ```

4. **调试失败测试**：
   ```bash
   # 运行单个测试并查看详细输出
   go test -v -run TestNoFingerprint 2>&1 | tee test.log
   ```

## 📊 测试统计

- **测试文件数**：6 个
- **测试用例数**：32+ 个
- **覆盖功能**：HTTP 请求、WebSocket、指纹伪装、API 服务

## 📝 贡献测试

添加新测试时，请遵循以下规范：

1. 测试函数名以 `Test` 开头
2. 使用 `t.Logf` 记录重要信息
3. 对于需要外部服务的测试，使用 `t.Skipf` 跳过而不是失败
4. 添加适当的注释说明测试目的
5. 确保测试可以独立运行
