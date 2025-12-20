# Fastls Fetch服务客户端示例

本目录包含使用 Fastls Fetch服务的客户端示例，支持 Python、Golang 和 Node.js。

## 启动Fetch服务

```bash
cd main/fetch
go run fetch_server.go
# 或
./fetch_server.exe
```

服务器默认运行在 `http://localhost:8800`

## Python 客户端

### 安装依赖

```bash
pip install requests
```

### 运行示例

```bash
python python_client.py
```

### 使用示例

```python
from python_client import FastlsFetchClient

# 创建客户端
client = FastlsFetchClient("http://localhost:8800")

# 发送请求
result = client.fetch(
    url="https://tls.peet.ws/api/all",
    browser="chrome142"
)
print(result)
```

## Golang 客户端

### 运行示例

```bash
go run go_client.go
```

### 使用示例

```go
package main

import (
    "fmt"
)

func main() {
    // 创建客户端
    client := NewFastlsFetchClient("http://localhost:8800")
    
    // 发送请求
    result, _ := client.Fetch(FetchParams{
        URL:     "https://tls.peet.ws/api/all",
        Browser: "chrome142",
    })
    fmt.Println(result)
}
```

## Node.js 客户端

### 运行示例

```bash
node nodejs_client.js
```

### 使用示例

```javascript
const FastlsFetchClient = require('./nodejs_client.js');

// 创建客户端
const client = new FastlsFetchClient('http://localhost:8800');

// 发送请求
client.fetch({
    url: 'https://tls.peet.ws/api/all',
    browser: 'chrome142'
}).then(result => {
    console.log(result);
});
```

## API端点

### POST /fetch

发送HTTP请求。

**请求参数:**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| url | string | 是 | 请求URL |
| method | string | 否 | HTTP方法，默认 "GET" |
| headers | object | 否 | 请求头 |
| body | string | 否 | 请求体 |
| proxy | string | 否 | 代理地址 |
| timeout | int | 否 | 超时时间（秒），默认 30 |
| disableRedirect | bool | 否 | 是否禁用重定向，默认 false |
| userAgent | string | 否 | User-Agent |
| fingerprint | object | 否 | 指纹配置，格式：`{"type": "ja3", "value": "..."}` 或 `{"type": "ja4r", "value": "..."}` |
| browser | string | 否 | 浏览器类型 |
| cookies | array | 否 | Cookie列表 |

**响应:**

```json
{
  "ok": true,
  "status": 200,
  "headers": {},
  "body": "...",
  "error": ""
}
```

### GET /health

健康检查。

**响应:**

```json
{
  "status": "ok"
}
```

## 支持的浏览器类型

- `chrome` - Chrome浏览器
- `chrome120` - Chrome 120版本
- `chrome142` - Chrome 142版本
- `chromium` - Chromium浏览器
- `edge` - Microsoft Edge浏览器
- `firefox` - Firefox浏览器
- `safari` - Safari浏览器
- `opera` - Opera浏览器

## 指纹类型

- `ja3` - JA3指纹
- `ja4r` - JA4R指纹（完整版本）

## 使用示例

### 1. 简单GET请求

```python
result = client.fetch({
    "url": "https://httpbin.org/get"
})
```

### 2. POST请求

```python
result = client.fetch({
    "url": "https://httpbin.org/post",
    "method": "POST",
    "headers": {"Content-Type": "application/json"},
    "body": '{"key": "value"}'
})
```

### 3. 使用浏览器指纹

```python
result = client.fetch({
    "url": "https://tls.peet.ws/api/all",
    "browser": "chrome142"
})
```

### 4. 使用自定义JA3指纹

```python
result = client.fetch({
    "url": "https://tls.peet.ws/api/all",
    "fingerprint": {
        "type": "ja3",
        "value": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
    }
})
```

### 5. 使用代理

```python
result = client.fetch({
    "url": "https://httpbin.org/ip",
    "proxy": "http://127.0.0.1:1080"
})
```

## 错误处理

响应中的错误格式：

```json
{
  "ok": false,
  "status": 0,
  "error": "错误信息"
}
```

常见错误：
- 网络连接失败
- 超时
- SSL证书验证失败
- 代理连接失败

