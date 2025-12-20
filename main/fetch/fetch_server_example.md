# Fetch服务使用说明

## 启动服务

```bash
cd main
go run fetch_server.go
```

服务默认运行在 `http://localhost:8800`

## API接口

### POST /fetch

发送HTTP请求的接口。

#### 请求示例

**cURL:**
```bash
curl -X POST http://localhost:8800/fetch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://tls.peet.ws/api/all",
    "method": "GET",
    "headers": {
      "Accept": "application/json"
    },
    "timeout": 30
  }'
```

**Python:**
```python
import requests

url = "http://localhost:8800/fetch"
payload = {
    "url": "https://tls.peet.ws/api/all",
    "method": "GET",
    "headers": {
        "Accept": "application/json"
    },
    "timeout": 30
}

response = requests.post(url, json=payload)
print(response.json())
```

#### 请求参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| url | string | 是 | 请求的URL地址 |
| method | string | 否 | HTTP方法，默认为GET |
| headers | object | 否 | 请求头，键值对格式 |
| body | string | 否 | 请求体（字符串格式） |
| proxy | string | 否 | 代理地址，格式：http://host:port 或 socks5://host:port |
| timeout | int | 否 | 超时时间（秒），默认30秒 |
| disableRedirect | bool | 否 | 是否禁用重定向 |
| userAgent | string | 否 | 自定义User-Agent |
| fingerprint | object | 否 | 指纹配置，格式：`{"type": "ja3", "value": "..."}` 或 `{"type": "ja4r", "value": "..."}` |
| browser | string | 否 | 浏览器类型：`chrome`, `chrome120`, `chrome142`, `chromium`, `edge`, `firefox`, `safari`, `opera` |
| cookies | array | 否 | Cookie数组 |

**注意：** 指纹设置的优先级：`fingerprint` > `browser` > 默认Firefox。如果同时指定了`fingerprint`和`browser`，将优先使用`fingerprint`。

#### 响应格式

```json
{
  "ok": true,
  "status": 200,
  "headers": {
    "Content-Type": "application/json",
    "Content-Length": "1234"
  },
  "body": "响应体内容（已自动解码）",
  "error": ""
}
```

#### 响应字段

| 字段 | 类型 | 说明 |
|------|------|------|
| ok | bool | 请求是否成功 |
| status | int | HTTP状态码 |
| headers | object | 响应头 |
| body | string | 响应体（已自动解码gzip、br、deflate等压缩格式） |
| error | string | 错误信息（如果ok为false） |

## 完整请求示例

### 1. 简单GET请求

**cURL:**
```bash
curl -X POST http://localhost:8800/fetch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://httpbin.org/get"
  }'
```

**Python:**
```python
import requests

response = requests.post(
    "http://localhost:8800/fetch",
    json={"url": "https://httpbin.org/get"}
)
print(response.json())
```

### 2. POST请求带Body

**cURL:**
```bash
curl -X POST http://localhost:8800/fetch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://httpbin.org/post",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": "{\"key\":\"value\"}"
  }'
```

**Python:**
```python
import requests

payload = {
    "url": "https://httpbin.org/post",
    "method": "POST",
    "headers": {
        "Content-Type": "application/json"
    },
    "body": '{"key":"value"}'
}

response = requests.post("http://localhost:8800/fetch", json=payload)
print(response.json())
```

### 3. 使用代理

**cURL:**
```bash
curl -X POST http://localhost:8800/fetch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://httpbin.org/ip",
    "proxy": "http://127.0.0.1:1080"
  }'
```

**Python:**
```python
import requests

payload = {
    "url": "https://httpbin.org/ip",
    "proxy": "http://127.0.0.1:1080"
}

response = requests.post("http://localhost:8800/fetch", json=payload)
print(response.json())
```

### 4. 使用指定浏览器指纹

**cURL:**
```bash
curl -X POST http://localhost:8800/fetch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://tls.peet.ws/api/all",
    "browser": "chrome142"
  }'
```

**Python:**
```python
import requests

payload = {
    "url": "https://tls.peet.ws/api/all",
    "browser": "chrome142"  # 可选: chrome, chrome120, chrome142, chromium, edge, firefox, safari, opera
}

response = requests.post("http://localhost:8800/fetch", json=payload)
print(response.json())
```

### 5. 自定义JA3指纹

**cURL:**
```bash
curl -X POST http://localhost:8800/fetch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://tls.peet.ws/api/all",
    "fingerprint": {
      "type": "ja3",
      "value": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
    },
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  }'
```

**Python:**
```python
import requests

payload = {
    "url": "https://tls.peet.ws/api/all",
    "fingerprint": {
        "type": "ja3",
        "value": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
    },
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

response = requests.post("http://localhost:8800/fetch", json=payload)
print(response.json())
```

### 6. 使用JA4R指纹

**cURL:**
```bash
curl -X POST http://localhost:8800/fetch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://tls.peet.ws/api/all",
    "fingerprint": {
      "type": "ja4r",
      "value": "t13d5911_002f,0032,0033,0035,0038,0039,003c,003d,0040,0067,006a,006b,009c,009d,009e,009f,00a2,00a3,00ff,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,c050,c051,c052,c053,c056,c057,c05c,c05d,c060,c061,c09c,c09d,c09e,c09f,c0a0,c0a1,c0a2,c0a3,c0ac,c0ad,c0ae,c0af,cca8,cca9,ccaa_000a,000b,000d,0016,0017,0023,002b,002d,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602"
    }
  }'
```

**Python:**
```python
import requests

payload = {
    "url": "https://tls.peet.ws/api/all",
    "fingerprint": {
        "type": "ja4r",
        "value": "t13d5911_002f,0032,0033,0035,0038,0039,003c,003d,0040,0067,006a,006b,009c,009d,009e,009f,00a2,00a3,00ff,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,c050,c051,c052,c053,c056,c057,c05c,c05d,c060,c061,c09c,c09d,c09e,c09f,c0a0,c0a1,c0a2,c0a3,c0ac,c0ad,c0ae,c0af,cca8,cca9,ccaa_000a,000b,000d,0016,0017,0023,002b,002d,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602"
    }
}

response = requests.post("http://localhost:8800/fetch", json=payload)
print(response.json())
```

### 7. 带Cookie的请求

**cURL:**
```bash
curl -X POST http://localhost:8800/fetch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://httpbin.org/cookies",
    "cookies": [
      {
        "name": "session",
        "value": "abc123",
        "domain": "httpbin.org"
      }
    ]
  }'
```

**Python:**
```python
import requests

payload = {
    "url": "https://httpbin.org/cookies",
    "cookies": [
        {
            "name": "session",
            "value": "abc123",
            "domain": "httpbin.org"
        }
    ]
}

response = requests.post("http://localhost:8800/fetch", json=payload)
print(response.json())
```

### 8. 完整示例：使用Chrome142指纹 + 代理 + 自定义Headers

**cURL:**
```bash
curl -X POST http://localhost:8800/fetch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://tls.peet.ws/api/all",
    "method": "GET",
    "browser": "chrome142",
    "proxy": "socks5://127.0.0.1:1080",
    "headers": {
      "Accept": "application/json",
      "Accept-Language": "en-US,en;q=0.9"
    },
    "timeout": 60
  }'
```

**Python:**
```python
import requests

payload = {
    "url": "https://tls.peet.ws/api/all",
    "method": "GET",
    "browser": "chrome142",
    "proxy": "socks5://127.0.0.1:1080",
    "headers": {
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9"
    },
    "timeout": 60
}

response = requests.post("http://localhost:8800/fetch", json=payload)
result = response.json()

if result["ok"]:
    print(f"Status: {result['status']}")
    print(f"Body: {result['body']}")
else:
    print(f"Error: {result['error']}")
```

## 健康检查

**cURL:**
```bash
curl http://localhost:8800/health
```

**Python:**
```python
import requests

response = requests.get("http://localhost:8800/health")
print(response.json())  # {"status": "ok"}
```

## 性能优化

- 服务使用全局Fastls客户端实例，支持高并发
- 自动设置最大CPU核心数
- 响应体自动解码（gzip、br、deflate、zstd等）
- 支持连接复用

## 支持的浏览器类型

| 浏览器类型 | 说明 |
|-----------|------|
| `chrome` | Chrome浏览器 |
| `chrome120` | Chrome 120版本 |
| `chrome142` | Chrome 142版本 |
| `chromium` | Chromium浏览器 |
| `edge` | Microsoft Edge浏览器 |
| `firefox` | Firefox浏览器（默认） |
| `safari` | Safari浏览器 |
| `opera` | Opera浏览器 |

## 指纹设置优先级

1. **自定义指纹** (`fingerprint`): 如果指定了`fingerprint`对象（JA3或JA4R），优先使用
2. **浏览器类型** (`browser`): 如果没有指定`fingerprint`但指定了`browser`，使用对应浏览器的预设指纹
3. **默认指纹**: 如果都没有指定，默认使用Firefox指纹

## 注意事项

1. 如果不提供`fingerprint`或`browser`参数，服务会自动使用Firefox指纹
2. 响应体会自动根据`Content-Encoding`头进行解码（gzip、br、deflate、zstd等）
3. 如果请求失败，`ok`字段为`false`，错误信息在`error`字段中
4. 超时时间建议根据实际需求设置，避免过长导致资源占用
5. 代理格式支持：`http://host:port`、`https://host:port`、`socks5://host:port`
6. Cookie数组中的每个Cookie对象应包含`name`和`value`字段，可选字段包括`domain`、`path`、`expires`等




