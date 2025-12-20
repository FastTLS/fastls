# Fastls Fetch服务

基于HTTP的Fetch服务，提供HTTP请求功能，支持TLS指纹伪装。

## 目录结构

```
fetch/
├── fetch_server.go          # Fetch服务器主程序
├── fetch_server_example.md  # Fetch服务API文档
├── README.md                # 本文件
└── example/                 # 客户端示例
    ├── README.md            # 客户端使用说明
    ├── python_client.py     # Python客户端示例
    ├── go_client.go         # Golang客户端示例
    └── nodejs_client.js     # Node.js客户端示例
```

## 快速开始

### 编译

```bash
cd main/fetch
go build -o fetch_server.exe fetch_server.go
```

### 运行

```bash
./fetch_server.exe
```

服务器默认运行在 `http://localhost:8800`

## 功能特性

- ✅ RESTful API接口
- ✅ TLS指纹伪装（JA3/JA4R或浏览器类型）
- ✅ 支持多种浏览器指纹预设
- ✅ 自动响应解压缩
- ✅ 代理支持
- ✅ CORS支持

## API端点

### POST /fetch

发送HTTP请求。

**请求示例:**

```bash
curl -X POST http://localhost:8800/fetch \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://tls.peet.ws/api/all",
    "browser": "chrome142"
  }'
```

### GET /health

健康检查。

**请求示例:**

```bash
curl http://localhost:8800/health
```

## 客户端示例

详细的客户端示例代码位于 `example/` 目录：

- **Python**: `example/python_client.py`
- **Golang**: `example/go_client.go`
- **Node.js**: `example/nodejs_client.js`

## 使用示例

### Python

```python
import requests

payload = {
    "url": "https://tls.peet.ws/api/all",
    "browser": "chrome142"
}

response = requests.post("http://localhost:8800/fetch", json=payload)
print(response.json())
```

### Golang

```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

func main() {
    payload := map[string]interface{}{
        "url":     "https://tls.peet.ws/api/all",
        "browser": "chrome142",
    }
    
    jsonData, _ := json.Marshal(payload)
    resp, _ := http.Post("http://localhost:8800/fetch", "application/json", bytes.NewBuffer(jsonData))
    // 处理响应...
}
```

### Node.js

```javascript
const http = require('http');

const data = JSON.stringify({
    url: 'https://tls.peet.ws/api/all',
    browser: 'chrome142'
});

const options = {
    hostname: 'localhost',
    port: 8800,
    path: '/fetch',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length
    }
};

const req = http.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => { data += chunk; });
    res.on('end', () => { console.log(JSON.parse(data)); });
});

req.write(data);
req.end();
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

## 文档

- [Fetch服务API文档](./fetch_server_example.md) - 详细的API说明和使用示例
- [客户端示例说明](./example/README.md) - 各语言客户端的使用方法

## 相关服务

- [MITM代理服务](../mitm/) - 中间人代理服务
- [RPC服务](../rpc/) - JSON-RPC 2.0服务
