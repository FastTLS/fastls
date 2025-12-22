# Fetch Server 编译说明

## 前置要求

1. **Go 环境**: 需要 Go 1.21 或更高版本
   ```bash
   go version
   ```

2. **依赖**: 项目使用 vendor 目录管理依赖，无需额外下载

## 编译方法

### 方法 1: 在 services/fastls-fetch 目录下编译

```bash
cd services/fastls-fetch
go build fetch_server.go
```

**Windows 系统**会生成 `fetch_server.exe`  
**Linux/Mac 系统**会生成 `fetch_server` 可执行文件

### 方法 2: 指定输出文件名

```bash
cd services/fastls-fetch
go build -o fetch_server.exe fetch_server.go  # Windows
go build -o fetch_server fetch_server.go      # Linux/Mac
```

### 方法 3: 从项目根目录编译

```bash
# 从项目根目录
cd .
go build -o services/fastls-fetch/fetch_server.exe ./services/fastls-fetch/fetch_server.go  # Windows
go build -o services/fastls-fetch/fetch_server ./services/fastls-fetch/fetch_server.go      # Linux/Mac
```

### 方法 4: 交叉编译（编译其他平台）

```bash
# 编译 Linux 版本（在 Windows 上）
cd services/fastls-fetch
set GOOS=linux
set GOARCH=amd64
go build -o fetch_server_linux fetch_server.go

# 编译 Mac 版本（在 Windows 上）
set GOOS=darwin
set GOARCH=amd64
go build -o fetch_server_mac fetch_server.go

# 编译 Windows 版本（在 Linux/Mac 上）
GOOS=windows GOARCH=amd64 go build -o fetch_server.exe fetch_server.go
```

### 方法 5: 使用 go run 直接运行（不生成可执行文件）

```bash
cd services/fastls-fetch
go run fetch_server.go
```

## 编译选项

### 添加版本信息

```bash
go build -ldflags "-X main.version=1.0.0 -X main.buildTime=$(date +%Y-%m-%d_%H:%M:%S)" fetch_server.go
```

### 优化编译（减小文件大小）

```bash
go build -ldflags "-s -w" fetch_server.go
```

- `-s`: 去除符号表
- `-w`: 去除调试信息

### 静态链接（生成独立可执行文件）

```bash
go build -ldflags "-linkmode external -extldflags '-static'" fetch_server.go
```

## 运行编译后的程序

### Windows
```bash
cd services/fastls-fetch
.\fetch_server.exe
```

### Linux/Mac
```bash
cd services/fastls-fetch
./fetch_server
```

## 常见问题

### 1. 找不到模块

如果遇到 `cannot find module` 错误，确保在项目根目录下有 `go.mod` 文件：

```bash
cd .
go mod download
```

### 2. 依赖问题

项目使用 vendor 目录，如果遇到依赖问题：

```bash
cd .
go mod vendor
```

### 3. 端口被占用

如果 8800 端口被占用，可以修改 `fetch_server.go` 中的端口号：

```go
port := ":8800"  // 修改为你想要的端口
```

## 生产环境部署

### 1. 编译优化版本

```bash
cd services/fastls-fetch
go build -ldflags "-s -w" -o fetch_server fetch_server.go
```

### 2. 后台运行（Linux）

```bash
nohup ./fetch_server > fetch_server.log 2>&1 &
```

### 3. 使用 systemd 管理（Linux）

创建 `/etc/systemd/system/fetch-server.service`:

```ini
[Unit]
Description=Fastls Fetch Server
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/services/fastls-fetch
ExecStart=/path/to/services/fastls-fetch/fetch_server
Restart=always

[Install]
WantedBy=multi-user.target
```

然后启动服务：

```bash
sudo systemctl enable fetch-server
sudo systemctl start fetch-server
```

## 验证编译

编译成功后，可以运行健康检查：

```bash
# 启动服务后
curl http://localhost:8800/health
```

应该返回：
```json
{"status":"ok"}
```

