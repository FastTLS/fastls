# 子仓库设置说明

所有子仓库已经完成本地初始化和提交。现在需要将它们推送到 GitHub 远程仓库。

## 子仓库列表

1. **fastls-fetch** - Fetch 服务
2. **fastls-mitm** - MITM 代理
3. **fastls-rpc** - RPC 服务

## 设置远程仓库

### 1. 在 GitHub 上创建仓库

首先在 GitHub 上创建以下三个仓库：
- `https://github.com/FastTLS/fastls-fetch`
- `https://github.com/FastTLS/fastls-mitm`
- `https://github.com/FastTLS/fastls-rpc`

### 2. 添加远程仓库并推送

#### fastls-fetch

```bash
cd services/fastls-fetch
git remote add origin https://github.com/FastTLS/fastls-fetch.git
git push -u origin main
```

#### fastls-mitm

```bash
cd services/fastls-mitm
git remote add origin https://github.com/FastTLS/fastls-mitm.git
git push -u origin main
```

#### fastls-rpc

```bash
cd services/fastls-rpc
git remote add origin https://github.com/FastTLS/fastls-rpc.git
git push -u origin main
```

## 验证

推送完成后，可以在 GitHub 上查看各个仓库：
- https://github.com/FastTLS/fastls-fetch
- https://github.com/FastTLS/fastls-mitm
- https://github.com/FastTLS/fastls-rpc

## 后续使用

子仓库可以作为独立的模块使用：

```bash
# 安装 Fetch 服务
go get github.com/FastTLS/fastls-fetch

# 安装 MITM 代理
go get github.com/FastTLS/fastls-mitm

# 安装 RPC 服务
go get github.com/FastTLS/fastls-rpc
```

