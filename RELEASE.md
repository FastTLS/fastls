# Go 库版本发布指南

本指南说明如何为 Fastls 库发布新版本。

## 版本号规范

遵循 [语义化版本](https://semver.org/lang/zh-CN/) 规范：
- **主版本号（MAJOR）**：不兼容的 API 修改
- **次版本号（MINOR）**：向下兼容的功能性新增
- **修订号（PATCH）**：向下兼容的问题修正

格式：`vMAJOR.MINOR.PATCH`，例如：`v1.0.0`、`v1.1.0`、`v1.0.1`

## 发布步骤

### 1. 准备发布

确保所有更改已提交：

```bash
# 检查状态
git status

# 提交所有更改
git add .
git commit -m "准备发布 v1.0.0"

# 推送到远程
git push origin main
```

### 2. 创建 Git Tag

```bash
# 创建带注释的 tag（推荐）
git tag -a v1.0.0 -m "Release v1.0.0: 初始版本发布"

# 或者创建轻量级 tag
git tag v1.0.0
```

### 3. 推送 Tag 到远程

```bash
# 推送单个 tag
git push origin v1.0.0

# 或者推送所有 tag
git push origin --tags
```

### 4. 在 GitHub 创建 Release

1. 访问 GitHub 仓库页面
2. 点击右侧 "Releases" → "Draft a new release"
3. 选择刚创建的 tag（如 `v1.0.0`）
4. 填写 Release 标题和描述
5. 点击 "Publish release"

### 5. 验证发布

用户可以通过以下方式使用你的库：

```bash
# 使用特定版本
go get github.com/FastTLS/fastls@v1.0.0

# 使用最新版本
go get github.com/FastTLS/fastls@latest

# 使用最新主版本
go get github.com/FastTLS/fastls@v1
```

## 快速发布脚本

### Linux/macOS

可以使用 `scripts/release.sh` 脚本快速发布：

```bash
chmod +x scripts/release.sh
./scripts/release.sh v1.0.0 "Release v1.0.0: 初始版本发布"
```

### Windows (PowerShell)

可以使用 `scripts/release.ps1` 脚本快速发布：

```powershell
.\scripts\release.ps1 -Version v1.0.0 -Message "Release v1.0.0: 初始版本发布"
```

## 发布检查清单

- [ ] 所有代码已提交并推送
- [ ] 测试通过：`go test ./...`
- [ ] 代码格式检查：`gofmt -l .`
- [ ] README.md 已更新
- [ ] CHANGELOG.md 已更新（如果有）
- [ ] 版本号已确定
- [ ] Git tag 已创建并推送
- [ ] GitHub Release 已创建

## 示例：发布 v1.0.0

```bash
# 1. 确保代码已提交
git add .
git commit -m "准备发布 v1.0.0"
git push origin main

# 2. 创建并推送 tag
git tag -a v1.0.0 -m "Release v1.0.0: 初始版本发布"
git push origin v1.0.0

# 3. 在 GitHub 上创建 Release（手动操作）
```

## 常见问题

### Q: 如何删除已发布的 tag？

```bash
# 删除本地 tag
git tag -d v1.0.0

# 删除远程 tag
git push origin --delete v1.0.0
```

### Q: 如何更新已发布的版本？

如果版本已发布，应该创建新版本而不是修改旧版本。如果必须修改，需要：
1. 删除旧的 tag
2. 创建新的 tag
3. 更新 GitHub Release

### Q: 如何查看所有已发布的版本？

```bash
# 查看所有 tag
git tag -l

# 查看 tag 详情
git show v1.0.0
```

## 参考资源

- [Go Modules 官方文档](https://go.dev/ref/mod)
- [语义化版本规范](https://semver.org/)
- [Git Tag 文档](https://git-scm.com/book/zh/v2/Git-%E5%9F%BA%E7%A1%80-%E6%89%93%E6%A0%87%E7%AD%BE)

