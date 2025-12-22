#!/bin/bash

# Go 库版本发布脚本
# 用法: ./_scripts/release.sh <version> [message]
# 示例: ./_scripts/release.sh v1.0.0 "Release v1.0.0: 初始版本发布"

set -e

VERSION=$1
MESSAGE=${2:-"Release $VERSION"}

if [ -z "$VERSION" ]; then
    echo "错误: 请提供版本号"
    echo "用法: $0 <version> [message]"
    echo "示例: $0 v1.0.0 \"Release v1.0.0: 初始版本发布\""
    exit 1
fi

# 检查版本号格式
if [[ ! $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "错误: 版本号格式不正确，应为 vMAJOR.MINOR.PATCH"
    echo "示例: v1.0.0, v1.1.0, v1.0.1"
    exit 1
fi

# 检查是否有未提交的更改
if [ -n "$(git status --porcelain)" ]; then
    echo "警告: 检测到未提交的更改"
    read -p "是否继续? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# 检查 tag 是否已存在
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo "错误: Tag $VERSION 已存在"
    exit 1
fi

echo "准备发布版本: $VERSION"
echo "发布信息: $MESSAGE"
echo ""

# 运行测试
echo "运行测试..."
if ! go test ./...; then
    echo "错误: 测试失败，请修复后再发布"
    exit 1
fi

# 创建 tag
echo "创建 Git tag: $VERSION"
git tag -a "$VERSION" -m "$MESSAGE"

# 推送 tag
echo "推送 tag 到远程..."
git push origin "$VERSION"

echo ""
echo "✅ 版本 $VERSION 发布成功！"
echo ""
echo "下一步:"
echo "1. 访问 GitHub 仓库创建 Release"
echo "2. 选择 tag: $VERSION"
echo "3. 填写 Release 描述"
echo "4. 发布 Release"
echo ""
echo "用户可以使用以下命令安装:"
echo "  go get github.com/FastTLS/fastls@$VERSION"

