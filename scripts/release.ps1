# Go 库版本发布脚本 (PowerShell)
# 用法: .\scripts\release.ps1 -Version v1.0.0 -Message "Release v1.0.0: 初始版本发布"

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [string]$Message = "Release $Version"
)

$ErrorActionPreference = "Stop"

# 检查版本号格式
if ($Version -notmatch '^v\d+\.\d+\.\d+$') {
    Write-Host "错误: 版本号格式不正确，应为 vMAJOR.MINOR.PATCH" -ForegroundColor Red
    Write-Host "示例: v1.0.0, v1.1.0, v1.0.1" -ForegroundColor Yellow
    exit 1
}

# 检查是否有未提交的更改
$status = git status --porcelain
if ($status) {
    Write-Host "警告: 检测到未提交的更改" -ForegroundColor Yellow
    $response = Read-Host "是否继续? (y/N)"
    if ($response -ne 'y' -and $response -ne 'Y') {
        exit 1
    }
}

# 检查 tag 是否已存在
$tagExists = git rev-parse "$Version" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "错误: Tag $Version 已存在" -ForegroundColor Red
    exit 1
}

Write-Host "准备发布版本: $Version" -ForegroundColor Green
Write-Host "发布信息: $Message" -ForegroundColor Green
Write-Host ""

# 运行测试
Write-Host "运行测试..." -ForegroundColor Cyan
go test ./...
if ($LASTEXITCODE -ne 0) {
    Write-Host "错误: 测试失败，请修复后再发布" -ForegroundColor Red
    exit 1
}

# 创建 tag
Write-Host "创建 Git tag: $Version" -ForegroundColor Cyan
git tag -a "$Version" -m "$Message"

# 推送 tag
Write-Host "推送 tag 到远程..." -ForegroundColor Cyan
git push origin "$Version"

Write-Host ""
Write-Host "✅ 版本 $Version 发布成功！" -ForegroundColor Green
Write-Host ""
Write-Host "下一步:" -ForegroundColor Yellow
Write-Host "1. 访问 GitHub 仓库创建 Release"
Write-Host "2. 选择 tag: $Version"
Write-Host "3. 填写 Release 描述"
Write-Host "4. 发布 Release"
Write-Host ""
Write-Host "用户可以使用以下命令安装:" -ForegroundColor Cyan
Write-Host "  go get github.com/ChengHoward/Fastls@$Version"

