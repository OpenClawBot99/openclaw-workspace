#!/usr/bin/env pwsh
# TileLang-Ascend 知识库 - 安装配置脚本
# 用于自动化安装和配置 GH CLI

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TileLang-Ascend 知识库构建工具" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. 检查并安装 GH CLI
Write-Host "[1/4] 检查 GH CLI..." -ForegroundColor Yellow
if (Get-Command gh -ErrorAction SilentlyContinue) {
    Write-Host "✅ GH CLI 已安装" -ForegroundColor Green
    $gh_version = gh --version | Select-Object -First 1
    Write-Host "   版本: $gh_version" -ForegroundColor Gray
} else {
    Write-Host "⬇️  正在下载 GH CLI..." -ForegroundColor Yellow
    
    # 下载最新版本
    $gh_url = "https://github.com/cli/cli/releases/download/v2.67.0/gh_2.67.0_windows_amd64.zip"
    $gh_zip = "gh.zip"
    $gh_dir = "gh-extract"
    
    try {
        Invoke-WebRequest -Uri $gh_url -OutFile $gh_zip -ErrorAction Stop
        Write-Host "✅ 下载完成" -ForegroundColor Green
        
        # 解压
        Write-Host "📦 解压中..." -ForegroundColor Yellow
        Expand-Archive -Path $gh_zip -DestinationPath $gh_dir -Force
        
        # 移动到系统路径或当前目录
        $gh_exe = Join-Path $gh_dir "bin" "gh.exe"
        if (Test-Path $gh_exe) {
            Copy-Item $gh_exe -Destination "gh.exe" -Force
            Write-Host "✅ GH CLI 已安装到当前目录" -ForegroundColor Green
        }
        
        # 清理
        Remove-Item $gh_zip -Force
        Remove-Item $gh_dir -Recurse -Force
    }
    catch {
        Write-Host "❌ 下载失败: $_" -ForegroundColor Red
        Write-Host "请手动安装 GH CLI: https://cli.github.com/" -ForegroundColor Yellow
    }
}

Write-Host ""

# 2. 验证 GH CLI
Write-Host "[2/4] 验证 GH CLI..." -ForegroundColor Yellow
try {
    $gh_status = gh auth status 2>&1
    if ($gh_status -match "Logged in") {
        Write-Host "✅ GH CLI 已登录" -ForegroundColor Green
        $gh_status | ForEach-Object { Write-Host "   $_" -ForegroundColor Gray }
    } else {
        Write-Host "⚠️  GH CLI 未登录" -ForegroundColor Yellow
        Write-Host "   状态: $gh_status" -ForegroundColor Gray
    }
}
catch {
    Write-Host "❌ 验证失败: $_" -ForegroundColor Red
}

Write-Host ""

# 3. 克隆或更新知识库仓库
Write-Host "[3/4] 同步知识库到 GitHub..." -ForegroundColor Yellow
$memory_repo = "git@github.com:OpenClawBot99/memory.git"
$skills_repo = "git@github.com:OpenClawBot99/skills.git"

# 检查远程仓库
Write-Host "   远程仓库:"
Write-Host "   - memory: $memory_repo" -ForegroundColor Gray
Write-Host "   - skills: $skills_repo" -ForegroundColor Gray

Write-Host ""

# 4. 推送知识库
Write-Host "[4/4] 准备推送知识库..." -ForegroundColor Yellow

# 添加所有更改
git add -A

# 检查状态
$status = git status --short
if ($status) {
    Write-Host "   待提交的更改:" -ForegroundColor Gray
    $status | ForEach-Object { Write-Host "   $_" -ForegroundColor Gray }
    
    # 提交
    $commit_msg = "feat: 添加 TileLang-Ascend 知识库 - 进度报告和安装脚本"
    git commit -m $commit_msg
    
    # 推送
    Write-Host "   推送到 origin..." -ForegroundColor Gray
    git push origin main
    
    Write-Host "✅ 推送完成!" -ForegroundColor Green
} else {
    Write-Host "   没有待提交的更改" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "配置完成!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
