@echo off
REM OpenList-Encrypt Git 初始化脚本 (Windows)
REM 请先在 GitHub 上创建一个新仓库，然后运行此脚本

echo ========================================
echo   OpenList-Encrypt Git 初始化工具
echo ========================================
echo.

REM 检查是否已经初始化 git
if exist ".git" (
    echo [警告] Git 仓库已存在，跳过初始化
) else (
    echo [1/5] 初始化 Git 仓库...
    git init
)

echo.
echo [2/5] 添加所有文件...
git add .

echo.
echo [3/5] 创建初始提交...
git commit -m "Initial commit: OpenList-Encrypt project"

echo.
echo [4/5] 设置主分支为 main...
git branch -M main

echo.
echo ========================================
echo   请输入你的 GitHub 仓库地址
echo   格式: https://github.com/用户名/仓库名.git
echo   或者: git@github.com:用户名/仓库名.git
echo ========================================
echo.

set /p REPO_URL="仓库地址: "

if "%REPO_URL%"=="" (
    echo [错误] 未输入仓库地址，退出
    exit /b 1
)

echo.
echo [5/5] 添加远程仓库并推送...
git remote add origin %REPO_URL%
git push -u origin main

echo.
echo ========================================
echo   完成！你的代码已推送到 GitHub
echo.
echo   下一步:
echo   1. 在 GitHub 仓库页面查看代码
echo   2. 进入 Actions 标签页查看构建状态
echo   3. 等待构建完成后下载 APK
echo ========================================

pause