@echo off
chcp 65001 >nul
echo ============================================
echo   编译网络数据包抓取与分析软件
echo ============================================

set PATH=E:\CodeBlocks\MinGW\bin;%PATH%

where g++.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo 错误: 未找到 g++ 编译器，请确认 MinGW 已安装
    pause
    exit /b 1
)

echo 正在编译...
g++.exe -o sniffer.exe main.cpp -lws2_32 -std=c++11

if %errorlevel% neq 0 (
    echo 编译失败!
    pause
    exit /b 1
)

echo 编译成功! 生成 sniffer.exe
echo.
echo 注意: 请以管理员身份运行 sniffer.exe
pause
