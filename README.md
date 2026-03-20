# 网络数据包抓取与分析软件

基于 C++ 实现的控制台网络抓包与协议分析工具，通过动态加载 Npcap 进行底层数据包捕获，所有协议解析逻辑均为手动编写。

## 功能

- 抓取本地网卡上的所有以太网帧（混杂模式）
- 解析并显示以太网（MAC）头部字段
- 解析并显示 IPv4 头部字段
- 解析并显示传输层协议头部字段（TCP、UDP、ICMP）
- 解析并显示 DNS 应用层协议（查询与响应）
- 概要列表实时展示抓取的数据包
- 输入序号查看任意数据包的分层详细信息
- 支持将抓包结果保存为文本日志文件
- 支持切换网卡重新抓包

## 项目结构

```
packet_parser.h   协议结构体定义与解析函数
main.cpp          主程序（抓包、控制台交互、日志保存）
build.bat         一键编译脚本
```

## 环境要求

- Windows 10/11
- [Npcap](https://npcap.com/)（安装 Wireshark 时会自带）
- MinGW g++（项目默认路径 `E:\CodeBlocks\MinGW\bin\g++.exe`，可在 `build.bat` 中修改）

## 编译

双击 `build.bat` 即可编译，生成 `sniffer.exe`。

也可以手动执行：

```bash
g++ -o sniffer.exe main.cpp -lws2_32 -std=c++11
```

## 运行

**必须以管理员身份运行**（抓包需要管理员权限）：

```
右键 sniffer.exe → 以管理员身份运行
```

## 使用说明

1. 程序启动后列出可用网络接口，输入编号选择
2. 开始抓包，实时显示数据包概要列表
3. 按 **Enter** 停止抓包
4. 进入交互菜单：
   - 输入 **数据包序号** → 查看该包的分层详细信息
   - 输入 **s** → 保存日志到 `log_YYYYMMDD_HHMMSS.txt`
   - 输入 **l** → 重新显示概要列表
   - 输入 **r** → 重新选择网卡抓包
   - 输入 **q** → 退出程序

## 支持的协议

| 层次 | 协议 |
|------|------|
| 数据链路层 | Ethernet II（MAC 地址、EtherType） |
| 网络层 | IPv4（版本、IHL、TTL、协议号、源/目的 IP 等） |
| 传输层 | TCP（端口、序列号、标志位等）、UDP（端口、长度）、ICMP（类型、代码） |
| 应用层 | DNS（事务 ID、查询/响应、域名解析、A/CNAME 记录） |

## 技术要点

- 通过 `LoadLibrary` + `GetProcAddress` 动态加载 `wpcap.dll`，无需 Npcap SDK
- 使用 `#pragma pack(push, 1)` 保证结构体与网络字节流对齐
- 使用 `ntohs` / `ntohl` 处理网络字节序到主机字节序的转换
- DNS 域名解析支持压缩指针（`0xC0` 指针跳转）
- 多线程抓包（`std::thread` + `std::atomic`）
