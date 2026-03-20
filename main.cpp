#define _WIN32_WINNT 0x0600
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <ctime>
#include <thread>
#include <atomic>
#include <iomanip>
#include <sstream>
#include <cstdlib>
#include "packet_parser.h"

static PcapFuncs g_pcap;
static std::vector<PacketInfo> g_packets;
static std::atomic<bool> g_capturing(false);

// ==================== 工具函数 ====================

static void setConsoleUTF8() {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
}

static std::string truncate(const std::string& s, size_t maxLen) {
    if (s.size() <= maxLen) return s;
    return s.substr(0, maxLen - 3) + "...";
}

static void printBanner() {
    std::cout << "============================================================" << std::endl;
    std::cout << "          网络数据包抓取与分析软件" << std::endl;
    std::cout << "============================================================" << std::endl;
}

// ==================== 打印概要表头与行 ====================

static void printTableHeader() {
    printf("%-6s %-12s %-18s %-18s %-6s %-16s %-16s %-6s %s\n",
           "序号", "时间", "源MAC", "目的MAC", "协议",
           "源IP", "目的IP", "长度", "信息");
    printf("------ ------------ ------------------ ------------------ ------ "
           "---------------- ---------------- ------ --------------------------------\n");
}

static void printPacketRow(const PacketInfo& pkt) {
    printf("%-6d %-12.6f %-18s %-18s %-6s %-16s %-16s %-6d %s\n",
           pkt.index,
           pkt.timestamp,
           truncate(pkt.srcMac, 17).c_str(),
           truncate(pkt.dstMac, 17).c_str(),
           truncate(pkt.protocol, 5).c_str(),
           truncate(pkt.srcIp, 15).c_str(),
           truncate(pkt.dstIp, 15).c_str(),
           pkt.length,
           truncate(pkt.info, 40).c_str());
}

// ==================== 接口选择 ====================

static pcap_if_t* selectInterface() {
    pcap_if_t* allDevs = nullptr;
    char errBuf[256] = {0};
    if (g_pcap.findalldevs(&allDevs, errBuf) == -1 || !allDevs) {
        std::cerr << "获取网络接口失败: " << errBuf << std::endl;
        return nullptr;
    }

    std::cout << "\n可用网络接口:" << std::endl;
    int count = 0;
    for (pcap_if_t* d = allDevs; d; d = d->next) {
        count++;
        std::cout << "  [" << count << "] " << d->name;
        if (d->description) std::cout << "  (" << d->description << ")";

        for (pcap_addr* a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                uint32_t addr = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
                std::cout << "  [IP: " << ipToString(addr) << "]";
            }
        }
        std::cout << std::endl;
    }

    if (count == 0) {
        std::cerr << "未找到可用网络接口" << std::endl;
        g_pcap.freealldevs(allDevs);
        return nullptr;
    }

    int choice = 0;
    while (true) {
        std::cout << "\n请选择网络接口 (1-" << count << "): ";
        std::cin >> choice;
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }
        if (choice >= 1 && choice <= count) break;
        std::cout << "输入无效，请重新选择" << std::endl;
    }
    std::cin.ignore(10000, '\n');

    pcap_if_t* target = allDevs;
    for (int i = 1; i < choice; i++) target = target->next;
    return target;
}

// ==================== 抓包线程 ====================

static void captureThread(pcap_t* handle) {
    pcap_pkthdr* header = nullptr;
    const uint8_t* pktData = nullptr;
    struct timeval firstTs = {0, 0};
    bool first = true;

    while (g_capturing.load()) {
        int res = g_pcap.next_ex(handle, &header, &pktData);
        if (res == 0) continue;  // timeout
        if (res < 0) break;      // error

        if (first) {
            firstTs = header->ts;
            first = false;
        }

        double relTime = (header->ts.tv_sec - firstTs.tv_sec) +
                          (header->ts.tv_usec - firstTs.tv_usec) / 1000000.0;

        int idx = (int)g_packets.size() + 1;
        PacketInfo pkt = buildPacketInfo(idx, relTime, pktData, header->caplen);
        g_packets.push_back(pkt);
        printPacketRow(pkt);
    }
}

// ==================== 日志保存 ====================

static void saveLog() {
    time_t now = time(nullptr);
    struct tm* t = localtime(&now);
    char filename[64];
    strftime(filename, sizeof(filename), "log_%Y%m%d_%H%M%S.txt", t);

    std::ofstream fout(filename, std::ios::out);
    if (!fout.is_open()) {
        std::cerr << "无法创建日志文件: " << filename << std::endl;
        return;
    }

    fout << "网络数据包抓取日志" << std::endl;
    char timeBuf[64];
    strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", t);
    fout << "生成时间: " << timeBuf << std::endl;
    fout << "共抓取 " << g_packets.size() << " 个数据包" << std::endl;
    fout << "============================================================" << std::endl << std::endl;

    char headerLine[256];
    snprintf(headerLine, sizeof(headerLine), "%-6s %-12s %-18s %-18s %-6s %-16s %-16s %-6s %s",
             "序号", "时间", "源MAC", "目的MAC", "协议", "源IP", "目的IP", "长度", "信息");
    fout << headerLine << std::endl;
    fout << "--------------------------------------------------------------"
            "--------------------------------------------------------------" << std::endl;

    for (const auto& pkt : g_packets) {
        char line[512];
        snprintf(line, sizeof(line), "%-6d %-12.6f %-18s %-18s %-6s %-16s %-16s %-6d %s",
                 pkt.index, pkt.timestamp,
                 pkt.srcMac.c_str(), pkt.dstMac.c_str(),
                 pkt.protocol.c_str(), pkt.srcIp.c_str(), pkt.dstIp.c_str(),
                 pkt.length, pkt.info.c_str());
        fout << line << std::endl;
    }

    fout << std::endl;
    fout << "======================== 详细信息 ========================" << std::endl;
    for (const auto& pkt : g_packets) {
        fout << "\n--- 数据包 #" << pkt.index << " ---" << std::endl;
        fout << getPacketDetail(pkt.rawData.data(), (int)pkt.rawData.size());
    }

    fout.close();
    std::cout << "日志已保存到: " << filename << std::endl;
}

// ==================== 交互菜单 ====================

static void interactiveMenu() {
    std::string input;
    while (true) {
        std::cout << "\n---------------------------------------------" << std::endl;
        std::cout << "输入数据包序号查看详情 | s: 保存日志 | l: 重新列出 | q: 退出" << std::endl;
        std::cout << "> ";
        std::getline(std::cin, input);

        if (input.empty()) continue;

        if (input == "q" || input == "Q") {
            std::cout << "退出程序" << std::endl;
            break;
        }
        if (input == "s" || input == "S") {
            saveLog();
            continue;
        }
        if (input == "l" || input == "L") {
            printTableHeader();
            for (const auto& pkt : g_packets) printPacketRow(pkt);
            std::cout << "共 " << g_packets.size() << " 个数据包" << std::endl;
            continue;
        }

        int idx = atoi(input.c_str());
        if (idx == 0) {
            std::cout << "无效输入" << std::endl;
            continue;
        }

        if (idx < 1 || idx > (int)g_packets.size()) {
            std::cout << "序号超出范围 (1-" << g_packets.size() << ")" << std::endl;
            continue;
        }

        const PacketInfo& pkt = g_packets[idx - 1];
        std::cout << "\n========== 数据包 #" << pkt.index << " 详细信息 ==========" << std::endl;
        std::cout << getPacketDetail(pkt.rawData.data(), (int)pkt.rawData.size());
    }
}

// ==================== 主函数 ====================

int main() {
    setConsoleUTF8();
    printBanner();

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (!loadPcap(g_pcap)) {
        std::cerr << "无法加载 wpcap.dll，请确认已安装 Npcap 或 WinPcap" << std::endl;
        std::cerr << "Npcap 下载地址: https://npcap.com/" << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "Npcap 加载成功" << std::endl;

    pcap_if_t* allDevs = nullptr;
    char errBuf[256] = {0};
    g_pcap.findalldevs(&allDevs, errBuf);

    pcap_if_t* dev = selectInterface();
    if (!dev) {
        system("pause");
        return 1;
    }

    std::string devName = dev->name;
    g_pcap.freealldevs(allDevs);

    pcap_t* handle = g_pcap.open_live(devName.c_str(), 65536, 1, 1000, errBuf);
    if (!handle) {
        std::cerr << "打开网络接口失败: " << errBuf << std::endl;
        std::cerr << "请以管理员身份运行本程序" << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "\n开始抓包... (按 Enter 键停止)\n" << std::endl;
    printTableHeader();

    g_capturing.store(true);
    std::thread capThread(captureThread, handle);

    std::cin.get();
    g_capturing.store(false);

    capThread.join();
    g_pcap.close(handle);

    std::cout << "\n抓包结束，共抓取 " << g_packets.size() << " 个数据包" << std::endl;

    if (g_packets.empty()) {
        std::cout << "未抓取到任何数据包" << std::endl;
        system("pause");
        return 0;
    }

    interactiveMenu();

    WSACleanup();
    return 0;
}
