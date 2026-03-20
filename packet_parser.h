#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

#pragma pack(push, 1)

// ==================== pcap 类型与动态加载 ====================

struct pcap_addr {
    pcap_addr*      next;
    struct sockaddr* addr;
    struct sockaddr* netmask;
    struct sockaddr* broadaddr;
    struct sockaddr* dstaddr;
};

struct pcap_if_t {
    pcap_if_t*  next;
    char*       name;
    char*       description;
    pcap_addr*  addresses;
    uint32_t    flags;
};

struct pcap_pkthdr {
    struct timeval ts;
    uint32_t caplen;
    uint32_t len;
};

typedef void pcap_t;

typedef int   (__cdecl *fn_pcap_findalldevs)(pcap_if_t**, char*);
typedef void  (__cdecl *fn_pcap_freealldevs)(pcap_if_t*);
typedef pcap_t* (__cdecl *fn_pcap_open_live)(const char*, int, int, int, char*);
typedef int   (__cdecl *fn_pcap_next_ex)(pcap_t*, pcap_pkthdr**, const uint8_t**);
typedef void  (__cdecl *fn_pcap_close)(pcap_t*);

struct PcapFuncs {
    HMODULE              hLib;
    fn_pcap_findalldevs  findalldevs;
    fn_pcap_freealldevs  freealldevs;
    fn_pcap_open_live    open_live;
    fn_pcap_next_ex      next_ex;
    fn_pcap_close        close;
};

inline bool loadPcap(PcapFuncs& f) {
    f.hLib = LoadLibraryA("wpcap.dll");
    if (!f.hLib) return false;
    f.findalldevs = (fn_pcap_findalldevs)GetProcAddress(f.hLib, "pcap_findalldevs");
    f.freealldevs = (fn_pcap_freealldevs)GetProcAddress(f.hLib, "pcap_freealldevs");
    f.open_live   = (fn_pcap_open_live)  GetProcAddress(f.hLib, "pcap_open_live");
    f.next_ex     = (fn_pcap_next_ex)    GetProcAddress(f.hLib, "pcap_next_ex");
    f.close       = (fn_pcap_close)      GetProcAddress(f.hLib, "pcap_close");
    return f.findalldevs && f.freealldevs && f.open_live && f.next_ex && f.close;
}

// ==================== 以太网帧头部 ====================

struct EthernetHeader {
    uint8_t  dstMac[6];
    uint8_t  srcMac[6];
    uint16_t etherType;
};

inline std::string macToString(const uint8_t mac[6]) {
    char buf[24];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

inline std::string etherTypeToString(uint16_t t) {
    switch (t) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x86DD: return "IPv6";
        default: {
            char buf[16];
            snprintf(buf, sizeof(buf), "0x%04X", t);
            return buf;
        }
    }
}

inline std::string parseEthernet(const EthernetHeader* eth) {
    std::ostringstream ss;
    uint16_t type = ntohs(eth->etherType);
    ss << "=== 以太网帧 (Ethernet II) ===" << std::endl;
    ss << "  目的MAC:  " << macToString(eth->dstMac) << std::endl;
    ss << "  源MAC:    " << macToString(eth->srcMac) << std::endl;
    ss << "  类型:     0x" << std::hex << std::setw(4) << std::setfill('0') << type
       << " (" << etherTypeToString(type) << ")" << std::dec << std::endl;
    return ss.str();
}

// ==================== IP 头部 ====================

struct IPHeader {
    uint8_t  verIhl;
    uint8_t  tos;
    uint16_t totalLen;
    uint16_t id;
    uint16_t flagsOffset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t srcAddr;
    uint32_t dstAddr;
};

inline std::string ipToString(uint32_t ip) {
    uint8_t* b = (uint8_t*)&ip;
    char buf[20];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

inline std::string protocolToString(uint8_t proto) {
    switch (proto) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        default: {
            char buf[16];
            snprintf(buf, sizeof(buf), "%u", proto);
            return buf;
        }
    }
}

inline std::string parseIP(const IPHeader* ip) {
    uint8_t version = (ip->verIhl >> 4) & 0x0F;
    uint8_t ihl = (ip->verIhl & 0x0F) * 4;
    uint16_t totalLen = ntohs(ip->totalLen);
    uint16_t id = ntohs(ip->id);
    uint16_t fo = ntohs(ip->flagsOffset);
    uint8_t flags = (fo >> 13) & 0x07;
    uint16_t offset = fo & 0x1FFF;

    std::ostringstream ss;
    ss << "=== IP 头部 ===" << std::endl;
    ss << "  版本:       " << (int)version << std::endl;
    ss << "  头部长度:   " << (int)ihl << " 字节" << std::endl;
    ss << "  服务类型:   0x" << std::hex << std::setw(2) << std::setfill('0') << (int)ip->tos << std::dec << std::endl;
    ss << "  总长度:     " << totalLen << std::endl;
    ss << "  标识:       0x" << std::hex << std::setw(4) << std::setfill('0') << id << std::dec << std::endl;
    ss << "  标志:       ";
    if (flags & 0x02) ss << "DF ";
    if (flags & 0x01) ss << "MF ";
    if (!(flags & 0x03)) ss << "无";
    ss << std::endl;
    ss << "  片偏移:     " << offset << std::endl;
    ss << "  生存时间:   " << (int)ip->ttl << std::endl;
    ss << "  协议:       " << protocolToString(ip->protocol) << " (" << (int)ip->protocol << ")" << std::endl;
    ss << "  校验和:     0x" << std::hex << std::setw(4) << std::setfill('0') << ntohs(ip->checksum) << std::dec << std::endl;
    ss << "  源IP:       " << ipToString(ip->srcAddr) << std::endl;
    ss << "  目的IP:     " << ipToString(ip->dstAddr) << std::endl;
    return ss.str();
}

// ==================== TCP 头部 ====================

struct TCPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t  dataOffsetReserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPtr;
};

inline std::string tcpFlagsToString(uint8_t f) {
    std::string s;
    if (f & 0x20) s += "URG,";
    if (f & 0x10) s += "ACK,";
    if (f & 0x08) s += "PSH,";
    if (f & 0x04) s += "RST,";
    if (f & 0x02) s += "SYN,";
    if (f & 0x01) s += "FIN,";
    if (!s.empty()) s.pop_back();
    return "[" + s + "]";
}

inline std::string parseTCP(const TCPHeader* tcp) {
    uint8_t dataOffset = ((tcp->dataOffsetReserved >> 4) & 0x0F) * 4;
    std::ostringstream ss;
    ss << "=== TCP 头部 ===" << std::endl;
    ss << "  源端口:     " << ntohs(tcp->srcPort) << std::endl;
    ss << "  目的端口:   " << ntohs(tcp->dstPort) << std::endl;
    ss << "  序列号:     " << ntohl(tcp->seqNum) << std::endl;
    ss << "  确认号:     " << ntohl(tcp->ackNum) << std::endl;
    ss << "  头部长度:   " << (int)dataOffset << " 字节" << std::endl;
    ss << "  标志:       " << tcpFlagsToString(tcp->flags) << std::endl;
    ss << "  窗口大小:   " << ntohs(tcp->window) << std::endl;
    ss << "  校验和:     0x" << std::hex << std::setw(4) << std::setfill('0') << ntohs(tcp->checksum) << std::dec << std::endl;
    ss << "  紧急指针:   " << ntohs(tcp->urgentPtr) << std::endl;
    return ss.str();
}

// ==================== UDP 头部 ====================

struct UDPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
};

inline std::string parseUDP(const UDPHeader* udp) {
    std::ostringstream ss;
    ss << "=== UDP 头部 ===" << std::endl;
    ss << "  源端口:     " << ntohs(udp->srcPort) << std::endl;
    ss << "  目的端口:   " << ntohs(udp->dstPort) << std::endl;
    ss << "  长度:       " << ntohs(udp->length) << std::endl;
    ss << "  校验和:     0x" << std::hex << std::setw(4) << std::setfill('0') << ntohs(udp->checksum) << std::dec << std::endl;
    return ss.str();
}

// ==================== ICMP 头部 ====================

struct ICMPHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

inline std::string icmpTypeToString(uint8_t type) {
    switch (type) {
        case 0:  return "Echo Reply";
        case 3:  return "Destination Unreachable";
        case 5:  return "Redirect";
        case 8:  return "Echo Request";
        case 11: return "Time Exceeded";
        default: {
            char buf[16];
            snprintf(buf, sizeof(buf), "Type %u", type);
            return buf;
        }
    }
}

inline std::string parseICMP(const ICMPHeader* icmp) {
    std::ostringstream ss;
    ss << "=== ICMP 头部 ===" << std::endl;
    ss << "  类型:       " << (int)icmp->type << " (" << icmpTypeToString(icmp->type) << ")" << std::endl;
    ss << "  代码:       " << (int)icmp->code << std::endl;
    ss << "  校验和:     0x" << std::hex << std::setw(4) << std::setfill('0') << ntohs(icmp->checksum) << std::dec << std::endl;
    ss << "  标识:       " << ntohs(icmp->id) << std::endl;
    ss << "  序列号:     " << ntohs(icmp->seq) << std::endl;
    return ss.str();
}

// ==================== DNS 头部与解析 ====================

struct DNSHeader {
    uint16_t transId;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority;
    uint16_t additional;
};

inline int parseDnsName(const uint8_t* dnsPayload, int payloadLen, int offset, std::string& name) {
    name.clear();
    int jumped = 0;
    int maxJumps = 50;

    while (offset < payloadLen && maxJumps-- > 0) {
        uint8_t len = dnsPayload[offset];
        if (len == 0) {
            offset++;
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= payloadLen) break;
            int ptr = ((len & 0x3F) << 8) | dnsPayload[offset + 1];
            if (jumped == 0) jumped = offset + 2;
            offset = ptr;
            continue;
        }
        offset++;
        if (offset + len > payloadLen) break;
        if (!name.empty()) name += ".";
        name.append((const char*)&dnsPayload[offset], len);
        offset += len;
    }
    return jumped ? jumped : offset;
}

inline std::string dnsTypeToString(uint16_t t) {
    switch (t) {
        case 1:  return "A";
        case 2:  return "NS";
        case 5:  return "CNAME";
        case 6:  return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        default: {
            char buf[16];
            snprintf(buf, sizeof(buf), "TYPE%u", t);
            return buf;
        }
    }
}

inline std::string parseDNS(const uint8_t* data, int len) {
    if (len < (int)sizeof(DNSHeader)) return "";
    const DNSHeader* dns = (const DNSHeader*)data;
    uint16_t flags = ntohs(dns->flags);
    uint16_t qCount = ntohs(dns->questions);
    uint16_t aCount = ntohs(dns->answers);

    std::ostringstream ss;
    ss << "=== DNS 头部 ===" << std::endl;
    ss << "  事务ID:     0x" << std::hex << std::setw(4) << std::setfill('0') << ntohs(dns->transId) << std::dec << std::endl;
    ss << "  标志:       0x" << std::hex << std::setw(4) << std::setfill('0') << flags << std::dec;
    ss << " (" << ((flags & 0x8000) ? "响应" : "查询") << ")" << std::endl;
    ss << "  问题数:     " << qCount << std::endl;
    ss << "  回答数:     " << aCount << std::endl;
    ss << "  授权数:     " << ntohs(dns->authority) << std::endl;
    ss << "  附加数:     " << ntohs(dns->additional) << std::endl;

    int offset = sizeof(DNSHeader);

    for (int i = 0; i < qCount && offset < len; i++) {
        std::string qname;
        offset = parseDnsName(data, len, offset, qname);
        if (offset + 4 > len) break;
        uint16_t qtype = (data[offset] << 8) | data[offset + 1];
        offset += 4;
        ss << "  [查询] " << qname << " 类型:" << dnsTypeToString(qtype) << std::endl;
    }

    for (int i = 0; i < aCount && offset < len; i++) {
        std::string aname;
        offset = parseDnsName(data, len, offset, aname);
        if (offset + 10 > len) break;
        uint16_t atype = (data[offset] << 8) | data[offset + 1];
        uint16_t rdlen = (data[offset + 8] << 8) | data[offset + 9];
        offset += 10;
        if (offset + rdlen > len) break;

        ss << "  [回答] " << aname << " 类型:" << dnsTypeToString(atype);
        if (atype == 1 && rdlen == 4) {
            ss << " -> " << (int)data[offset] << "." << (int)data[offset+1]
               << "." << (int)data[offset+2] << "." << (int)data[offset+3];
        } else if (atype == 5) {
            std::string cname;
            parseDnsName(data, len, offset, cname);
            ss << " -> " << cname;
        }
        ss << std::endl;
        offset += rdlen;
    }
    return ss.str();
}

// ==================== 获取 DNS 查询域名（用于概要信息） ====================

inline std::string getDnsQueryName(const uint8_t* data, int len) {
    if (len < (int)sizeof(DNSHeader)) return "";
    int offset = sizeof(DNSHeader);
    std::string name;
    parseDnsName(data, len, offset, name);
    return name;
}

#pragma pack(pop)

// ==================== 综合数据包信息 ====================

struct PacketInfo {
    int            index;
    double         timestamp;
    std::string    srcMac;
    std::string    dstMac;
    std::string    protocol;
    std::string    srcIp;
    std::string    dstIp;
    int            length;
    std::string    info;
    std::vector<uint8_t> rawData;
};

inline std::string getPacketDetail(const uint8_t* data, int len) {
    std::ostringstream ss;
    if (len < (int)sizeof(EthernetHeader)) return "数据包过短\n";

    const EthernetHeader* eth = (const EthernetHeader*)data;
    ss << parseEthernet(eth);

    uint16_t etherType = ntohs(eth->etherType);
    if (etherType != 0x0800) {
        ss << "  (非IPv4数据包, 不做进一步解析)" << std::endl;
        return ss.str();
    }

    int ipOffset = sizeof(EthernetHeader);
    if (ipOffset + (int)sizeof(IPHeader) > len) return ss.str();

    const IPHeader* ip = (const IPHeader*)(data + ipOffset);
    ss << parseIP(ip);

    uint8_t ihl = (ip->verIhl & 0x0F) * 4;
    int transportOffset = ipOffset + ihl;

    switch (ip->protocol) {
        case 6: {
            if (transportOffset + (int)sizeof(TCPHeader) > len) break;
            const TCPHeader* tcp = (const TCPHeader*)(data + transportOffset);
            ss << parseTCP(tcp);
            break;
        }
        case 17: {
            if (transportOffset + (int)sizeof(UDPHeader) > len) break;
            const UDPHeader* udp = (const UDPHeader*)(data + transportOffset);
            ss << parseUDP(udp);
            uint16_t srcPort = ntohs(udp->srcPort);
            uint16_t dstPort = ntohs(udp->dstPort);
            if (srcPort == 53 || dstPort == 53) {
                int dnsOffset = transportOffset + sizeof(UDPHeader);
                int dnsLen = len - dnsOffset;
                if (dnsLen > 0) {
                    ss << parseDNS(data + dnsOffset, dnsLen);
                }
            }
            break;
        }
        case 1: {
            if (transportOffset + (int)sizeof(ICMPHeader) > len) break;
            const ICMPHeader* icmp = (const ICMPHeader*)(data + transportOffset);
            ss << parseICMP(icmp);
            break;
        }
        default:
            ss << "=== 未知传输层协议 (" << (int)ip->protocol << ") ===" << std::endl;
            break;
    }
    return ss.str();
}

inline PacketInfo buildPacketInfo(int idx, double ts, const uint8_t* data, int len) {
    PacketInfo pkt;
    pkt.index = idx;
    pkt.timestamp = ts;
    pkt.length = len;
    pkt.rawData.assign(data, data + len);

    if (len < (int)sizeof(EthernetHeader)) {
        pkt.protocol = "???";
        pkt.info = "数据包过短";
        return pkt;
    }

    const EthernetHeader* eth = (const EthernetHeader*)data;
    pkt.srcMac = macToString(eth->srcMac);
    pkt.dstMac = macToString(eth->dstMac);

    uint16_t etherType = ntohs(eth->etherType);
    if (etherType == 0x0806) {
        pkt.protocol = "ARP";
        pkt.info = "ARP";
        return pkt;
    }
    if (etherType == 0x86DD) {
        pkt.protocol = "IPv6";
        pkt.info = "IPv6";
        return pkt;
    }
    if (etherType != 0x0800) {
        pkt.protocol = etherTypeToString(etherType);
        pkt.info = "非IPv4";
        return pkt;
    }

    int ipOff = sizeof(EthernetHeader);
    if (ipOff + (int)sizeof(IPHeader) > len) {
        pkt.protocol = "IP?";
        pkt.info = "IP头不完整";
        return pkt;
    }

    const IPHeader* ip = (const IPHeader*)(data + ipOff);
    pkt.srcIp = ipToString(ip->srcAddr);
    pkt.dstIp = ipToString(ip->dstAddr);

    uint8_t ihl = (ip->verIhl & 0x0F) * 4;
    int tOff = ipOff + ihl;

    switch (ip->protocol) {
        case 6: {
            pkt.protocol = "TCP";
            if (tOff + (int)sizeof(TCPHeader) <= len) {
                const TCPHeader* tcp = (const TCPHeader*)(data + tOff);
                std::ostringstream info;
                info << ntohs(tcp->srcPort) << " -> " << ntohs(tcp->dstPort)
                     << " " << tcpFlagsToString(tcp->flags);
                pkt.info = info.str();
            }
            break;
        }
        case 17: {
            if (tOff + (int)sizeof(UDPHeader) <= len) {
                const UDPHeader* udp = (const UDPHeader*)(data + tOff);
                uint16_t sp = ntohs(udp->srcPort);
                uint16_t dp = ntohs(udp->dstPort);
                if (sp == 53 || dp == 53) {
                    pkt.protocol = "DNS";
                    int dnsOff = tOff + sizeof(UDPHeader);
                    int dnsLen = len - dnsOff;
                    std::string qname = getDnsQueryName(data + dnsOff, dnsLen);
                    const DNSHeader* dns = (dnsLen >= (int)sizeof(DNSHeader))
                        ? (const DNSHeader*)(data + dnsOff) : nullptr;
                    bool isResp = dns && (ntohs(dns->flags) & 0x8000);
                    std::ostringstream info;
                    info << (isResp ? "响应" : "查询");
                    if (!qname.empty()) info << " " << qname;
                    pkt.info = info.str();
                } else {
                    pkt.protocol = "UDP";
                    std::ostringstream info;
                    info << sp << " -> " << dp;
                    pkt.info = info.str();
                }
            } else {
                pkt.protocol = "UDP";
            }
            break;
        }
        case 1: {
            pkt.protocol = "ICMP";
            if (tOff + (int)sizeof(ICMPHeader) <= len) {
                const ICMPHeader* icmp = (const ICMPHeader*)(data + tOff);
                pkt.info = icmpTypeToString(icmp->type);
            }
            break;
        }
        default: {
            char buf[32];
            snprintf(buf, sizeof(buf), "IP_Proto_%u", ip->protocol);
            pkt.protocol = buf;
            break;
        }
    }
    return pkt;
}

#endif // PACKET_PARSER_H
