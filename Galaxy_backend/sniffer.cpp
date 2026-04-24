/*
  Network Traffic Monitoring - C++ Backend
  Uses Windows API for threading (compatible with older MinGW)
  Compile:
  g++ sniffer.cpp -o sniffer.exe -I"C:\Users\User\Downloads\npcap-sdk-1.16\Include" -L"C:\Users\User\Downloads\npcap-sdk-1.16\Lib\x64" -lwpcap -lPacket -lws2_32 -std=c++17 -O2
*/

#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <algorithm>

#include <pcap.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

// ── Windows mutex wrapper ───────────────────────────────────────────────────
struct WinMutex
{
    CRITICAL_SECTION cs;
    WinMutex() { InitializeCriticalSection(&cs); }
    ~WinMutex() { DeleteCriticalSection(&cs); }
    void lock() { EnterCriticalSection(&cs); }
    void unlock() { LeaveCriticalSection(&cs); }
};

struct LockGuard
{
    WinMutex &m;
    LockGuard(WinMutex &mx) : m(mx) { m.lock(); }
    ~LockGuard() { m.unlock(); }
};

// ── Header structs ──────────────────────────────────────────────────────────
#pragma pack(push, 1)

struct EthernetHeader
{
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};

struct IPv4Header
{
    uint8_t ihl_version;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct TCPHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

struct UDPHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

#pragma pack(pop)

// ── Packet record ───────────────────────────────────────────────────────────
struct PacketRecord
{
    std::string timestamp;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    int src_port;
    int dst_port;
    int size;
    std::string service;
};

// ── Globals ──────────────────────────────────────────────────────────────────
std::vector<PacketRecord> g_packets;
WinMutex g_mutex;
volatile bool g_running = false;
pcap_t *g_handle = nullptr;
std::string g_currentDevice;

// ── Port to service map ──────────────────────────────────────────────────────
std::string portToService(int port)
{
    static const std::map<int, std::string> s = {
        {20, "FTP-DATA"}, {21, "FTP"}, {22, "SSH"}, {23, "TELNET"}, {25, "SMTP"}, {53, "DNS"}, {67, "DHCP"}, {68, "DHCP"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"}, {443, "HTTPS"}, {3306, "MySQL"}, {3389, "RDP"}, {5432, "PostgreSQL"}, {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"}, {123, "NTP"}, {161, "SNMP"}, {389, "LDAP"}, {993, "IMAPS"}, {995, "POP3S"}, {1433, "MSSQL"}, {27017, "MongoDB"}, {6379, "Redis"}, {5900, "VNC"},{5353,"mDNS"}, {1900,"SSDP"}, {137,"NetBIOS"},
{138,"NetBIOS"}, {139,"NetBIOS"}, {445,"SMB"},
{500,"IKE/VPN"}, {4500,"IPSec"}, {1194,"OpenVPN"},
{5228,"GCM/Android"}, {5222,"XMPP"}};
    auto it = s.find(port);
    return it != s.end() ? it->second : "Unknown";
}

// ── Helpers ──────────────────────────────────────────────────────────────────
std::string getTimestamp()
{
    time_t now = time(nullptr);
    struct tm *t = localtime(&now);
    char buf[32];
    strftime(buf, sizeof(buf), "%H:%M:%S", t);
    return std::string(buf);
}

std::string ipToStr(uint32_t ip)
{
    in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

std::string escapeJson(const std::string &s)
{
    std::string out;
    for (char c : s)
    {
        if (c == '"')
            out += "\\\"";
        else if (c == '\\')
            out += "\\\\";
        else
            out += c;
    }
    return out;
}

// ── Packet callback ───────────────────────────────────────────────────────────
void packetHandler(u_char *, const struct pcap_pkthdr *header, const u_char *data)
{
    if (!g_running)
        return;
    if (header->caplen < sizeof(EthernetHeader))
        return;

    const EthernetHeader *eth = (const EthernetHeader *)data;
    if (ntohs(eth->type) != 0x0800)
        return; // IPv4 only

    size_t offset = sizeof(EthernetHeader);
    if (header->caplen < offset + sizeof(IPv4Header))
        return;

    const IPv4Header *ip = (const IPv4Header *)(data + offset);
    int ihl = (ip->ihl_version & 0x0F) * 4;
    offset += ihl;

    PacketRecord rec;
    rec.timestamp = getTimestamp();
    rec.src_ip = ipToStr(ip->src_ip);
    rec.dst_ip = ipToStr(ip->dst_ip);
    rec.size = ntohs(ip->total_length);
    rec.src_port = 0;
    rec.dst_port = 0;
    rec.service = "N/A";

    switch (ip->protocol)
    {
    case 6:
        rec.protocol = "TCP";
        if (header->caplen >= offset + sizeof(TCPHeader))
        {
            const TCPHeader *tcp = (const TCPHeader *)(data + offset);
            rec.src_port = ntohs(tcp->src_port);
            rec.dst_port = ntohs(tcp->dst_port);
            rec.service = portToService(rec.dst_port);
            if (rec.service == "Unknown")
                rec.service = portToService(rec.src_port);
        }
        break;
    case 17:
        rec.protocol = "UDP";
        if (header->caplen >= offset + sizeof(UDPHeader))
        {
            const UDPHeader *udp = (const UDPHeader *)(data + offset);
            rec.src_port = ntohs(udp->src_port);
            rec.dst_port = ntohs(udp->dst_port);
            rec.service = portToService(rec.dst_port);
            if (rec.service == "Unknown")
                rec.service = portToService(rec.src_port);
        }
        break;
    case 1:
        rec.protocol = "ICMP";
        rec.service = "ICMP";
        break;
    default:
        rec.protocol = "OTHER";
        break;
    }

    LockGuard lock(g_mutex);
    g_packets.push_back(rec);
    if (g_packets.size() > 5000)
        g_packets.erase(g_packets.begin(), g_packets.begin() + 1000);
}

// ── Capture thread ────────────────────────────────────────────────────────────
DWORD WINAPI captureThread(LPVOID)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(g_currentDevice.c_str(), 65535, 1, 100, errbuf);
    if (!g_handle)
    {
        std::cerr << "[ERROR] pcap_open_live: " << errbuf << "\n";
        g_running = false;
        return 1;
    }
    std::cout << "[INFO] Capturing on: " << g_currentDevice << "\n";
    while (g_running)
    {
        pcap_dispatch(g_handle, 10, packetHandler, nullptr);
    }
    pcap_close(g_handle);
    g_handle = nullptr;
    std::cout << "[INFO] Capture stopped.\n";
    return 0;
}

// ── JSON builders ─────────────────────────────────────────────────────────────
std::string buildPacketsJson()
{
    LockGuard lock(g_mutex);
    std::ostringstream ss;
    ss << "[";
    for (size_t i = 0; i < g_packets.size(); i++)
    {
        const auto &p = g_packets[i];
        if (i)
            ss << ",";
        ss << "{"
           << "\"time\":\"" << escapeJson(p.timestamp) << "\","
           << "\"src_ip\":\"" << escapeJson(p.src_ip) << "\","
           << "\"dst_ip\":\"" << escapeJson(p.dst_ip) << "\","
           << "\"protocol\":\"" << escapeJson(p.protocol) << "\","
           << "\"src_port\":" << p.src_port << ","
           << "\"dst_port\":" << p.dst_port << ","
           << "\"size\":" << p.size << ","
           << "\"service\":\"" << escapeJson(p.service) << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildStatsJson()
{
    LockGuard lock(g_mutex);
    int tcp = 0, udp = 0, icmp = 0, other = 0;
    long long total_size = 0;
    for (const auto &p : g_packets)
    {
        if (p.protocol == "TCP")
            tcp++;
        else if (p.protocol == "UDP")
            udp++;
        else if (p.protocol == "ICMP")
            icmp++;
        else
            other++;
        total_size += p.size;
    }
    int total = (int)g_packets.size();
    int avg = total > 0 ? (int)(total_size / total) : 0;
    std::ostringstream ss;
    ss << "{"
       << "\"total\":" << total << ","
       << "\"tcp\":" << tcp << ","
       << "\"udp\":" << udp << ","
       << "\"icmp\":" << icmp << ","
       << "\"other\":" << other << ","
       << "\"avg_size\":" << avg << ","
       << "\"running\":" << (g_running ? "true" : "false")
       << "}";
    return ss.str();
}

std::string buildDevicesJson()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    std::ostringstream ss;
    ss << "[";
    if (pcap_findalldevs(&alldevs, errbuf) == 0)
    {
        bool first = true;
        for (pcap_if_t *d = alldevs; d; d = d->next)
        {
            if (!first)
                ss << ",";
            first = false;
            std::string name = d->name ? d->name : "";
            std::string desc = d->description ? d->description : "";
            ss << "{\"name\":\"" << escapeJson(name) << "\","
               << "\"desc\":\"" << escapeJson(desc) << "\"}";
        }
        pcap_freealldevs(alldevs);
    }
    ss << "]";
    return ss.str();
}

// ── HTTP response builder ─────────────────────────────────────────────────────
std::string httpResp(int code, const std::string &ct, const std::string &body)
{
    std::string status = code == 200 ? "200 OK" : code == 404 ? "404 Not Found"
                                                              : "400 Bad Request";
    std::ostringstream ss;
    ss << "HTTP/1.1 " << status << "\r\n"
       << "Content-Type: " << ct << "\r\n"
       << "Access-Control-Allow-Origin: *\r\n"
       << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
       << "Access-Control-Allow-Headers: Content-Type\r\n"
       << "Content-Length: " << body.size() << "\r\n"
       << "Connection: close\r\n\r\n"
       << body;
    return ss.str();
}

// ── Per-client handler thread ─────────────────────────────────────────────────
DWORD WINAPI clientThread(LPVOID arg)
{
    SOCKET client = (SOCKET)(uintptr_t)arg;

    char buf[4096] = {};
    recv(client, buf, sizeof(buf) - 1, 0);
    std::string req(buf);

    std::string method, path;
    std::istringstream rs(req);
    rs >> method >> path;

    std::string resp;

    if (method == "OPTIONS")
    {
        resp = httpResp(200, "text/plain", "");
    }
    else if (path == "/api/packets")
    {
        resp = httpResp(200, "application/json", buildPacketsJson());
    }
    else if (path == "/api/stats")
    {
        resp = httpResp(200, "application/json", buildStatsJson());
    }
    else if (path == "/api/devices")
    {
        resp = httpResp(200, "application/json", buildDevicesJson());
    }
    else if (path.find("/api/start") == 0)
    {
        std::string dev;
        size_t pos = path.find("?dev=");
        if (pos != std::string::npos)
        {
            dev = path.substr(pos + 5);
            std::string decoded;
            for (size_t i = 0; i < dev.size(); i++)
            {
                if (dev[i] == '%' && i + 2 < dev.size())
                {
                    int val;
                    std::istringstream hex(dev.substr(i + 1, 2));
                    hex >> std::hex >> val;
                    decoded += (char)val;
                    i += 2;
                }
                else if (dev[i] == '+')
                {
                    decoded += ' ';
                }
                else
                {
                    decoded += dev[i];
                }
            }
            dev = decoded;
        }

        if (!g_running)
        {
            if (!dev.empty())
                g_currentDevice = dev;
            g_running = true;
            {
                LockGuard lock(g_mutex);
                g_packets.clear();
            }
            HANDLE t = CreateThread(nullptr, 0, captureThread, nullptr, 0, nullptr);
            if (t)
                CloseHandle(t);
            resp = httpResp(200, "application/json", "{\"ok\":true,\"msg\":\"Monitoring started\"}");
        }
        else
        {
            resp = httpResp(200, "application/json", "{\"ok\":false,\"msg\":\"Already running\"}");
        }
    }
    else if (path == "/api/stop")
    {
        if (g_running)
        {
            g_running = false;
            Sleep(400);
            resp = httpResp(200, "application/json", "{\"ok\":true,\"msg\":\"Monitoring stopped\"}");
        }
        else
        {
            resp = httpResp(200, "application/json", "{\"ok\":false,\"msg\":\"Not running\"}");
        }
    }
    else if (path == "/api/clear")
    {
        LockGuard lock(g_mutex);
        g_packets.clear();
        resp = httpResp(200, "application/json", "{\"ok\":true}");
    }
    else
    {
        resp = httpResp(404, "application/json", "{\"error\":\"Not found\"}");
    }

    send(client, resp.c_str(), (int)resp.size(), 0);
    closesocket(client);
    return 0;
}

// ── Main ──────────────────────────────────────────────────────────────────────
int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == INVALID_SOCKET)
    {
        std::cerr << "[ERROR] socket() failed\n";
        return 1;
    }

    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8765);

    if (bind(server, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        std::cerr << "[ERROR] bind() failed — is port 8765 already in use?\n";
        return 1;
    }

    listen(server, SOMAXCONN);

    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════╗\n";
    std::cout << "║  NetMon Backend  —  Listening :8765  ║\n";
    std::cout << "╚══════════════════════════════════════╝\n";
    std::cout << "Open your frontend and select a device.\n\n";

    while (true)
    {
        SOCKET client = accept(server, nullptr, nullptr);
        if (client == INVALID_SOCKET)
            continue;
        HANDLE t = CreateThread(nullptr, 0, clientThread, (LPVOID)(uintptr_t)client, 0, nullptr);
        if (t)
            CloseHandle(t);
    }

    WSACleanup();
    return 0;
}
