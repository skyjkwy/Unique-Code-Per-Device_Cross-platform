#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include "ntp_client.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

static const char* ntp_servers[NTP_SERVER_COUNT] = {
    "time.windows.com",           //微软
    "time.nist.gov",             //美国国家标准与技术研究院
    "time.apple.com",           //苹果
    "ntp.tencent.com",         //腾讯
    "ntp.aliyun.com",         //阿里云
    "ntp.ntsc.ac.cn",        //中国国家授时中心
};

static int wsa_initialized = 0;

static SRWLOCK wsa_lock = SRWLOCK_INIT;

static int init_wsa() {
    AcquireSRWLockExclusive(&wsa_lock);
    if (wsa_initialized) {
        ReleaseSRWLockExclusive(&wsa_lock);
        return 0;
    }

    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ReleaseSRWLockExclusive(&wsa_lock);
        return -1;
    }
    wsa_initialized = 1;
    ReleaseSRWLockExclusive(&wsa_lock);
    return 0;
}

static void cleanup_wsa() {
    AcquireSRWLockExclusive(&wsa_lock);
    if (wsa_initialized) {
        WSACleanup();
        wsa_initialized = 0;
    }
    ReleaseSRWLockExclusive(&wsa_lock);
}

static int resolve_host(const char* hostname, struct in_addr* addr) {
    struct addrinfo hints, *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        return -1;
    }

    *addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;

    freeaddrinfo(res);
    return 0;
}

static uint32_t ntp_to_unix_time(uint64_t ntp_timestamp) {

    uint32_t ntp_seconds = (uint32_t)(ntp_timestamp >> 32);

    const uint32_t NTP_OFFSET = 2208988800UL;

    uint32_t unix_time = ntp_seconds - NTP_OFFSET;

    if (unix_time < 946684800UL || unix_time > 4102444800UL) {
        return 0;
    }

    return unix_time;
}

static BOOL query_ntp_server(const char* server_name, uint32_t* result_time) {
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server_addr;
    uint8_t ntp_packet[48];
    uint8_t response[48];

    memset(ntp_packet, 0, sizeof(ntp_packet));
    ntp_packet[0] = 0x23;

    if (resolve_host(server_name, &server_addr.sin_addr) != 0) {
        return FALSE;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(NTP_PORT);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return FALSE;
    }

    int timeout = NTP_TIMEOUT_SECONDS * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    if (sendto(sock, (const char*)ntp_packet, sizeof(ntp_packet), 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return FALSE;
    }

    struct sockaddr_in from_addr;
    int from_len = sizeof(from_addr);
    int recv_len = recvfrom(sock, (char*)response, sizeof(response), 0,
                            (struct sockaddr*)&from_addr, &from_len);

    closesocket(sock);

    if (recv_len != sizeof(response)) {
        return FALSE;
    }

    if (from_addr.sin_addr.s_addr != server_addr.sin_addr.s_addr) {
        return FALSE;
    }

    uint64_t transmit_timestamp = ((uint64_t)response[40] << 24) |
                                   ((uint64_t)response[41] << 16) |
                                   ((uint64_t)response[42] << 8)  |
                                   ((uint64_t)response[43]);
    transmit_timestamp = (transmit_timestamp << 32) |
                          ((uint64_t)response[44] << 24) |
                          ((uint64_t)response[45] << 16) |
                          ((uint64_t)response[46] << 8)  |
                          ((uint64_t)response[47]);

    *result_time = ntp_to_unix_time(transmit_timestamp);
    return (*result_time != 0);
}

BOOL GetNtpTime(uint32_t* ntp_time) {
    if (!ntp_time) return FALSE;

    if (init_wsa() != 0) {
        return FALSE;
    }

    for (int i = 0; i < NTP_SERVER_COUNT; i++) {
        if (query_ntp_server(ntp_servers[i], ntp_time)) {
            cleanup_wsa();
            return TRUE;
        }
    }

    cleanup_wsa();
    return FALSE;
}