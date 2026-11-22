#include "ntp_client.h"

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static const char *ntp_servers[NTP_SERVER_COUNT] = {
    "time.windows.com",
    "time.nist.gov",
    "time.apple.com",
    "ntp.tencent.com",
    "ntp.aliyun.com",
    "ntp.ntsc.ac.cn",
};

static uint32_t ntp_to_unix_time(uint64_t ntp_timestamp) {
    uint32_t ntp_seconds = (uint32_t)(ntp_timestamp >> 32);
    const uint32_t NTP_OFFSET = 2208988800UL;
    uint32_t unix_time = ntp_seconds - NTP_OFFSET;
    if (unix_time < 946684800UL || unix_time > 4102444800UL) {
        return 0;
    }
    return unix_time;
}

static lic_bool query_ntp_server(const char *server_name, uint32_t *result_time) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char port[8];
    snprintf(port, sizeof(port), "%d", NTP_PORT);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(server_name, port, &hints, &res) != 0 || !res) {
        return FALSE;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        return FALSE;
    }

    uint8_t packet[48];
    uint8_t response[48];
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x23;

    if (sendto(sock, packet, sizeof(packet), 0, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        return FALSE;
    }

    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ready = poll(&pfd, 1, NTP_TIMEOUT_SECONDS * 1000);
    if (ready <= 0 || !(pfd.revents & POLLIN)) {
        close(sock);
        freeaddrinfo(res);
        return FALSE;
    }

    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);
    ssize_t recv_len = recvfrom(sock, response, sizeof(response), 0,
                                (struct sockaddr *)&from, &from_len);
    close(sock);
    freeaddrinfo(res);

    if (recv_len != (ssize_t)sizeof(response)) {
        return FALSE;
    }

    uint64_t transmit_timestamp = ((uint64_t)response[40] << 24) |
                                  ((uint64_t)response[41] << 16) |
                                  ((uint64_t)response[42] << 8) |
                                  ((uint64_t)response[43]);
    transmit_timestamp = (transmit_timestamp << 32) |
                         ((uint64_t)response[44] << 24) |
                         ((uint64_t)response[45] << 16) |
                         ((uint64_t)response[46] << 8) |
                         ((uint64_t)response[47]);

    *result_time = ntp_to_unix_time(transmit_timestamp);
    return (*result_time != 0) ? TRUE : FALSE;
}

lic_bool GetNtpTime(uint32_t *ntp_time) {
    if (!ntp_time) return FALSE;

    for (int i = 0; i < NTP_SERVER_COUNT; i++) {
        if (query_ntp_server(ntp_servers[i], ntp_time)) {
            return TRUE;
        }
    }
    return FALSE;
}
