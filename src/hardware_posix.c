#include "hardware.h"

#include <ctype.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__linux__)
#include <netpacket/packet.h>
#elif defined(__APPLE__)
#include <net/if_dl.h>
#include <sys/sysctl.h>
#endif

static void trim_text(char *s) {
    if (!s) return;
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
}

static lic_bool read_first_line(const char *path, char *out, size_t cap) {
    FILE *fp = fopen(path, "r");
    if (!fp) return FALSE;
    lic_bool ok = FALSE;
    if (fgets(out, (int)cap, fp)) {
        trim_text(out);
        ok = out[0] != '\0';
    }
    fclose(fp);
    return ok;
}

lic_bool GetVolumeSerialNumber(char *serial, size_t max_len) {
    if (!serial || max_len == 0) return FALSE;

#if defined(__linux__)
    if (read_first_line("/etc/machine-id", serial, max_len)) return TRUE;
    if (read_first_line("/var/lib/dbus/machine-id", serial, max_len)) return TRUE;
#elif defined(__APPLE__)
    FILE *fp = popen("ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            char *key = strstr(line, "IOPlatformUUID");
            if (!key) continue;
            char *eq = strchr(key, '=');
            if (!eq) continue;
            char *q1 = strchr(eq, '"');
            if (!q1) continue;
            char *q2 = strchr(q1 + 1, '"');
            if (!q2) continue;
            size_t len = (size_t)(q2 - q1 - 1);
            if (len >= max_len) len = max_len - 1;
            memcpy(serial, q1 + 1, len);
            serial[len] = '\0';
            pclose(fp);
            return TRUE;
        }
        pclose(fp);
    }
#endif

    char host[256] = {0};
    if (gethostname(host, sizeof(host) - 1) == 0) {
        trim_text(host);
        if (host[0]) {
            snprintf(serial, max_len, "%s", host);
            return TRUE;
        }
    }
    return FALSE;
}

lic_bool GetComputerNameStr(char *name, size_t max_len) {
    if (!name || max_len == 0) return FALSE;
    if (gethostname(name, max_len - 1) != 0) return FALSE;
    name[max_len - 1] = '\0';
    trim_text(name);
    return name[0] != '\0';
}

lic_bool GetProcessorInfo(char *info, size_t max_len) {
    if (!info || max_len == 0) return FALSE;

#if defined(__linux__)
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "model name", 10) != 0 &&
                strncmp(line, "Hardware", 8) != 0) continue;
            char *colon = strchr(line, ':');
            if (!colon) continue;
            snprintf(info, max_len, "%s", colon + 1);
            fclose(fp);
            trim_text(info);
            if (info[0]) return TRUE;
        }
        fclose(fp);
    }
#elif defined(__APPLE__)
    size_t len = max_len;
    if (sysctlbyname("machdep.cpu.brand_string", info, &len, NULL, 0) == 0) {
        info[max_len - 1] = '\0';
        trim_text(info);
        if (info[0]) return TRUE;
    }
#endif

    struct utsname uts;
    if (uname(&uts) == 0) {
        snprintf(info, max_len, "%s", uts.machine);
        return TRUE;
    }
    return FALSE;
}

lic_bool GetMACAddress(char *mac, size_t max_len) {
    if (!mac || max_len == 0) return FALSE;

    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0) return FALSE;

    char best_name[IF_NAMESIZE] = {0};
    unsigned char best_addr[6] = {0};
    int found = 0;

    for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_name) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;

        unsigned char addr[6] = {0};
        int have = 0;
#if defined(__linux__)
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
            if (sll->sll_halen == 6) {
                memcpy(addr, sll->sll_addr, 6);
                have = 1;
            }
        }
#elif defined(__APPLE__)
        if (ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            if (sdl->sdl_alen == 6) {
                memcpy(addr, LLADDR(sdl), 6);
                have = 1;
            }
        }
#endif
        if (!have) continue;

        int all_zero = 1;
        for (int i = 0; i < 6; i++) {
            if (addr[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) continue;

        if (!found || strcmp(ifa->ifa_name, best_name) < 0) {
            snprintf(best_name, sizeof(best_name), "%s", ifa->ifa_name);
            memcpy(best_addr, addr, 6);
            found = 1;
        }
    }

    freeifaddrs(ifap);
    if (!found) return FALSE;

    snprintf(mac, max_len, "%02X-%02X-%02X-%02X-%02X-%02X",
             best_addr[0], best_addr[1], best_addr[2],
             best_addr[3], best_addr[4], best_addr[5]);
    return TRUE;
}

lic_bool GenerateHardwareFingerprint(char *fingerprint, size_t max_len) {
    if (!fingerprint || max_len == 0) return FALSE;

    char volume[MAX_HW_INFO_LEN] = {0};
    char processor[MAX_HW_INFO_LEN] = {0};
    char mac[MAX_HW_INFO_LEN] = {0};

    if (!GetVolumeSerialNumber(volume, MAX_HW_INFO_LEN)) {
        snprintf(volume, sizeof(volume), "%s", "unknown");
    }
    if (!GetProcessorInfo(processor, MAX_HW_INFO_LEN)) {
        snprintf(processor, sizeof(processor), "%s", "unknown");
    }
    if (!GetMACAddress(mac, MAX_HW_INFO_LEN)) {
        snprintf(mac, sizeof(mac), "%s", "unknown");
    }

    snprintf(fingerprint, max_len, "%s|%s|%s", volume, processor, mac);
    return TRUE;
}
