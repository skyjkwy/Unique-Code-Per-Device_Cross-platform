#include "hardware.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iphlpapi.h>
#include <intrin.h>

#pragma comment(lib, "iphlpapi.lib")

BOOL GetVolumeSerialNumber(char *serial, size_t max_len) {
    DWORD serialNumber;

    if (GetVolumeInformation("C:\\", NULL, 0, &serialNumber, NULL, NULL, NULL, 0)) {

        snprintf(serial, max_len, "%08X", serialNumber);
        return TRUE;
    }

    char curDir[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, curDir) > 0 && curDir[0] != '\0') {
        char drive[4] = { curDir[0], ':', '\\', '\0' };
        if (GetVolumeInformation(drive, NULL, 0, &serialNumber, NULL, NULL, NULL, 0)) {
            snprintf(serial, max_len, "%08X", serialNumber);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL GetComputerNameStr(char *name, size_t max_len) {

    if (!name || max_len == 0) return FALSE;

    DWORD size = (DWORD)(max_len - 1);

    if (GetComputerNameA(name, &size)) {

        name[size] = '\0';
        return TRUE;
    }
    return FALSE;
}

BOOL GetProcessorInfo(char *info, size_t max_len) {
    int cpuInfo[4] = {0};
    char cpuBrand[64] = {0};

    __cpuid(cpuInfo, 0);

    int idLength = cpuInfo[0];
    if (idLength > 0) {
        char brand[64] = {0};
        __cpuid((int*)brand, 0);
        __cpuid((int*)(brand + 4), 1);
        __cpuid((int*)(brand + 8), 2);
        __cpuid((int*)(brand + 12), 3);
        __cpuid((int*)(brand + 16), 4);
        __cpuid((int*)(brand + 20), 5);
        __cpuid((int*)(brand + 24), 6);
        __cpuid((int*)(brand + 28), 7);
        __cpuid((int*)(brand + 32), 8);
        __cpuid((int*)(brand + 36), 9);
        __cpuid((int*)(brand + 40), 10);
        __cpuid((int*)(brand + 44), 11);
        __cpuid((int*)(brand + 48), 12);

        if (strlen(brand) > 0) {
            strncpy(info, brand, max_len - 1);
            info[max_len - 1] = '\0';
            return TRUE;
        }
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_INTEL:
            strncpy(info, "Intel", max_len - 1);
            break;
        case PROCESSOR_ARCHITECTURE_AMD64:
            strncpy(info, "AMD64", max_len - 1);
            break;
        default:
            strncpy(info, "Unknown", max_len - 1);
            break;
    }
    info[max_len - 1] = '\0';
    return TRUE;
}

BOOL GetMACAddress(char *mac, size_t max_len) {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    PIP_ADAPTER_INFO pHeapInfo = NULL;

    DWORD ret = GetAdaptersInfo(adapterInfo, &bufLen);
    IP_ADAPTER_INFO *pAdapterList = adapterInfo;

    if (ret == ERROR_BUFFER_OVERFLOW) {
        pHeapInfo = (IP_ADAPTER_INFO *)malloc(bufLen);
        if (pHeapInfo) {
            if (GetAdaptersInfo(pHeapInfo, &bufLen) == ERROR_SUCCESS) {
                pAdapterList = pHeapInfo;
                ret = ERROR_SUCCESS;
            } else {
                free(pHeapInfo);
                pHeapInfo = NULL;
            }
        }
    }

    if (ret == ERROR_SUCCESS) {
        IP_ADAPTER_INFO *pAdapter = pAdapterList;

        while (pAdapter) {

            if (pAdapter->Type != MIB_IF_TYPE_LOOPBACK && pAdapter->AddressLength > 0) {
                char temp[64] = {0};

                for (int i = 0; i < pAdapter->AddressLength; i++) {
                    if (i > 0) {

                        if (strlen(temp) + 1 >= sizeof(temp)) break;
                        strcat(temp, "-");
                    }
                    char hex[4];

                    snprintf(hex, sizeof(hex), "%02X", (unsigned char)pAdapter->Address[i]);

                    if (strlen(temp) + strlen(hex) >= sizeof(temp)) break;
                    strcat(temp, hex);
                }

                strncpy(mac, temp, max_len - 1);
                mac[max_len - 1] = '\0';
                if (pHeapInfo) free(pHeapInfo);
                return TRUE;
            }
            pAdapter = pAdapter->Next;
        }
    }
    if (pHeapInfo) free(pHeapInfo);
    return FALSE;
}

BOOL GenerateHardwareFingerprint(char *fingerprint, size_t max_len) {
    char volume[MAX_HW_INFO_LEN] = {0};
    char processor[MAX_HW_INFO_LEN] = {0};
    char mac[MAX_HW_INFO_LEN] = {0};

    BOOL success = TRUE;

    if (!GetVolumeSerialNumber(volume, MAX_HW_INFO_LEN)) {
        strcpy(volume, "unknown");
        success = FALSE;
    }

    if (!GetProcessorInfo(processor, MAX_HW_INFO_LEN)) {
        strcpy(processor, "unknown");
        success = FALSE;
    }

    if (!GetMACAddress(mac, MAX_HW_INFO_LEN)) {
        strcpy(mac, "unknown");
        success = FALSE;
    }

    snprintf(fingerprint, max_len, "%s|%s|%s", volume, processor, mac);

    return TRUE;
}