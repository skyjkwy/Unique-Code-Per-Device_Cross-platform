#ifndef HARDWARE_H
#define HARDWARE_H

#include <windows.h>

#define MAX_HW_INFO_LEN 256

BOOL GetVolumeSerialNumber(char *serial, size_t max_len);
BOOL GetComputerNameStr(char *name, size_t max_len);
BOOL GetProcessorInfo(char *info, size_t max_len);
BOOL GetMACAddress(char *mac, size_t max_len);
BOOL GenerateHardwareFingerprint(char *fingerprint, size_t max_len);

#endif
