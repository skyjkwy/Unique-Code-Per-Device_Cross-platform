#ifndef HARDWARE_H
#define HARDWARE_H

#include "platform.h"

#define MAX_HW_INFO_LEN 256

#ifdef __cplusplus
extern "C" {
#endif

lic_bool GetVolumeSerialNumber(char *serial, size_t max_len);
lic_bool GetComputerNameStr(char *name, size_t max_len);
lic_bool GetProcessorInfo(char *info, size_t max_len);
lic_bool GetMACAddress(char *mac, size_t max_len);
lic_bool GenerateHardwareFingerprint(char *fingerprint, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif
