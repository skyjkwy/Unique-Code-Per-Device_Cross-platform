#ifndef NTP_CLIENT_H
#define NTP_CLIENT_H

#include "platform.h"

#include <stdint.h>

#define NTP_TIMEOUT_SECONDS 3

#define NTP_SERVER_COUNT 6

#define NTP_PORT 123

#ifdef __cplusplus
extern "C" {
#endif

lic_bool GetNtpTime(uint32_t *ntp_time);

#ifdef __cplusplus
}
#endif

#endif
