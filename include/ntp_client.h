#ifndef NTP_CLIENT_H
#define NTP_CLIENT_H

#include <windows.h>
#include <stdint.h>

#define NTP_TIMEOUT_SECONDS 3

#define NTP_SERVER_COUNT 6

#define NTP_PORT 123

BOOL GetNtpTime(uint32_t *ntp_time);

#endif
