#ifndef TIME_ANCHOR_H
#define TIME_ANCHOR_H

#include <windows.h>
#include <stdint.h>

#define ANCHOR_HMAC_SIZE 32
#define ANCHOR_DATA_SIZE (sizeof(uint32_t) + ANCHOR_HMAC_SIZE)

typedef struct {
    uint32_t timestamp;
    uint8_t hmac[ANCHOR_HMAC_SIZE];
} TimeAnchor;

BOOL InitTimeAnchors(const char* machine_code, uint32_t current_time);
BOOL CheckTimeAnchors(const char* machine_code, uint32_t local_time, uint32_t* max_anchor_time);
BOOL UpdateTimeAnchors(const char* machine_code, uint32_t current_time);

#endif
