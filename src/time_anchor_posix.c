#include "time_anchor.h"
#include "key.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ANCHOR_FILENAME "SkyBox.sys_cache"
#define ANCHOR_HIDDEN_FILENAME ".SkyBox.sys_cache"

static void generate_anchor_hmac(uint32_t timestamp, const char *machine_code,
                                 uint8_t *hmac_output) {
    char data[512];
    size_t pub_key_len = 0;
    const uint8_t *pub_key = GetEmbeddedPublicKey(&pub_key_len);
    if (!pub_key || pub_key_len == 0) {
        memset(hmac_output, 0, ANCHOR_HMAC_SIZE);
        return;
    }
    snprintf(data, sizeof(data), "%s|%08X", machine_code, timestamp);
    hmac_sha256(pub_key, pub_key_len, (const uint8_t *)data, strlen(data), hmac_output);
}

static lic_bool build_anchor_path(int which, char *out, size_t cap) {
    if (which == 0) {
        char dir[LICENSE_PATH_MAX];
        if (lic_data_dir(dir, sizeof(dir), "SkySoftware", 1) != 0) return FALSE;
        snprintf(out, cap, "%s/%s", dir, ANCHOR_FILENAME);
        return TRUE;
    }

    char dir[LICENSE_PATH_MAX];
    if (lic_exe_dir(dir, sizeof(dir)) != 0) return FALSE;
    snprintf(out, cap, "%s/%s", dir, ANCHOR_HIDDEN_FILENAME);
    return TRUE;
}

static lic_bool write_anchor_file(int which, uint32_t timestamp, const char *machine_code) {
    char path[LICENSE_PATH_MAX];
    if (!build_anchor_path(which, path, sizeof(path))) return FALSE;

    TimeAnchor anchor;
    anchor.timestamp = timestamp;
    generate_anchor_hmac(timestamp, machine_code, anchor.hmac);

    return lic_write_all(path, &anchor, sizeof(anchor), 1) == 0 ? TRUE : FALSE;
}

static lic_bool read_anchor_file(int which, TimeAnchor *anchor) {
    char path[LICENSE_PATH_MAX];
    if (!build_anchor_path(which, path, sizeof(path))) return FALSE;

    uint8_t *data = NULL;
    size_t len = 0;
    if (lic_read_all(path, &data, &len, sizeof(TimeAnchor) * 4) != 0) return FALSE;

    lic_bool ok = FALSE;
    if (len == sizeof(TimeAnchor)) {
        memcpy(anchor, data, sizeof(TimeAnchor));
        ok = TRUE;
    }
    free(data);
    return ok;
}

static lic_bool verify_anchor_integrity(const TimeAnchor *anchor, const char *machine_code) {
    uint8_t expected[ANCHOR_HMAC_SIZE];
    generate_anchor_hmac(anchor->timestamp, machine_code, expected);
    return memcmp(anchor->hmac, expected, ANCHOR_HMAC_SIZE) == 0 ? TRUE : FALSE;
}

lic_bool InitTimeAnchors(const char *machine_code, uint32_t current_time) {
    if (!machine_code) return FALSE;
    lic_bool a = write_anchor_file(0, current_time, machine_code);
    lic_bool b = write_anchor_file(1, current_time, machine_code);
    return (a || b) ? TRUE : FALSE;
}

lic_bool CheckTimeAnchors(const char *machine_code, uint32_t local_time,
                          uint32_t *max_anchor_time) {
    TimeAnchor anchor;
    uint32_t max_time = 0;
    int valid = 0;

    for (int which = 0; which < 2; which++) {
        if (!read_anchor_file(which, &anchor)) continue;
        if (!verify_anchor_integrity(&anchor, machine_code)) continue;
        valid++;
        if (anchor.timestamp > max_time) max_time = anchor.timestamp;
    }

    if (max_anchor_time) *max_anchor_time = max_time;
    if (valid == 0) return FALSE;

    if (local_time + 86400 < max_time) return FALSE;
    return TRUE;
}

lic_bool UpdateTimeAnchors(const char *machine_code, uint32_t current_time) {
    return InitTimeAnchors(machine_code, current_time);
}
