#include "time_anchor.h"
#include "license.h"
#include "sha256.h"
#include "key.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LICENSE_FILE "license-SkyBox.dat"

#define ANCHOR_STREAM_NAME ":TimeAnchor-SkyBox"

#define ANCHOR_FILENAME "SkyBox.sys_cache"

static void compute_hmac(const char* data, size_t data_len, uint8_t* key, size_t key_len, uint8_t* hmac_output) {
    const size_t BSIZE = 64;
    uint8_t k_pad[64];
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    uint8_t outer_hash[SHA256_DIGEST_SIZE];
    uint8_t key_derived[SHA256_DIGEST_SIZE];

    if (key_len > BSIZE) {
        sha256_hash(key, key_len, key_derived);
        key = key_derived;
        key_len = SHA256_DIGEST_SIZE;
    }

    memset(k_pad, 0, BSIZE);
    memcpy(k_pad, key, key_len);

    for (size_t i = 0; i < BSIZE; i++) {
        k_ipad[i] = k_pad[i] ^ 0x36;
        k_opad[i] = k_pad[i] ^ 0x5C;
    }

    if (data_len > 1024 * 1024) return;
    uint8_t* inner_data = (uint8_t*)malloc(BSIZE + data_len);

    if (!inner_data) { memset(hmac_output, 0, ANCHOR_HMAC_SIZE); return; }

    memcpy(inner_data, k_ipad, BSIZE);
    memcpy(inner_data + BSIZE, data, data_len);
    sha256_hash(inner_data, BSIZE + data_len, inner_hash);
    free(inner_data);

    uint8_t outer_data[64 + SHA256_DIGEST_SIZE];
    memcpy(outer_data, k_opad, BSIZE);
    memcpy(outer_data + BSIZE, inner_hash, SHA256_DIGEST_SIZE);
    sha256_hash(outer_data, BSIZE + SHA256_DIGEST_SIZE, outer_hash);

    memcpy(hmac_output, outer_hash, SHA256_DIGEST_SIZE);
}

static void generate_anchor_hmac(uint32_t timestamp, const char* machine_code, uint8_t* hmac_output) {
    char data[512];
    size_t pub_key_len = 0;
    const uint8_t* pub_key = GetEmbeddedPublicKey(&pub_key_len);
    if (!pub_key || pub_key_len == 0) return;
    snprintf(data, sizeof(data), "%s|%08X", machine_code, timestamp);
    compute_hmac(data, strlen(data), (uint8_t*)pub_key, pub_key_len, hmac_output);
}

static BOOL write_ads_anchor(const char* filename, const char* stream_name, uint32_t timestamp, const char* machine_code) {
    char ads_path[MAX_PATH];

    snprintf(ads_path, sizeof(ads_path), "%s%s", filename, stream_name);

    FILE* check_fp = fopen(filename, "rb");
    if (check_fp) {
        fclose(check_fp);
    } else {
        FILE* create_fp = fopen(filename, "wb");
        if (create_fp) fclose(create_fp);

    }

    FILE* fp = fopen(ads_path, "wb");
    if (!fp) return FALSE;

    TimeAnchor anchor;
    anchor.timestamp = timestamp;
    generate_anchor_hmac(timestamp, machine_code, anchor.hmac);

    fwrite(&anchor, sizeof(TimeAnchor), 1, fp);
    fclose(fp);

    return TRUE;
}

static BOOL read_ads_anchor(const char* filename, const char* stream_name, TimeAnchor* anchor) {
    char ads_path[MAX_PATH];

    snprintf(ads_path, sizeof(ads_path), "%s%s", filename, stream_name);

    FILE* fp = fopen(ads_path, "rb");
    if (!fp) return FALSE;

    size_t read = fread(anchor, sizeof(TimeAnchor), 1, fp);
    fclose(fp);

    return (read == 1);
}

static BOOL get_appdata_path(char* path, size_t path_size) {
    const char* appdata = getenv("APPDATA");
    if (!appdata) {

        const char* home = getenv("USERPROFILE");
        if (!home) return FALSE;
        snprintf(path, path_size, "%s\\AppData\\Roaming", home);
    } else {
        snprintf(path, path_size, "%s", appdata);
    }
    return TRUE;
}

static BOOL write_hidden_file_anchor(uint32_t timestamp, const char* machine_code) {
    char dir_path[MAX_PATH];
    char file_path[MAX_PATH];

    if (!get_appdata_path(dir_path, sizeof(dir_path))) return FALSE;

    CreateDirectory(dir_path, NULL);

    snprintf(file_path, sizeof(file_path), "%s\\%s", dir_path, ANCHOR_FILENAME);

    FILE* fp = fopen(file_path, "wb");
    if (!fp) return FALSE;

    TimeAnchor anchor;
    anchor.timestamp = timestamp;
    generate_anchor_hmac(timestamp, machine_code, anchor.hmac);

    fwrite(&anchor, sizeof(TimeAnchor), 1, fp);
    fclose(fp);

    SetFileAttributesA(file_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    return TRUE;
}

static BOOL read_hidden_file_anchor(TimeAnchor* anchor) {
    char dir_path[MAX_PATH];
    char file_path[MAX_PATH];

    if (!get_appdata_path(dir_path, sizeof(dir_path))) return FALSE;

    snprintf(file_path, sizeof(file_path), "%s\\%s", dir_path, ANCHOR_FILENAME);

    FILE* fp = fopen(file_path, "rb");
    if (!fp) return FALSE;

    size_t read = fread(anchor, sizeof(TimeAnchor), 1, fp);
    fclose(fp);

    return (read == 1);
}

static BOOL verify_anchor_integrity(const TimeAnchor* anchor, const char* machine_code) {
    uint8_t expected_hmac[ANCHOR_HMAC_SIZE];

    generate_anchor_hmac(anchor->timestamp, machine_code, expected_hmac);

    return (memcmp(anchor->hmac, expected_hmac, ANCHOR_HMAC_SIZE) == 0);
}

static BOOL get_file_mtime_anchor(uint32_t* mtime) {
    FILETIME ft;
    SYSTEMTIME st;

    HANDLE hFile = CreateFileA(LICENSE_FILE, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    if (!GetFileTime(hFile, NULL, NULL, &ft)) {
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    if (!FileTimeToLocalFileTime(&ft, &ft)) return FALSE;

    if (!FileTimeToSystemTime(&ft, &st)) return FALSE;

    struct tm timeinfo;
    timeinfo.tm_year = st.wYear - 1900;
    timeinfo.tm_mon = st.wMonth - 1;
    timeinfo.tm_mday = st.wDay;
    timeinfo.tm_hour = st.wHour;
    timeinfo.tm_min = st.wMinute;
    timeinfo.tm_sec = st.wSecond;
    timeinfo.tm_isdst = -1;

    time_t t = mktime(&timeinfo);

    if (t == (time_t)-1) return FALSE;
    *mtime = (uint32_t)t;
    return TRUE;
}

BOOL InitTimeAnchors(const char* machine_code, uint32_t current_time) {
    BOOL success = TRUE;

    if (!write_ads_anchor(LICENSE_FILE, ANCHOR_STREAM_NAME, current_time, machine_code)) {
        success = FALSE;
    }

    if (!write_hidden_file_anchor(current_time, machine_code)) {
        success = FALSE;
    }

    return success;
}

BOOL CheckTimeAnchors(const char* machine_code, uint32_t local_time, uint32_t* max_anchor_time) {
    TimeAnchor ads_anchor, file_anchor;
    uint32_t max_time = 0;
    int valid_anchors = 0;

    if (read_ads_anchor(LICENSE_FILE, ANCHOR_STREAM_NAME, &ads_anchor)) {
        if (verify_anchor_integrity(&ads_anchor, machine_code)) {
            valid_anchors++;
            if (ads_anchor.timestamp > max_time) max_time = ads_anchor.timestamp;
        }
    }

    if (read_hidden_file_anchor(&file_anchor)) {
        if (verify_anchor_integrity(&file_anchor, machine_code)) {
            valid_anchors++;
            if (file_anchor.timestamp > max_time) max_time = file_anchor.timestamp;
        }
    }

    if (valid_anchors == 0) {
        if (max_anchor_time) *max_anchor_time = 0;
        return FALSE;
    }

    if (local_time + 86400 < max_time) {
        if (max_anchor_time) *max_anchor_time = max_time;
        return FALSE;
    }

    if (max_anchor_time) *max_anchor_time = max_time;
    return TRUE;
}

BOOL UpdateTimeAnchors(const char* machine_code, uint32_t current_time) {
    return InitTimeAnchors(machine_code, current_time);
}