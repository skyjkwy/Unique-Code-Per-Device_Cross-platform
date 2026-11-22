#include "license_backup.h"
#include "platform.h"

#include <stdlib.h>
#include <string.h>

#define BACKUP_DIR_NAME  "SkySoftware"
#define BACKUP_FILE_NAME "license-SkyBox.dat"
#define BACKUP_ADS_NAME  L"license-SkyBox"
#define BACKUP_MAGIC     0x534B5431u

static int utf8_to_wide(const char *src, wchar_t *dst, size_t dst_cap) {
    if (!src || !dst || dst_cap == 0) return -1;
    return MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, (int)dst_cap) > 0 ? 0 : -1;
}

static int appdata_path(char *out, size_t cap, int create) {
    char dir[LICENSE_PATH_MAX];
    if (lic_data_dir(dir, sizeof(dir), BACKUP_DIR_NAME, create) != 0) return -1;
    lic_snprintf(out, cap, "%s\\%s", dir, BACKUP_FILE_NAME);
    return 0;
}

static int save_registry(const uint8_t *data, size_t size) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\SkySoftware\\SkyBox\\License",
                        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return -1;
    }

    LONG result = RegSetValueExW(hKey, L"LicenseData", 0, REG_BINARY,
                                 data, (DWORD)size);
    if (result == ERROR_SUCCESS) {
        DWORD flags = 0x4C494331;
        RegSetValueExW(hKey, L"LicenseFlags", 0, REG_DWORD,
                       (const BYTE *)&flags, sizeof(flags));
    }
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS ? 0 : -1;
}

static int load_registry(uint8_t **out_data, size_t *out_size) {
    *out_data = NULL;
    *out_size = 0;

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\SkySoftware\\SkyBox\\License",
                      0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) {
        return -1;
    }

    DWORD flags = 0;
    DWORD flags_size = sizeof(flags);
    if (RegQueryValueExW(hKey, L"LicenseFlags", NULL, NULL,
                         (BYTE *)&flags, &flags_size) != ERROR_SUCCESS ||
        flags != 0x4C494331) {
        RegCloseKey(hKey);
        return -1;
    }

    DWORD data_size = 0;
    if (RegQueryValueExW(hKey, L"LicenseData", NULL, NULL, NULL, &data_size) != ERROR_SUCCESS ||
        data_size == 0 || data_size > 10 * 1024 * 1024) {
        RegCloseKey(hKey);
        return -1;
    }

    uint8_t *data = (uint8_t *)malloc(data_size);
    if (!data) {
        RegCloseKey(hKey);
        return -1;
    }

    if (RegQueryValueExW(hKey, L"LicenseData", NULL, NULL, data, &data_size) != ERROR_SUCCESS) {
        free(data);
        RegCloseKey(hKey);
        return -1;
    }

    RegCloseKey(hKey);
    *out_data = data;
    *out_size = data_size;
    return 0;
}

static int appdata_save(const uint8_t *data, size_t size) {
    char path[LICENSE_PATH_MAX];
    if (appdata_path(path, sizeof(path), 1) != 0) return -1;

    size_t total = 8 + size;
    uint8_t *buffer = (uint8_t *)malloc(total);
    if (!buffer) return -1;

    uint32_t magic = BACKUP_MAGIC;
    uint32_t size32 = (uint32_t)size;
    memcpy(buffer, &magic, 4);
    memcpy(buffer + 4, &size32, 4);
    memcpy(buffer + 8, data, size);

    int rc = lic_write_all(path, buffer, total, 1);
    free(buffer);
    return rc;
}

static int appdata_load(uint8_t **out_data, size_t *out_size) {
    *out_data = NULL;
    *out_size = 0;

    char path[LICENSE_PATH_MAX];
    if (appdata_path(path, sizeof(path), 0) != 0) return -1;

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (lic_read_all(path, &raw, &raw_len, 10 * 1024 * 1024) != 0) return -1;
    if (raw_len < 8) {
        free(raw);
        return -1;
    }

    uint32_t magic = 0;
    uint32_t data_size = 0;
    memcpy(&magic, raw, 4);
    memcpy(&data_size, raw + 4, 4);
    if (magic != BACKUP_MAGIC || data_size == 0 ||
        (uint64_t)data_size + 8 != raw_len) {
        free(raw);
        return -1;
    }

    uint8_t *data = (uint8_t *)malloc(data_size);
    if (!data) {
        free(raw);
        return -1;
    }
    memcpy(data, raw + 8, data_size);
    free(raw);

    *out_data = data;
    *out_size = data_size;
    return 0;
}

static int ads_save(const uint8_t *data, size_t size, const char *primary_path) {
    if (!primary_path) return -1;
    wchar_t wpath[LICENSE_PATH_MAX];
    wchar_t wads[LICENSE_PATH_MAX + 64];
    if (utf8_to_wide(primary_path, wpath, LICENSE_PATH_MAX) != 0) return -1;
    _snwprintf_s(wads, sizeof(wads) / sizeof(wads[0]), _TRUNCATE, L"%ls:%ls",
                 wpath, BACKUP_ADS_NAME);

    HANDLE hFile = CreateFileW(wads, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, data, (DWORD)size, &written, NULL);
    CloseHandle(hFile);
    return (ok && written == size) ? 0 : -1;
}

static int ads_load(uint8_t **out_data, size_t *out_size, const char *primary_path) {
    *out_data = NULL;
    *out_size = 0;
    if (!primary_path) return -1;

    wchar_t wpath[LICENSE_PATH_MAX];
    wchar_t wads[LICENSE_PATH_MAX + 64];
    if (utf8_to_wide(primary_path, wpath, LICENSE_PATH_MAX) != 0) return -1;
    _snwprintf_s(wads, sizeof(wads) / sizeof(wads[0]), _TRUNCATE, L"%ls:%ls",
                 wpath, BACKUP_ADS_NAME);

    HANDLE hFile = CreateFileW(wads, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    LARGE_INTEGER li;
    if (!GetFileSizeEx(hFile, &li) || li.QuadPart <= 0 || li.QuadPart > 10 * 1024 * 1024) {
        CloseHandle(hFile);
        return -1;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)li.QuadPart);
    if (!data) {
        CloseHandle(hFile);
        return -1;
    }

    DWORD read = 0;
    BOOL ok = ReadFile(hFile, data, (DWORD)li.QuadPart, &read, NULL);
    CloseHandle(hFile);
    if (!ok || read != (DWORD)li.QuadPart) {
        free(data);
        return -1;
    }

    *out_data = data;
    *out_size = (size_t)li.QuadPart;
    return 0;
}

int LicenseBackup_Init(void) {
    char path[LICENSE_PATH_MAX];
    return appdata_path(path, sizeof(path), 1) == 0 ? 0 : -1;
}

int LicenseBackup_Save(const uint8_t *data, size_t size, const char *primary_path) {
    if (!data || size == 0) return -1;

    int ok = 0;
    if (save_registry(data, size) == 0) ok = 1;
    if (appdata_save(data, size) == 0) ok = 1;
    if (ads_save(data, size, primary_path) == 0) ok = 1;
    return ok ? 0 : -1;
}

int LicenseBackup_Load(const char *primary_path, uint8_t **data, size_t *size, char *source, int *tampered) {
    if (!data || !size || !source || !tampered) return -1;
    *data = NULL;
    *size = 0;
    *source = 'N';
    *tampered = 0;

    if (load_registry(data, size) == 0 && *size > 0) {
        *source = 'R';
        return 0;
    }
    if (appdata_load(data, size) == 0 && *size > 0) {
        *source = 'D';
        return 0;
    }
    if (ads_load(data, size, primary_path) == 0 && *size > 0) {
        *source = 'A';
        return 0;
    }

    *tampered = 1;
    return -1;
}

int LicenseBackup_Clear(const char *primary_path) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\SkySoftware\\SkyBox\\License",
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"LicenseData");
        RegDeleteValueW(hKey, L"LicenseFlags");
        RegCloseKey(hKey);
    }
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\SkySoftware\\SkyBox\\License");

    char path[LICENSE_PATH_MAX];
    if (appdata_path(path, sizeof(path), 0) == 0) {
        lic_remove(path);
    }

    if (primary_path) {
        wchar_t wpath[LICENSE_PATH_MAX];
        wchar_t wads[LICENSE_PATH_MAX + 64];
        if (utf8_to_wide(primary_path, wpath, LICENSE_PATH_MAX) == 0) {
            _snwprintf_s(wads, sizeof(wads) / sizeof(wads[0]), _TRUNCATE, L"%ls:%ls",
                         wpath, BACKUP_ADS_NAME);
            DeleteFileW(wads);
        }
    }

    return 0;
}
