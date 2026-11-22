#include "platform.h"

#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <wchar.h>

#pragma comment(lib, "bcrypt.lib")

static int utf8_to_wide(const char *src, wchar_t *dst, size_t dst_cap) {
    if (!src || !dst || dst_cap == 0) return -1;
    int n = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, (int)dst_cap);
    return n > 0 ? 0 : -1;
}

static int wide_to_utf8(const wchar_t *src, char *dst, size_t dst_cap) {
    if (!src || !dst || dst_cap == 0) return -1;
    int n = WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)dst_cap, NULL, NULL);
    return n > 0 ? 0 : -1;
}

void lic_secure_zero(void *p, size_t n) {
    if (p) SecureZeroMemory(p, n);
}

int lic_strcpy(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return -1;
    if (!src) {
        dst[0] = '\0';
        return 0;
    }
    size_t i = 0;
    for (; i + 1 < cap && src[i]; i++) dst[i] = src[i];
    dst[i] = '\0';
    return src[i] == '\0' ? 0 : -1;
}

int lic_vsnprintf(char *dst, size_t cap, const char *fmt, va_list ap) {
    if (!dst || cap == 0) return -1;
    return vsnprintf(dst, cap, fmt, ap);
}

int lic_snprintf(char *dst, size_t cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = lic_vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    return n;
}

const char *lic_strerror(int err, char *buf, size_t cap) {
    if (!buf || cap == 0) return "";
    if (strerror_s(buf, cap, err) != 0) {
        lic_strcpy(buf, cap, "unknown error");
    }
    return buf;
}

uint64_t lic_tick_ms(void) {
    return (uint64_t)GetTickCount64();
}

void lic_sleep_ms(unsigned ms) {
    Sleep((DWORD)ms);
}

int lic_random_bytes(void *out, size_t len) {
    if (!out || len == 0) return -1;
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)out, (ULONG)len,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == 0 ? 0 : -1;
}

int lic_exe_path(char *out, size_t cap) {
    if (!out || cap == 0) return -1;
    wchar_t wpath[LICENSE_PATH_MAX];
    DWORD n = GetModuleFileNameW(NULL, wpath, (DWORD)(sizeof(wpath) / sizeof(wpath[0])));
    if (n == 0 || n >= (DWORD)(sizeof(wpath) / sizeof(wpath[0]))) return -1;
    return wide_to_utf8(wpath, out, cap);
}

int lic_exe_dir(char *out, size_t cap) {
    if (!out || cap == 0) return -1;
    if (lic_exe_path(out, cap) != 0) return -1;
    size_t len = strlen(out);
    while (len > 0) {
        char c = out[len - 1];
        if (c == '\\' || c == '/') {
            out[len - 1] = '\0';
            break;
        }
        len--;
    }
    return out[0] ? 0 : -1;
}

static int is_absolute_path(const char *path) {
    if (!path || !path[0]) return 0;
    if (path[0] == '\\' || path[0] == '/') return 1;
    return ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'))
           && path[1] == ':' && (path[2] == '\\' || path[2] == '/');
}

int lic_resolve_exe_relative(const char *name, char *out, size_t cap) {
    if (!name || !out || cap == 0) return -1;
    if (is_absolute_path(name)) {
        return lic_strcpy(out, cap, name);
    }
    char dir[LICENSE_PATH_MAX];
    if (lic_exe_dir(dir, sizeof(dir)) != 0) return -1;
    lic_snprintf(out, cap, "%s\\%s", dir, name);
    return 0;
}

int lic_mkdir_p(const char *path) {
    if (!path || !path[0]) return -1;
    wchar_t wpath[LICENSE_PATH_MAX];
    if (utf8_to_wide(path, wpath, LICENSE_PATH_MAX) != 0) return -1;

    size_t len = wcslen(wpath);
    for (size_t i = 1; i < len; i++) {
        if (wpath[i] == L'\\' || wpath[i] == L'/') {
            wchar_t saved = wpath[i];
            wpath[i] = L'\0';
            CreateDirectoryW(wpath, NULL);
            wpath[i] = saved;
        }
    }
    if (!CreateDirectoryW(wpath, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) return -1;
    }
    return 0;
}

int lic_data_dir(char *out, size_t cap, const char *subdir, int create) {
    if (!out || cap == 0) return -1;

    wchar_t wbase[LICENSE_PATH_MAX];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", wbase,
                                      (DWORD)(sizeof(wbase) / sizeof(wbase[0])));
    if (n == 0 || n >= (DWORD)(sizeof(wbase) / sizeof(wbase[0]))) {
        wchar_t wprofile[LICENSE_PATH_MAX];
        DWORD pn = GetEnvironmentVariableW(L"USERPROFILE", wprofile,
                                           (DWORD)(sizeof(wprofile) / sizeof(wprofile[0])));
        if (pn == 0 || pn >= (DWORD)(sizeof(wprofile) / sizeof(wprofile[0]))) return -1;
        out[0] = '\0';
        if (wide_to_utf8(wprofile, out, cap) != 0) return -1;
        size_t l = strlen(out);
        lic_snprintf(out + l, cap - l, "%s", "\\AppData\\Local");
    } else {
        if (wide_to_utf8(wbase, out, cap) != 0) return -1;
    }

    if (subdir && subdir[0]) {
        size_t l = strlen(out);
        lic_snprintf(out + l, cap - l, "\\%s", subdir);
    }

    if (create && lic_mkdir_p(out) != 0) return -1;
    return 0;
}

FILE *lic_fopen(const char *path, const char *mode) {
    if (!path || !mode) return NULL;
    wchar_t wpath[LICENSE_PATH_MAX];
    wchar_t wmode[16];
    if (utf8_to_wide(path, wpath, LICENSE_PATH_MAX) != 0) return NULL;
    if (utf8_to_wide(mode, wmode, sizeof(wmode) / sizeof(wmode[0])) != 0) return NULL;
    return _wfopen(wpath, wmode);
}

int lic_remove(const char *path) {
    if (!path) return -1;
    wchar_t wpath[LICENSE_PATH_MAX];
    if (utf8_to_wide(path, wpath, LICENSE_PATH_MAX) != 0) return -1;
    return _wremove(wpath) == 0 ? 0 : -1;
}

int lic_file_exists(const char *path) {
    if (!path) return 0;
    wchar_t wpath[LICENSE_PATH_MAX];
    if (utf8_to_wide(path, wpath, LICENSE_PATH_MAX) != 0) return 0;
    DWORD attrs = GetFileAttributesW(wpath);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

int lic_read_all(const char *path, uint8_t **out, size_t *out_len, size_t max_len) {
    if (!path || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;

    FILE *fp = lic_fopen(path, "rb");
    if (!fp) return -1;

    if (_fseeki64(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    __int64 size = _ftelli64(fp);
    if (size <= 0 || (max_len && (uint64_t)size > max_len)) {
        fclose(fp);
        return -1;
    }
    if (_fseeki64(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)size);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    size_t rd = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    if (rd != (size_t)size) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = (size_t)size;
    return 0;
}

int lic_write_all(const char *path, const void *data, size_t len, int hidden) {
    if (!path || (!data && len)) return -1;
    FILE *fp = lic_fopen(path, "wb");
    if (!fp) return -1;
    size_t wr = len ? fwrite(data, 1, len, fp) : 0;
    int flush_ok = fflush(fp) == 0;
    int close_ok = fclose(fp) == 0;
    if (wr != len || !flush_ok || !close_ok) return -1;
    if (hidden) lic_set_hidden(path, 1);
    return 0;
}

int lic_set_hidden(const char *path, int on) {
    if (!path) return -1;
    wchar_t wpath[LICENSE_PATH_MAX];
    if (utf8_to_wide(path, wpath, LICENSE_PATH_MAX) != 0) return -1;
    DWORD attrs = GetFileAttributesW(wpath);
    if (attrs == INVALID_FILE_ATTRIBUTES) return -1;
    DWORD flags = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    DWORD next = on ? (attrs | flags)
                    : (attrs & ~(flags | FILE_ATTRIBUTE_READONLY));
    if (next == 0) next = FILE_ATTRIBUTE_NORMAL;
    return SetFileAttributesW(wpath, next) ? 0 : -1;
}

int lic_file_mtime(const char *path, uint32_t *out_mtime) {
    if (!path || !out_mtime) return -1;
    wchar_t wpath[LICENSE_PATH_MAX];
    struct _stat64 st;
    if (utf8_to_wide(path, wpath, LICENSE_PATH_MAX) != 0) return -1;
    if (_wstat64(wpath, &st) != 0) return -1;
    *out_mtime = (uint32_t)st.st_mtime;
    return 0;
}

static HANDLE g_lock_handle = INVALID_HANDLE_VALUE;

int lic_lock_file(const char *path) {
    if (!path) return -1;
    lic_unlock_file();

    wchar_t wpath[LICENSE_PATH_MAX];
    if (utf8_to_wide(path, wpath, LICENSE_PATH_MAX) != 0) return -1;

    HANDLE h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    g_lock_handle = h;
    return 0;
}

void lic_unlock_file(void) {
    if (g_lock_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_lock_handle);
        g_lock_handle = INVALID_HANDLE_VALUE;
    }
}

int lic_localtime(uint32_t t, struct tm *out) {
    if (!out) return -1;
    time_t tt = (time_t)t;
    if (localtime_s(out, &tt) != 0) {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    return 0;
}

void lic_perf_counter(LARGE_INTEGER *out) {
    if (out) QueryPerformanceCounter(out);
}

void lic_perf_frequency(LARGE_INTEGER *out) {
    if (out) QueryPerformanceFrequency(out);
}

void lic_process_exit(int code) {
    ExitProcess((UINT)code);
}
