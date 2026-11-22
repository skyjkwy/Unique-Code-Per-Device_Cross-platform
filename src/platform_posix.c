#include "platform.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

void lic_secure_zero(void *p, size_t n) {
    if (!p || n == 0) return;
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
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
    const char *msg = strerror(err);
    lic_strcpy(buf, cap, msg ? msg : "unknown error");
    return buf;
}

uint64_t lic_tick_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

void lic_sleep_ms(unsigned ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000);
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

int lic_random_bytes(void *out, size_t len) {
    if (!out || len == 0) return -1;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    unsigned char *p = (unsigned char *)out;
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, p + done, len - done);
        if (n <= 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    close(fd);
    return 0;
}

int lic_exe_path(char *out, size_t cap) {
    if (!out || cap == 0) return -1;
#if defined(__APPLE__)
    uint32_t size = (uint32_t)cap;
    if (_NSGetExecutablePath(out, &size) != 0) return -1;
    char resolved[LICENSE_PATH_MAX];
    if (realpath(out, resolved)) {
        return lic_strcpy(out, cap, resolved);
    }
    return 0;
#else
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0) return -1;
    out[n] = '\0';
    return 0;
#endif
}

int lic_exe_dir(char *out, size_t cap) {
    if (!out || cap == 0) return -1;
    if (lic_exe_path(out, cap) != 0) return -1;
    size_t len = strlen(out);
    while (len > 0) {
        char c = out[len - 1];
        if (c == '/') {
            out[len - 1] = '\0';
            break;
        }
        len--;
    }
    return out[0] ? 0 : -1;
}

int lic_resolve_exe_relative(const char *name, char *out, size_t cap) {
    if (!name || !out || cap == 0) return -1;
    if (name[0] == '/') {
        return lic_strcpy(out, cap, name);
    }
    char dir[LICENSE_PATH_MAX];
    if (lic_exe_dir(dir, sizeof(dir)) != 0) return -1;
    lic_snprintf(out, cap, "%s/%s", dir, name);
    return 0;
}

int lic_mkdir_p(const char *path) {
    if (!path || !path[0]) return -1;
    char tmp[LICENSE_PATH_MAX];
    if (lic_strcpy(tmp, sizeof(tmp), path) != 0) return -1;

    size_t len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/') tmp[--len] = '\0';

    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
    return 0;
}

int lic_data_dir(char *out, size_t cap, const char *subdir, int create) {
    if (!out || cap == 0) return -1;

    const char *base = getenv("XDG_DATA_HOME");
    if (base && base[0]) {
        lic_strcpy(out, cap, base);
    } else {
        const char *home = getenv("HOME");
        if (!home || !home[0]) return -1;
#if defined(__APPLE__)
        lic_snprintf(out, cap, "%s/Library/Application Support", home);
#else
        lic_snprintf(out, cap, "%s/.local/share", home);
#endif
    }

    if (subdir && subdir[0]) {
        size_t l = strlen(out);
        lic_snprintf(out + l, cap - l, "/%s", subdir);
    }

    if (create && lic_mkdir_p(out) != 0) return -1;
    return 0;
}

FILE *lic_fopen(const char *path, const char *mode) {
    if (!path || !mode) return NULL;
    return fopen(path, mode);
}

int lic_remove(const char *path) {
    if (!path) return -1;
    return remove(path) == 0 ? 0 : -1;
}

int lic_file_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int lic_read_all(const char *path, uint8_t **out, size_t *out_len, size_t max_len) {
    if (!path || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;

    FILE *fp = lic_fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long size = ftell(fp);
    if (size <= 0 || (max_len && (uint64_t)size > max_len)) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
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
    return chmod(path, on ? 0600 : 0644) == 0 ? 0 : -1;
}

int lic_file_mtime(const char *path, uint32_t *out_mtime) {
    if (!path || !out_mtime) return -1;
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *out_mtime = (uint32_t)st.st_mtime;
    return 0;
}

static int g_lock_fd = -1;

int lic_lock_file(const char *path) {
    if (!path) return -1;
    lic_unlock_file();
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_SH | LOCK_NB) != 0) {
        close(fd);
        return -1;
    }
    g_lock_fd = fd;
    return 0;
}

void lic_unlock_file(void) {
    if (g_lock_fd >= 0) {
        flock(g_lock_fd, LOCK_UN);
        close(g_lock_fd);
        g_lock_fd = -1;
    }
}

int lic_localtime(uint32_t t, struct tm *out) {
    if (!out) return -1;
    time_t tt = (time_t)t;
    if (!localtime_r(&tt, out)) {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    return 0;
}

void lic_perf_counter(LARGE_INTEGER *out) {
    if (!out) return;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        out->QuadPart = 0;
        return;
    }
    out->QuadPart = (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
}

void lic_perf_frequency(LARGE_INTEGER *out) {
    if (out) out->QuadPart = 1000000000LL;
}

void lic_process_exit(int code) {
    exit(code);
}
