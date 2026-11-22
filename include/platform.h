#ifndef LICENSE_PLATFORM_H
#define LICENSE_PLATFORM_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
typedef int lic_bool;
#else
typedef int lic_bool;
typedef void *HWND;
typedef struct {
    long long QuadPart;
} LARGE_INTEGER;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#endif

#ifndef LICENSE_PATH_MAX
#define LICENSE_PATH_MAX 4096
#endif

#ifdef __cplusplus
extern "C" {
#endif

void lic_secure_zero(void *p, size_t n);
int lic_strcpy(char *dst, size_t cap, const char *src);
int lic_vsnprintf(char *dst, size_t cap, const char *fmt, va_list ap);
int lic_snprintf(char *dst, size_t cap, const char *fmt, ...);
const char *lic_strerror(int err, char *buf, size_t cap);

uint64_t lic_tick_ms(void);
void lic_sleep_ms(unsigned ms);
int lic_random_bytes(void *out, size_t len);

int lic_exe_path(char *out, size_t cap);
int lic_exe_dir(char *out, size_t cap);
int lic_resolve_exe_relative(const char *name, char *out, size_t cap);
int lic_data_dir(char *out, size_t cap, const char *subdir, int create);
int lic_mkdir_p(const char *path);

FILE *lic_fopen(const char *path, const char *mode);
int lic_remove(const char *path);
int lic_file_exists(const char *path);
int lic_read_all(const char *path, uint8_t **out, size_t *len, size_t max_len);
int lic_write_all(const char *path, const void *data, size_t len, int hidden);
int lic_set_hidden(const char *path, int on);
int lic_file_mtime(const char *path, uint32_t *out_mtime);

int lic_lock_file(const char *path);
void lic_unlock_file(void);

int lic_localtime(uint32_t t, struct tm *out);
void lic_perf_counter(LARGE_INTEGER *out);
void lic_perf_frequency(LARGE_INTEGER *out);
void lic_process_exit(int code);

#ifdef __cplusplus
}
#endif

#ifndef _WIN32
#define SecureZeroMemory(p, n) lic_secure_zero((p), (n))
#endif

#endif
