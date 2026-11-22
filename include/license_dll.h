#ifndef LICENSE_DLL_H
#define LICENSE_DLL_H

#include "platform.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
    #if defined(LICENSE_DLL_EXPORTS)
        #define LICENSE_API __declspec(dllexport)
    #elif defined(LICENSE_STATIC)
        #define LICENSE_API
    #else
        #define LICENSE_API __declspec(dllimport)
    #endif
#else
    #define LICENSE_API __attribute__((visibility("default")))
#endif

#define LICENSE_OK 0

#define LICENSE_ERROR -1

#define LICENSE_NOT_INITIALIZED -2

#define LICENSE_INVALID_PARAM -3

#define LICENSE_NO_MEMORY -4

#define LICENSE_STATUS_NOT_ACTIVATED 0

#define LICENSE_STATUS_ACTIVATED 1

#define LICENSE_STATUS_PERMANENT 2

#define LICENSE_STATUS_EXPIRED 3

typedef struct {
    int status;
    char username[64];
    char email[64];
    char machine_code[65];
    uint32_t expire_time;
    uint32_t remaining_days;
    uint32_t current_time;
    int source;
} LicenseInfo;

typedef struct {
    int show_activation_dialog;
    int auto_check_interval;
    int ntp_timeout;
    int ntp_retry_count;
} LicenseConfig;

LICENSE_API void License_SetNtpBase(uint32_t ntp_base_time,
                                    LARGE_INTEGER perf_counter_base,
                                    LARGE_INTEGER perf_frequency);

LICENSE_API int License_Init(const LicenseConfig* config);

LICENSE_API void License_Shutdown(void);

LICENSE_API lic_bool License_IsActivated(void);

LICENSE_API int License_GetSessionKey(unsigned char* out_key, int buf_size);

LICENSE_API int License_GetInfo(LicenseInfo* info);

LICENSE_API int License_GetMachineCode(char* machine_code, int buf_size);

LICENSE_API int License_GetObfuscatedMachineCode(char* obfuscated_out, int buf_size);

LICENSE_API int License_NormalizeMachineCode(const char* input_machine_code, char* normalized_out, int buf_size);

LICENSE_API lic_bool License_Verify(void);

LICENSE_API int License_ShowActivationDialog(HWND parent_hwnd);

LICENSE_API int License_Activate(const char* activation_code, const char* username, const char* email);

LICENSE_API int License_GetLastErrorMsg(char* buffer, int buf_size);

LICENSE_API int License_Clear(void);

LICENSE_API int License_GenerateCode(const char* machine_code, uint64_t total_seconds,
                                     const char* username, const char* email,
                                     char* activation_code);

#define LICENSE_SOURCE_NONE     0
#define LICENSE_SOURCE_OFFLINE  1
#define LICENSE_SOURCE_ONLINE   2

LICENSE_API int License_ImportOnline(const char* activation_code, const char* username,
                                     const char* email, uint32_t expire_time,
                                     uint32_t server_time);

LICENSE_API int License_GetOnlineCode(char* code, int buf_size, uint32_t* last_verify);

LICENSE_API int License_GetSource(void);

LICENSE_API int License_ClearOnline(void);

#ifdef __cplusplus
}
#endif

#endif
