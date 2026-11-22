#ifndef LICENSE_DLL_EXPORTS
#define LICENSE_DLL_EXPORTS
#endif

#include "license_dll.h"
#include "license.h"
#include "ntp_client.h"
#include "anti_debug.h"
#include "sha256.h"
#include "dll_hash.h"

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

extern const char* GetLastLicenseFileIOError(void);

static BOOL g_initialized = FALSE;

static LicenseConfig g_default_config = {
    1,
    300,
    3000,
    3
};

static LicenseConfig g_config;

static char g_machine_code[MACHINE_CODE_LEN] = {0};

static BOOL g_is_activated = FALSE;

static uint32_t g_expire_time = 0;

static char g_username[USERNAME_LEN] = {0};

static char g_email[EMAIL_LEN] = {0};

static int g_license_source = LICENSE_SOURCE_NONE;

static uint32_t g_verified_time = 0;

static uint32_t g_ntp_base_time = 0;
static LARGE_INTEGER g_perf_counter_base;
static LARGE_INTEGER g_perf_frequency;
static BOOL g_ntp_base_ready = FALSE;

static HANDLE g_auto_check_timer = NULL;

static char g_lastErrorMsg[512] = {0};

static void SetLastErrorUtf8(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(g_lastErrorMsg, sizeof(g_lastErrorMsg), _TRUNCATE, fmt, ap);
    va_end(ap);
}

static uint32_t DllGetTrustedTime(void) {
    if (g_ntp_base_ready) {
        LARGE_INTEGER current_counter;
        QueryPerformanceCounter(&current_counter);
        __int64 elapsed_seconds = (current_counter.QuadPart - g_perf_counter_base.QuadPart)
                                  / g_perf_frequency.QuadPart;
        return (uint32_t)((__int64)g_ntp_base_time + elapsed_seconds);
    }
    return g_verified_time;
}

static void RecordNtpBase(uint32_t ntp_time) {
    g_ntp_base_time = ntp_time;
    QueryPerformanceCounter(&g_perf_counter_base);
    QueryPerformanceFrequency(&g_perf_frequency);
    g_ntp_base_ready = TRUE;
}

LICENSE_API void License_SetNtpBase(uint32_t ntp_base_time,
                                    LARGE_INTEGER perf_counter_base,
                                    LARGE_INTEGER perf_frequency) {
    g_ntp_base_time = ntp_base_time;
    g_perf_counter_base = perf_counter_base;
    g_perf_frequency = perf_frequency;
    g_ntp_base_ready = TRUE;
}

#define SKY_FEATURE_TOKEN_LABEL  "SkyBox-Premium-Token-v1"
#define SKY_FEATURE_TOKEN_FILE   "feature.tok"
#define SKY_SESSION_KEY_TTL_MS   30000

static uint8_t g_session_key[SHA256_DIGEST_SIZE];
static BOOL g_session_key_valid = FALSE;
static DWORD g_session_key_tick = 0;

static const uint8_t SKY_KDF_SALT[SHA256_DIGEST_SIZE] = {
    0x53,0x6b,0x79,0x42,0x6f,0x78,0x2d,0x53,
    0x65,0x73,0x73,0x69,0x6f,0x6e,0x2d,0x4b,
    0x44,0x46,0x2d,0x76,0x31,0x2d,0x41,0x39,
    0x33,0x46,0x37,0x43,0x31,0x45,0x35,0x44
};

static BOOL GetFeatureTokenPath(char *out_path, size_t out_size) {
    char base[MAX_PATH] = {0};
    if (!GetEnvironmentVariableA("LOCALAPPDATA", base, (DWORD)sizeof(base)) || !base[0]) {
        return FALSE;
    }
    _snprintf_s(out_path, out_size, _TRUNCATE, "%s\\SkySoftware\\" SKY_FEATURE_TOKEN_FILE, base);
    return out_path[0] != '\0';
}

static BOOL DeriveSessionKey(uint8_t out_key[SHA256_DIGEST_SIZE]) {
    if (!g_machine_code[0]) return FALSE;

    uint32_t disk_expire = 0;
    char disk_user[USERNAME_LEN] = {0};
    char disk_email[EMAIL_LEN] = {0};
    if (!LoadActivationStatus(g_machine_code, &disk_expire, disk_user, disk_email)) {
        return FALSE;
    }

    uint32_t now = DllGetTrustedTime();
    if (disk_expire != 0 && disk_expire < now) return FALSE;

    char online_code[24] = {0};
    uint32_t online_last = 0;
    BOOL has_online = LoadOnlineAuth(online_code, sizeof(online_code), &online_last)
                      && online_code[0] != '\0';

    char material[320] = {0};
    _snprintf_s(material, sizeof(material), _TRUNCATE, "%s|%08x|%s|%s",
                g_machine_code, (unsigned int)disk_expire,
                has_online ? online_code : "-", disk_user);

    uint8_t ikm[SHA256_DIGEST_SIZE];
    sha256_hash((const uint8_t *)material, strlen(material), ikm);
    hmac_sha256(SKY_KDF_SALT, sizeof(SKY_KDF_SALT), ikm, sizeof(ikm), out_key);

    SecureZeroMemory(material, sizeof(material));
    SecureZeroMemory(ikm, sizeof(ikm));
    SecureZeroMemory(online_code, sizeof(online_code));
    return TRUE;
}

static void RefreshFeatureToken(void) {
    uint8_t key[SHA256_DIGEST_SIZE];
    char path[MAX_PATH] = {0};
    char hex[SHA256_DIGEST_SIZE * 2 + 1] = {0};

    g_session_key_valid = FALSE;
    memset(g_session_key, 0, sizeof(g_session_key));

    if (!GetFeatureTokenPath(path, sizeof(path))) return;

    if (!DeriveSessionKey(key)) {
        DeleteFileA(path);
        return;
    }

    memcpy(g_session_key, key, sizeof(g_session_key));
    g_session_key_valid = TRUE;
    g_session_key_tick = GetTickCount();

    hmac_sha256_to_hex(key, SHA256_DIGEST_SIZE,
                       (const uint8_t *)SKY_FEATURE_TOKEN_LABEL,
                       strlen(SKY_FEATURE_TOKEN_LABEL), hex);

    InitLicenseBackupDirectory();

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD hex_len = (DWORD)strlen(hex);
        DWORD written = 0;
        WriteFile(hFile, hex, hex_len, &written, NULL);
        CloseHandle(hFile);
    }

    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(hex, sizeof(hex));
}

LICENSE_API int License_GetSessionKey(unsigned char* out_key, int buf_size) {
    if (!g_initialized) return LICENSE_NOT_INITIALIZED;
    if (!out_key || buf_size < SHA256_DIGEST_SIZE) return LICENSE_INVALID_PARAM;

    if (!g_session_key_valid || (GetTickCount() - g_session_key_tick) > SKY_SESSION_KEY_TTL_MS) {
        uint8_t key[SHA256_DIGEST_SIZE];
        if (!DeriveSessionKey(key)) {
            g_session_key_valid = FALSE;
            return LICENSE_ERROR;
        }
        memcpy(g_session_key, key, sizeof(g_session_key));
        g_session_key_valid = TRUE;
        g_session_key_tick = GetTickCount();
        SecureZeroMemory(key, sizeof(key));
    }

    memcpy(out_key, g_session_key, SHA256_DIGEST_SIZE);
    return LICENSE_OK;
}

static BOOL VerifySelfCodeIntegrity(void) {
    HMODULE hSelf = NULL;

    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)VerifySelfCodeIntegrity, &hSelf)) {
        return FALSE;
    }

    uint8_t *base = (uint8_t *)hSelf;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
    uint8_t *code_data = NULL;
    uint32_t code_size = 0;

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strncmp((char *)sections[i].Name, ".text", 5) == 0) {
            code_data = base + sections[i].VirtualAddress;
            code_size = sections[i].SizeOfRawData;
            break;
        }
    }

    if (!code_data || code_size == 0) return FALSE;

    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_hash(code_data, code_size, hash);

    char hex_str[SHA256_DIGEST_SIZE * 2 + 1];
    sha256_to_hex(hash, hex_str);

    return (strcmp(hex_str, LICENSE_DLL_CODE_SHA256) == 0);
}

static void InitAntiDebug(void) {
    AntiDebug_Init();
    AntiDebug_StartPeriodicScan(5000);
}

static void CleanupAntiDebug(void) {
    AntiDebug_StopPeriodicScan();
    AntiDebug_Cleanup();
}

static VOID CALLBACK AutoCheckCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {
    UNREFERENCED_PARAMETER(lpParameter);
    UNREFERENCED_PARAMETER(TimerOrWaitFired);

    if (!VerifySelfCodeIntegrity()) {
        g_is_activated = FALSE;

    }
}

BOOL APIENTRY DllMain(HMODULE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            if (g_initialized) {
                if (g_auto_check_timer) {
                    DeleteTimerQueueTimer(NULL, g_auto_check_timer, NULL);
                    g_auto_check_timer = NULL;
                }
                CleanupAntiDebug();
                g_initialized = FALSE;
                g_is_activated = FALSE;
            }
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}

LICENSE_API int License_Init(const LicenseConfig* config) {
    if (g_initialized) {
        return LICENSE_OK;
    }

    if (!VerifySelfCodeIntegrity()) {
        return LICENSE_ERROR;
    }

    InitLicenseBackupDirectory();

    if (config) {
        memcpy(&g_config, config, sizeof(LicenseConfig));
    } else {
        memcpy(&g_config, &g_default_config, sizeof(LicenseConfig));
    }

    InitAntiDebug();

    if (!GenerateMachineCode(g_machine_code, sizeof(g_machine_code))) {
        CleanupAntiDebug();
        return LICENSE_ERROR;
    }

    uint32_t ntp_time = 0;
    if (!g_ntp_base_ready) {
        if (GetNtpTime(&ntp_time)) {
            g_verified_time = ntp_time;
            RecordNtpBase(ntp_time);
        } else {
            g_verified_time = (uint32_t)time(NULL);
        }
    } else {

        g_verified_time = DllGetTrustedTime();
    }

    uint32_t saved_expire = 0;
    char saved_username[USERNAME_LEN] = {0};
    char saved_email[EMAIL_LEN] = {0};

    if (LoadActivationStatus(g_machine_code, &saved_expire, saved_username, saved_email)) {
        if (!IsLicenseExpired(saved_expire, g_verified_time)) {
            g_is_activated = TRUE;
            g_expire_time = saved_expire;
            g_license_source = GetActivationSource();
            if (g_license_source != LICENSE_SOURCE_OFFLINE &&
                g_license_source != LICENSE_SOURCE_ONLINE) {
                g_license_source = LICENSE_SOURCE_OFFLINE;
            }
            strncpy_s(g_username, sizeof(g_username), saved_username, _TRUNCATE);
            strncpy_s(g_email, sizeof(g_email), saved_email, _TRUNCATE);
            UpdateLastSeenTime(g_verified_time);

            RefreshFeatureToken();
        }
    }

    g_initialized = TRUE;

    if (g_config.auto_check_interval > 0) {
        CreateTimerQueueTimer(&g_auto_check_timer, NULL, AutoCheckCallback, NULL,
                              (DWORD)g_config.auto_check_interval * 1000,
                              (DWORD)g_config.auto_check_interval * 1000,
                              WT_EXECUTEDEFAULT);
    }

    return LICENSE_OK;
}

LICENSE_API void License_Shutdown(void) {
    if (!g_initialized) return;

    if (g_auto_check_timer) {
        DeleteTimerQueueTimer(NULL, g_auto_check_timer, NULL);
        g_auto_check_timer = NULL;
    }
    CleanupAntiDebug();

    g_initialized = FALSE;
    g_is_activated = FALSE;
    g_expire_time = 0;
    g_verified_time = 0;
    g_license_source = LICENSE_SOURCE_NONE;
    memset(g_username, 0, sizeof(g_username));
    memset(g_email, 0, sizeof(g_email));
    memset(g_machine_code, 0, sizeof(g_machine_code));
}

LICENSE_API BOOL License_IsActivated(void) {
    if (!g_initialized) {
        return FALSE;
    }

    if (g_is_activated) {

        if (!VerifySelfCodeIntegrity()) {
            g_is_activated = FALSE;
            ClearActivationStatus();
            ExitProcess(1);
        }

        g_verified_time = DllGetTrustedTime();

        if (IsLicenseExpired(g_expire_time, g_verified_time)) {
            g_is_activated = FALSE;
            return FALSE;
        }

        return TRUE;
    }

    return FALSE;
}

LICENSE_API int License_GetInfo(LicenseInfo* info) {
    if (!g_initialized) {
        return LICENSE_NOT_INITIALIZED;
    }

    if (!info) {
        return LICENSE_INVALID_PARAM;
    }

    memset(info, 0, sizeof(LicenseInfo));

    g_verified_time = DllGetTrustedTime();

    info->current_time = g_verified_time;
    strncpy_s(info->machine_code, sizeof(info->machine_code), g_machine_code, _TRUNCATE);

    if (g_is_activated) {
        info->expire_time = g_expire_time;
        info->source = g_license_source;
        strncpy_s(info->username, sizeof(info->username), g_username, _TRUNCATE);
        strncpy_s(info->email, sizeof(info->email), g_email, _TRUNCATE);

        if (IsLicenseExpired(g_expire_time, g_verified_time)) {
            info->status = LICENSE_STATUS_EXPIRED;
            info->remaining_days = 0;
        } else {
            int remaining = GetRemainingDays(g_expire_time, g_verified_time);
            if (remaining < 0) {
                info->status = LICENSE_STATUS_PERMANENT;
                info->remaining_days = 0xFFFFFFFF;
            } else {
                info->status = LICENSE_STATUS_ACTIVATED;
                info->remaining_days = (uint32_t)remaining;
            }
        }
    } else {
        info->status = LICENSE_STATUS_NOT_ACTIVATED;
        info->remaining_days = 0;
    }

    return LICENSE_OK;
}

LICENSE_API int License_GetMachineCode(char* machine_code, int buf_size) {
    if (!g_initialized) {
        return LICENSE_NOT_INITIALIZED;
    }

    if (!machine_code || buf_size < MACHINE_CODE_LEN) {
        return LICENSE_INVALID_PARAM;
    }

    strncpy_s(machine_code, buf_size, g_machine_code, _TRUNCATE);
    machine_code[buf_size - 1] = '\0';

    return LICENSE_OK;
}

LICENSE_API int License_GetObfuscatedMachineCode(char* obfuscated_out, int buf_size) {
    if (!g_initialized) {
        return LICENSE_NOT_INITIALIZED;
    }

    if (!obfuscated_out || buf_size < MACHINE_CODE_LEN) {
        return LICENSE_INVALID_PARAM;
    }

    if (!ObfuscateMachineCode(g_machine_code, obfuscated_out, (size_t)buf_size)) {

        strncpy_s(obfuscated_out, buf_size, g_machine_code, _TRUNCATE);
        obfuscated_out[buf_size - 1] = '\0';
    }

    return LICENSE_OK;
}

LICENSE_API int License_NormalizeMachineCode(const char* input_machine_code, char* normalized_out, int buf_size) {
    if (!input_machine_code || !normalized_out || buf_size < MACHINE_CODE_LEN) {
        return LICENSE_INVALID_PARAM;
    }

    if (!NormalizeMachineCode(input_machine_code, normalized_out, (size_t)buf_size)) {
        return LICENSE_INVALID_PARAM;
    }

    return LICENSE_OK;
}

LICENSE_API BOOL License_Verify(void) {
    if (!g_initialized) {
        return FALSE;
    }

    if (!g_is_activated) {
        return FALSE;
    }

    if (!VerifySelfCodeIntegrity()) {
        g_is_activated = FALSE;
        ClearActivationStatus();
        ExitProcess(1);
    }

    g_verified_time = DllGetTrustedTime();

    uint32_t verified_time = 0;
    int time_source = 0;
    if (!VerifyTimeIntegrity(g_machine_code, &verified_time, &time_source)) {
        g_is_activated = FALSE;
        ClearActivationStatus();
        return FALSE;
    }

    if (verified_time > g_verified_time) {
        g_verified_time = verified_time;
    }

    if (IsLicenseExpired(g_expire_time, g_verified_time)) {
        g_is_activated = FALSE;
        ClearActivationStatus();
        return FALSE;
    }

    UpdateLastSeenTime(g_verified_time);
    return TRUE;
}

LICENSE_API int License_ShowActivationDialog(HWND parent_hwnd) {
    if (!g_initialized) {
        return LICENSE_NOT_INITIALIZED;
    }

    char machine_code[MACHINE_CODE_LEN] = {0};
    strncpy_s(machine_code, sizeof(machine_code), g_machine_code, _TRUNCATE);

    WCHAR message[512];
    WCHAR w_machine[512];

    ZeroMemory(w_machine, sizeof(w_machine));
    MultiByteToWideChar(CP_UTF8, 0, machine_code, -1, w_machine, 512);

    swprintf_s(message, 512,
        L"您的机器码是：\n\n%s\n\n"
        L"请复制此机器码，联系开发者获取激活码。\n\n"
        L"获取激活码后，请再次运行本程序进行激活。",
        w_machine);

    MessageBoxW(parent_hwnd, message, L"激活提示", MB_OK | MB_ICONINFORMATION);

    return LICENSE_OK;
}

LICENSE_API int License_Activate(const char* activation_code, const char* username, const char* email) {
    g_lastErrorMsg[0] = '\0';
    if (!g_initialized) {
        SetLastErrorUtf8("授权系统未初始化，请先调用 License_Init");
        return LICENSE_NOT_INITIALIZED;
    }

    if (!activation_code || strlen(activation_code) == 0) {
        SetLastErrorUtf8("激活码为空");
        return LICENSE_INVALID_PARAM;
    }

    g_verified_time = DllGetTrustedTime();

    char clean_code[ACTIVATION_CODE_LEN] = {0};
    int clean_idx = 0;
    for (int i = 0; activation_code[i] && clean_idx < ACTIVATION_CODE_LEN - 1; i++) {
        char c = activation_code[i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            clean_code[clean_idx++] = c;
        }
    }
    clean_code[clean_idx] = '\0';

    uint32_t expire_time = 0;
    char code_seq[CODE_SEQ_LEN + 1] = {0};

    char safe_username[USERNAME_LEN] = {0};
    char safe_email[EMAIL_LEN] = {0};

    if (username) strncpy_s(safe_username, sizeof(safe_username), username, _TRUNCATE);
    if (email) strncpy_s(safe_email, sizeof(safe_email), email, _TRUNCATE);

    int result = ValidateActivationCode(
        g_machine_code, safe_username, safe_email,
        clean_code, &expire_time, g_verified_time, code_seq
    );

    if (result != ACT_VALID) {

        char timeNowBuf[32] = {0};
        {
            time_t tt = (time_t)g_verified_time;
            struct tm tm_buf;
            if (localtime_s(&tm_buf, &tt) == 0) {
                strftime(timeNowBuf, sizeof(timeNowBuf), "%Y-%m-%d %H:%M:%S", &tm_buf);
            }
        }

        if (result == ACT_USED) {
            SetLastErrorUtf8(
                "激活码已被使用：序列号 %s 已在本台机器的 license-SkyBox.dat 中登记。\n"
                "解决方法：请在激活码生成器中重新点击【生成激活码】，产生一个新序列号的激活码（生成时间会变化，序列号也会不同），再用新码续期。",
                code_seq);
        } else if (result == ACT_EXPIRED_FUTURE) {
            char expBuf[32] = {0};
            time_t tt = (time_t)expire_time;
            struct tm tm_buf;
            if (expire_time > 0 && localtime_s(&tm_buf, &tt) == 0) {
                strftime(expBuf, sizeof(expBuf), "%Y-%m-%d %H:%M:%S", &tm_buf);
            }
            SetLastErrorUtf8(
                "激活码已过期：该激活码到期时间为 %s，而本机可信时间是 %s。\n"
                "解决方法：请在激活码生成器中将授权时长设置为更大的数值（例如 1 年、365 天），重新生成激活码。",
                expBuf[0] ? expBuf : "未知", timeNowBuf[0] ? timeNowBuf : "未知");
        } else {

            char clean_machine[200] = {0};

            char expHint[64] = {0};
            if (expire_time > 0) {
                time_t tt = (time_t)expire_time;
                struct tm tm_buf;
                if (localtime_s(&tm_buf, &tt) == 0) {
                    strftime(expHint, sizeof(expHint), "expire=%Y-%m-%d %H:%M:%S", &tm_buf);
                }
            }
            SetLastErrorUtf8(
                "激活码无效（哈希校验/CRC校验/时间范围 之一不通过）。\n"
                "—— 请严格对照以下 4 项逐一检查，100%% 匹配才能通过：\n"
                "  1) 机器码：生成器里的机器码 和 续期界面的机器码 必须完全一样（当前本机：%.16s...）；\n"
                "  2) 用户名：生成器里填的用户名 和 续期界面的用户名 必须完全一样（大小写、空格都算不同）（当前激活入参：%s）；\n"
                "  3) 邮箱：生成器里填的邮箱 和 续期界面的邮箱 必须完全一样（当前激活入参：%s）；\n"
                "  4) 时间：生成器与本台机器可信时间不能相差 > 60 秒（本机时间：%s），否则会被判定为『生成时间超窗』。\n"
                "%s%s%s"
                "如果以上 4 项已完全一致仍提示无效，请把生成器中的激活码完整复制（不要漏首尾字符），或者关闭生成器再重新生成一次新的激活码重试。",
                g_machine_code,
                safe_username[0] ? safe_username : "(空)",
                safe_email[0] ? safe_email : "(空)",
                timeNowBuf[0] ? timeNowBuf : "未知",
                code_seq[0] ? "（激活码序列号：" : "",
                code_seq[0] ? code_seq : "",
                code_seq[0] ? "）\n" : "");
        }
        return LICENSE_ERROR;
    }

    if (!SaveActivationStatus(TRUE, g_machine_code, expire_time,
                               safe_username, safe_email, code_seq, g_verified_time)) {
        const char* detail = GetLastLicenseFileIOError();
        if (detail && detail[0]) {
            SetLastErrorUtf8(
                "保存授权文件 license-SkyBox.dat 失败，可能是程序没有写入权限。\n"
                "==============================\n"
                "【详细诊断信息】\n"
                "%s\n"
                "==============================\n"
                "建议尝试：先关闭所有可能占用 license-SkyBox.dat 的程序，再右键 SkyBox.exe → 以管理员身份运行后重试授权更新。",
                detail);
        } else {
            SetLastErrorUtf8(
                "保存授权文件 license-SkyBox.dat 失败，可能是程序没有写入权限。\n"
                "建议尝试：右键 SkyBox.exe → 以管理员身份运行后重试授权更新。");
        }
        return LICENSE_ERROR;
    }

    g_is_activated = TRUE;
    g_license_source = LICENSE_SOURCE_OFFLINE;
    g_expire_time = expire_time;
    strncpy_s(g_username, sizeof(g_username), safe_username, _TRUNCATE);
    strncpy_s(g_email, sizeof(g_email), safe_email, _TRUNCATE);

    if (!InitializeTimeProtection(g_machine_code, g_verified_time)) {
        g_is_activated = FALSE;
        g_license_source = LICENSE_SOURCE_NONE;
        g_expire_time = 0;
        memset(g_username, 0, sizeof(g_username));
        memset(g_email, 0, sizeof(g_email));
        ClearActivationStatus();
        SetLastErrorUtf8("时间防篡改初始化失败，请检查本机时间是否被回拨。");
        return LICENSE_ERROR;
    }

    RefreshFeatureToken();

    SetLastErrorUtf8("");
    return LICENSE_OK;
}

LICENSE_API int License_GetLastErrorMsg(char* buffer, int buf_size) {
    if (!buffer || buf_size <= 0) return 0;
    size_t len = strlen(g_lastErrorMsg);
    if (len == 0) {
        buffer[0] = '\0';
        return 0;
    }
    size_t cp = (len < (size_t)(buf_size - 1)) ? len : (size_t)(buf_size - 1);
    memcpy(buffer, g_lastErrorMsg, cp);
    buffer[cp] = '\0';
    return (int)cp;
}

LICENSE_API int License_Clear(void) {
    if (!g_initialized) {
        return LICENSE_NOT_INITIALIZED;
    }

    ClearActivationStatus();

    g_is_activated = FALSE;
    g_license_source = LICENSE_SOURCE_NONE;
    g_expire_time = 0;
    memset(g_username, 0, sizeof(g_username));
    memset(g_email, 0, sizeof(g_email));

    return LICENSE_OK;
}

LICENSE_API int License_ImportOnline(const char* activation_code, const char* username,
                                     const char* email, uint32_t expire_time,
                                     uint32_t server_time) {
    g_lastErrorMsg[0] = '\0';
    if (!g_initialized) {
        SetLastErrorUtf8("授权系统未初始化，请先调用 License_Init");
        return LICENSE_NOT_INITIALIZED;
    }
    if (!activation_code || !*activation_code) {
        SetLastErrorUtf8("在线激活码为空");
        return LICENSE_INVALID_PARAM;
    }
    if (!username || !email) {
        SetLastErrorUtf8("用户名和邮箱不能为空");
        return LICENSE_INVALID_PARAM;
    }

    char safe_code[64] = {0};
    char safe_username[USERNAME_LEN] = {0};
    char safe_email[EMAIL_LEN] = {0};
    strncpy_s(safe_code, sizeof(safe_code), activation_code, _TRUNCATE);
    strncpy_s(safe_username, sizeof(safe_username), username, _TRUNCATE);
    strncpy_s(safe_email, sizeof(safe_email), email, _TRUNCATE);

    uint32_t anchor_time = (server_time > 0) ? server_time : DllGetTrustedTime();

    if (!SaveOnlineActivation(safe_code, g_machine_code, expire_time,
                              safe_username, safe_email, anchor_time)) {
        const char* detail = GetLastLicenseFileIOError();
        if (detail && detail[0]) {
            SetLastErrorUtf8(
                "保存授权文件 license-SkyBox.dat 失败，可能是程序没有写入权限。\n"
                "==============================\n【详细诊断信息】\n%s\n==============================\n"
                "建议尝试：先关闭所有可能占用 license-SkyBox.dat 的程序，再右键 SkyBox.exe → 以管理员身份运行后重试。",
                detail);
        } else {
            SetLastErrorUtf8(
                "保存授权文件 license-SkyBox.dat 失败，可能是程序没有写入权限。\n"
                "建议尝试：右键 SkyBox.exe → 以管理员身份运行后重试授权更新。");
        }
        return LICENSE_ERROR;
    }

    g_is_activated = TRUE;
    g_license_source = LICENSE_SOURCE_ONLINE;
    g_expire_time = expire_time;
    strncpy_s(g_username, sizeof(g_username), safe_username, _TRUNCATE);
    strncpy_s(g_email, sizeof(g_email), safe_email, _TRUNCATE);

    if (!InitializeTimeProtection(g_machine_code, anchor_time)) {
        g_is_activated = FALSE;
        g_license_source = LICENSE_SOURCE_NONE;
        g_expire_time = 0;
        memset(g_username, 0, sizeof(g_username));
        memset(g_email, 0, sizeof(g_email));
        ClearOnlineActivation();
        SetLastErrorUtf8("时间防篡改初始化失败，请检查本机时间是否被回拨。");
        return LICENSE_ERROR;
    }

    RefreshFeatureToken();

    SetLastErrorUtf8("");
    return LICENSE_OK;
}

LICENSE_API int License_GetOnlineCode(char* code, int buf_size, uint32_t* last_verify) {
    if (!g_initialized) {
        return LICENSE_NOT_INITIALIZED;
    }
    if (!code || buf_size < 20) {
        return LICENSE_INVALID_PARAM;
    }
    if (!LoadOnlineAuth(code, (size_t)buf_size, last_verify) || code[0] == '\0') {
        code[0] = '\0';
        if (last_verify) *last_verify = 0;
        return LICENSE_ERROR;
    }
    return LICENSE_OK;
}

LICENSE_API int License_GetSource(void) {
    if (!g_initialized) {
        return LICENSE_SOURCE_NONE;
    }
    return g_license_source;
}

LICENSE_API int License_ClearOnline(void) {
    if (!g_initialized) {
        return LICENSE_NOT_INITIALIZED;
    }
    if (g_license_source != LICENSE_SOURCE_ONLINE) {
        return LICENSE_OK;
    }

    if (!ClearOnlineActivation()) {
        return LICENSE_ERROR;
    }

    g_is_activated = FALSE;
    g_license_source = LICENSE_SOURCE_NONE;
    g_expire_time = 0;
    memset(g_username, 0, sizeof(g_username));
    memset(g_email, 0, sizeof(g_email));
    return LICENSE_OK;
}

LICENSE_API int License_GenerateCode(const char* machine_code, uint64_t total_seconds,
                                       const char* username, const char* email,
                                       char* activation_code) {
    if (!g_initialized) {
        return LICENSE_NOT_INITIALIZED;
    }

    if (!machine_code || !activation_code) {
        return LICENSE_INVALID_PARAM;
    }

    g_verified_time = DllGetTrustedTime();

    char safe_username[USERNAME_LEN] = {0};
    char safe_email[EMAIL_LEN] = {0};

    if (username) strncpy_s(safe_username, sizeof(safe_username), username, _TRUNCATE);
    if (email) strncpy_s(safe_email, sizeof(safe_email), email, _TRUNCATE);

    if (!GenerateActivationCode(machine_code, total_seconds, safe_username, safe_email,
                                  activation_code, ACTIVATION_CODE_LEN, g_verified_time)) {
        return LICENSE_ERROR;
    }

    return LICENSE_OK;
}
