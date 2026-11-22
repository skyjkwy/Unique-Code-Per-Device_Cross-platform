#include "license.h"
#include "hardware.h"
#include "sha256.h"
#include "ntp_client.h"
#include "time_anchor.h"
#include "key.h"
#include "ecdsa.h"
#include <windows.h>
#include <shlobj.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#define TIME_SOURCE_NTP 1
#define TIME_SOURCE_ANCHOR 2
#define TIME_SOURCE_LOCAL 3

#define LICENSE_FILE "license-SkyBox.dat"
#define BASE_FILE_SIZE 169

#define ACT_SOURCE_NONE     0
#define ACT_SOURCE_OFFLINE  1
#define ACT_SOURCE_ONLINE   2

#define ONLINE_FOOTER_MAGIC    "SKON"
#define ONLINE_FOOTER_SIZE     32
#define ONLINE_CODE_STORE_LEN  20

static void CleanString(const char *input, char *output, size_t max_len, int tolower_flag, const char *obfuscate_charset);

static BOOL MakeAbsolutePath(const char *rel_path, wchar_t *out_path) {
    if (!rel_path || !out_path) return FALSE;

    if (rel_path[0] == '\\' || (rel_path[1] == ':' && rel_path[2] == '\\')) {
        MultiByteToWideChar(CP_UTF8, 0, rel_path, -1, out_path, MAX_PATH);
        return TRUE;
    }

    wchar_t module_dir[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, module_dir, MAX_PATH);
    wchar_t *last_slash = wcsrchr(module_dir, L'\\');
    if (last_slash) *(last_slash + 1) = L'\0';

    char full_path[MAX_PATH] = {0};
    strncpy_s(full_path, MAX_PATH, rel_path, _TRUNCATE);

    wchar_t wfull[MAX_PATH] = {0};
    MultiByteToWideChar(CP_UTF8, 0, full_path, -1, wfull, MAX_PATH);

    if (module_dir[0]) {
        wcscat_s(module_dir, MAX_PATH, wfull);
        wcscpy_s(out_path, MAX_PATH, module_dir);
    } else {
        wcscpy_s(out_path, MAX_PATH, wfull);
    }
    return TRUE;
}

#define LICENSE_REG_ROOT    L"Software\\SkySoftware\\SkyBox\\License"
#define LICENSE_REG_VALUE   L"LicenseData"
#define LICENSE_REG_FLAGS   L"LicenseFlags"

#define LICENSE_ADS_STREAM  "license-SkyBox"

#define LICENSE_APPDATA_DIR   L"SkySoftware"
#define LICENSE_APPDATA_FILE  L"license-SkyBox.dat"
#define LICENSE_APPDATA_MAGIC 0x534B5431

static HANDLE g_hLicenseFileLock = NULL;

static char g_lastLicenseFileIOError[1024] = {0};
static void SetLicenseFileIOError(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(g_lastLicenseFileIOError, sizeof(g_lastLicenseFileIOError), _TRUNCATE, fmt, ap);
    va_end(ap);
}
const char* GetLastLicenseFileIOError(void) {
    return g_lastLicenseFileIOError;
}

static uint32_t crc32_table[256];
static int crc32_table_initialized = 0;

static void init_crc32_table() {
    if (crc32_table_initialized) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
    crc32_table_initialized = 1;
}

static uint32_t calculate_crc32(const char *data, size_t len) {
    init_crc32_table();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {

        crc = (crc >> 8) ^ crc32_table[(crc ^ (uint8_t)data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

static char CustomEncode(int val, const char *charset) {
    return charset[val & 0x0F];
}

static int CustomDecode(char ch, const char *charset) {
    char ch_upper = (ch >= 'a' && ch <= 'z') ? (ch - 'a' + 'A') : ch;
    char ch_lower = (ch >= 'A' && ch <= 'Z') ? (ch - 'A' + 'a') : ch;
    for (int i = 0; i < 16; i++) {
        if (charset[i] == ch || charset[i] == ch_upper || charset[i] == ch_lower) return i;
    }
    return -1;
}

static void XorEncode(uint8_t *data, size_t len, const uint8_t *xor_key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= xor_key[i % XOR_KEY_LEN];
    }
}

static void XorDecode(uint8_t *data, size_t len, const uint8_t *xor_key) {
    XorEncode(data, len, xor_key);
}

static void ByteEncode(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] = ((data[i] & 0x0F) << 4) | ((data[i] & 0xF0) >> 4);
    }
}

static void ByteDecode(uint8_t *data, size_t len) {
    ByteEncode(data, len);
}

static int ObfuscateCode(const char *hex_code, char *obfuscated, size_t max_len) {
    if (max_len == 0) return 0;

    size_t hex_len = strlen(hex_code);
    size_t byte_len = hex_len / 2;

    if (byte_len == 0 || hex_len > 200) return 0;

    char charset[Obfuscate_CHARSET_LEN + 1];
    uint8_t xor_key[XOR_KEY_LEN];
    GetObfuscateCharset(charset);
    GetXorKey(xor_key);

    uint8_t bytes[100];
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte_val = 0;
        sscanf(hex_code + i * 2, "%2x", &byte_val);
        bytes[i] = (uint8_t)byte_val;
    }

    XorEncode(bytes, byte_len, xor_key);

    ByteEncode(bytes, byte_len);

    size_t obf_len = 0;

    for (size_t i = 0; i < byte_len && obf_len < max_len - 2; i++) {
        obfuscated[obf_len++] = CustomEncode((bytes[i] >> 4) & 0x0F, charset);
        obfuscated[obf_len++] = CustomEncode(bytes[i] & 0x0F, charset);
    }
    obfuscated[obf_len] = '\0';

    SecureZeroMemory(charset, sizeof(charset));
    SecureZeroMemory(xor_key, sizeof(xor_key));

    return (int)obf_len;
}

static int DeobfuscateCode(const char *obfuscated, char *hex_code, size_t max_len) {
    if (max_len < 2) return 0;

    size_t obf_len = strlen(obfuscated);
    size_t byte_len = obf_len / 2;

    if (byte_len == 0 || byte_len > 100) return 0;

    char charset[Obfuscate_CHARSET_LEN + 1];
    uint8_t xor_key[XOR_KEY_LEN];
    GetObfuscateCharset(charset);
    GetXorKey(xor_key);

    uint8_t bytes[100];
    for (size_t i = 0; i < byte_len; i++) {
        int high = CustomDecode(obfuscated[i * 2], charset);
        int low = CustomDecode(obfuscated[i * 2 + 1], charset);
        if (high < 0 || low < 0) {
            SecureZeroMemory(charset, sizeof(charset));
            SecureZeroMemory(xor_key, sizeof(xor_key));
            return 0;
        }
        bytes[i] = ((uint8_t)high << 4) | (uint8_t)low;
    }

    ByteDecode(bytes, byte_len);

    XorDecode(bytes, byte_len, xor_key);

    size_t hex_len = 0;
    for (size_t i = 0; i < byte_len && hex_len < max_len - 2; i++) {
        hex_len += sprintf(hex_code + hex_len, "%02x", bytes[i]);
    }
    hex_code[hex_len] = '\0';

    SecureZeroMemory(charset, sizeof(charset));
    SecureZeroMemory(xor_key, sizeof(xor_key));

    return (int)hex_len;
}

static int IsObfuscatedChar(char ch, const char *charset) {
    char ch_upper = (ch >= 'a' && ch <= 'z') ? (ch - 'a' + 'A') : ch;
    char ch_lower = (ch >= 'A' && ch <= 'Z') ? (ch - 'A' + 'a') : ch;
    for (int i = 0; i < 16; i++) {
        if (charset[i] == ch || charset[i] == ch_upper || charset[i] == ch_lower) return 1;
    }
    return 0;
}

static int IsHexChar(char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

static int DetectCodeFormat(const char *code, const char *charset) {
    if (!code || !code[0]) return -1;

    int has_non_hex = 0;

    for (int i = 0; code[i]; i++) {
        if (!IsHexChar(code[i])) {
            has_non_hex = 1;

            if (!IsObfuscatedChar(code[i], charset)) return -1;
        }
    }

    return has_non_hex ? 1 : 0;
}

static char McCustomEncode(int val, const char *charset) {
    return charset[val & 0x0F];
}

static int McCustomDecode(char ch, const char *charset) {
    char ch_upper = (ch >= 'a' && ch <= 'z') ? (ch - 'a' + 'A') : ch;
    char ch_lower = (ch >= 'A' && ch <= 'Z') ? (ch - 'A' + 'a') : ch;
    for (int i = 0; i < 16; i++) {
        if (charset[i] == ch || charset[i] == ch_upper || charset[i] == ch_lower) return i;
    }
    return -1;
}

static int McIsObfuscatedChar(char ch, const char *charset) {
    return McCustomDecode(ch, charset) >= 0;
}

static void McXorEncode(uint8_t *data, size_t len, const uint8_t *xor_key) {
    uint8_t prev = 0;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= xor_key[i % XOR_KEY_LEN];
        data[i] ^= prev;
        prev = data[i];
    }
}

static void McXorDecode(uint8_t *data, size_t len, const uint8_t *xor_key) {
    uint8_t prev = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t cur = data[i];
        data[i] ^= prev;
        data[i] ^= xor_key[i % XOR_KEY_LEN];
        prev = cur;
    }
}

static int DetectMachineCodeFormat(const char *code, const char *charset) {
    if (!code || !code[0]) return -1;

    int has_mc_obf = 0;

    for (int i = 0; code[i]; i++) {
        if (IsHexChar(code[i])) {
            continue;
        }

        if (McIsObfuscatedChar(code[i], charset)) {
            has_mc_obf = 1;
        } else {
            return -1;
        }
    }

    return has_mc_obf ? 1 : 0;
}

BOOL ObfuscateMachineCode(const char *original_machine_code, char *obfuscated_out, size_t max_len) {
    if (!original_machine_code || !obfuscated_out || max_len < 2) return FALSE;

    char mc_charset[MACHINE_CHARSET_LEN + 1];
    uint8_t mc_xor_key[XOR_KEY_LEN];
    GetMachineObfuscateCharset(mc_charset);
    GetMachineXorKey(mc_xor_key);

    char clean_input[MACHINE_CODE_LEN * 2] = {0};
    CleanString(original_machine_code, clean_input, sizeof(clean_input), 1, mc_charset);

    size_t hex_len = strlen(clean_input);
    if (hex_len == 0 || hex_len % 2 != 0 || hex_len > MACHINE_CODE_LEN * 2) {
        SecureZeroMemory(mc_charset, sizeof(mc_charset));
        SecureZeroMemory(mc_xor_key, sizeof(mc_xor_key));
        return FALSE;
    }
    size_t byte_len = hex_len / 2;

    uint8_t bytes[128] = {0};
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte_val = 0;
        if (sscanf(clean_input + i * 2, "%2x", &byte_val) != 1) {
            SecureZeroMemory(mc_charset, sizeof(mc_charset));
            SecureZeroMemory(mc_xor_key, sizeof(mc_xor_key));
            return FALSE;
        }
        bytes[i] = (uint8_t)byte_val;
    }

    McXorEncode(bytes, byte_len, mc_xor_key);

    ByteEncode(bytes, byte_len);

    size_t obf_len = 0;
    for (size_t i = 0; i < byte_len && obf_len < max_len - 2; i++) {
        obfuscated_out[obf_len++] = McCustomEncode((bytes[i] >> 4) & 0x0F, mc_charset);
        obfuscated_out[obf_len++] = McCustomEncode(bytes[i] & 0x0F, mc_charset);
    }
    obfuscated_out[obf_len] = '\0';

    SecureZeroMemory(mc_charset, sizeof(mc_charset));
    SecureZeroMemory(mc_xor_key, sizeof(mc_xor_key));

    return TRUE;
}

BOOL DeobfuscateMachineCode(const char *input_machine_code, char *deobfuscated_out, size_t max_len) {
    if (!input_machine_code || !deobfuscated_out || max_len < 2) return FALSE;

    char mc_charset[MACHINE_CHARSET_LEN + 1];
    uint8_t mc_xor_key[XOR_KEY_LEN];
    GetMachineObfuscateCharset(mc_charset);
    GetMachineXorKey(mc_xor_key);

    char clean_input[MACHINE_CODE_LEN * 2] = {0};
    CleanString(input_machine_code, clean_input, sizeof(clean_input), 0, mc_charset);

    size_t obf_len = strlen(clean_input);
    if (obf_len == 0 || obf_len % 2 != 0 || obf_len > MACHINE_CODE_LEN * 2) {
        SecureZeroMemory(mc_charset, sizeof(mc_charset));
        SecureZeroMemory(mc_xor_key, sizeof(mc_xor_key));
        return FALSE;
    }
    size_t byte_len = obf_len / 2;

    uint8_t bytes[128] = {0};
    for (size_t i = 0; i < byte_len; i++) {
        int high = McCustomDecode(clean_input[i * 2], mc_charset);
        int low  = McCustomDecode(clean_input[i * 2 + 1], mc_charset);
        if (high < 0 || low < 0) {
            SecureZeroMemory(mc_charset, sizeof(mc_charset));
            SecureZeroMemory(mc_xor_key, sizeof(mc_xor_key));
            return FALSE;
        }
        bytes[i] = ((uint8_t)high << 4) | (uint8_t)low;
    }

    ByteDecode(bytes, byte_len);

    McXorDecode(bytes, byte_len, mc_xor_key);

    size_t hex_len = 0;
    for (size_t i = 0; i < byte_len && hex_len < max_len - 2; i++) {
        hex_len += sprintf(deobfuscated_out + hex_len, "%02x", bytes[i]);
    }
    deobfuscated_out[hex_len] = '\0';

    SecureZeroMemory(mc_charset, sizeof(mc_charset));
    SecureZeroMemory(mc_xor_key, sizeof(mc_xor_key));

    return TRUE;
}

BOOL NormalizeMachineCode(const char *input_machine_code, char *normalized_out, size_t max_len) {
    if (!input_machine_code || !normalized_out || max_len == 0) return FALSE;

    char mc_charset[MACHINE_CHARSET_LEN + 1];
    GetMachineObfuscateCharset(mc_charset);

    char clean_input[MACHINE_CODE_LEN * 2] = {0};
    CleanString(input_machine_code, clean_input, sizeof(clean_input), 0, mc_charset);

    if (!clean_input[0]) {
        SecureZeroMemory(mc_charset, sizeof(mc_charset));
        return FALSE;
    }

    int fmt = DetectMachineCodeFormat(clean_input, mc_charset);
    if (fmt == 0) {

        size_t j = 0;
        for (size_t i = 0; clean_input[i] && j < max_len - 1; i++) {
            if (clean_input[i] >= 'A' && clean_input[i] <= 'F') {
                normalized_out[j++] = (char)(clean_input[i] + 32);
            } else {
                normalized_out[j++] = clean_input[i];
            }
        }
        normalized_out[j] = '\0';
        SecureZeroMemory(mc_charset, sizeof(mc_charset));
        return TRUE;
    } else if (fmt == 1) {

        SecureZeroMemory(mc_charset, sizeof(mc_charset));
        return DeobfuscateMachineCode(clean_input, normalized_out, max_len);
    } else {

        SecureZeroMemory(mc_charset, sizeof(mc_charset));
        return FALSE;
    }
}

static const uint8_t* find_online_footer(const uint8_t *data, size_t data_size, size_t *used_size_out) {
    size_t used_size = 0;
    const uint8_t *footer = NULL;
    if (data_size >= BASE_FILE_SIZE) {
        used_size = data_size - BASE_FILE_SIZE;
        if (used_size >= ONLINE_FOOTER_SIZE &&
            memcmp(data + data_size - ONLINE_FOOTER_SIZE, ONLINE_FOOTER_MAGIC, 4) == 0) {
            footer = data + data_size - ONLINE_FOOTER_SIZE;
            used_size -= ONLINE_FOOTER_SIZE;
        }
    }
    if (used_size_out) *used_size_out = used_size;
    return footer;
}

static void compute_binding_digest(int source, const char *machine_code, uint8_t *out) {

    size_t pub_key_len = 0;
    const uint8_t *pub_key = GetEmbeddedPublicKey(&pub_key_len);

    uint8_t combined[512];
    size_t mc_len = strlen(machine_code);
    memset(combined, 0, sizeof(combined));
    memcpy(combined, machine_code, mc_len);
    if (pub_key && pub_key_len > 0) {
        memcpy(combined + mc_len, pub_key, pub_key_len);
    }
    sha256_hash(combined, mc_len + pub_key_len, out);
}

BOOL IsActivationCodeUsed(const char *code_seq) {
    if (!code_seq || strlen(code_seq) != CODE_SEQ_LEN) return FALSE;

    uint8_t *data = NULL;
    size_t data_size = 0;

    if (!DecryptLicenseFile(LICENSE_FILE, &data, &data_size)) {
        return FALSE;
    }

    if (data_size < BASE_FILE_SIZE) {
        free(data);
        return FALSE;
    }

    size_t used_section_size = 0;
    find_online_footer(data, data_size, &used_section_size);
    int total_count = (int)(used_section_size / CODE_SEQ_LEN);
    if (total_count <= 0) {
        free(data);
        return FALSE;
    }

    char *used_codes = (char*)(data + BASE_FILE_SIZE);
    for (int i = 0; i < total_count; i++) {
        if (used_codes[i * CODE_SEQ_LEN] == '\0') continue;
        if (memcmp(used_codes + i * CODE_SEQ_LEN, code_seq, CODE_SEQ_LEN) == 0) {
            free(data);
            return TRUE;
        }
    }

    free(data);
    return FALSE;
}

void MarkActivationCodeUsed(const char *code_seq) {
    if (!code_seq || strlen(code_seq) != CODE_SEQ_LEN) return;
    if (IsActivationCodeUsed(code_seq)) return;

    uint8_t *data = NULL;
    size_t data_size = 0;

    if (!DecryptLicenseFile(LICENSE_FILE, &data, &data_size)) {
        return;
    }

    if (data_size < BASE_FILE_SIZE) {
        free(data);
        return;
    }

    size_t used_section_size = 0;
    const uint8_t *footer = find_online_footer(data, data_size, &used_section_size);
    size_t footer_off = footer ? (size_t)(footer - data) : data_size;

    size_t new_size = data_size + CODE_SEQ_LEN;
    uint8_t *new_data = (uint8_t*)malloc(new_size);
    if (!new_data) {
        free(data);
        return;
    }
    memset(new_data, 0, new_size);

    memcpy(new_data, data, footer_off);
    memcpy(new_data + footer_off, code_seq, CODE_SEQ_LEN);
    if (footer) {
        memcpy(new_data + footer_off + CODE_SEQ_LEN, footer, ONLINE_FOOTER_SIZE);
    }
    free(data);

    EncryptLicenseFile(new_data, new_size, LICENSE_FILE);

    free(new_data);
}

BOOL GenerateMachineCode(char *machine_code, size_t max_len) {
    if (!machine_code || max_len == 0) return FALSE;

    char fingerprint[1024] = {0};
    uint8_t digest[SHA256_DIGEST_SIZE];

    GenerateHardwareFingerprint(fingerprint, sizeof(fingerprint));

    sha256_hash((const uint8_t *)fingerprint, strlen(fingerprint), digest);

    char hex_str[SHA256_DIGEST_SIZE * 2 + 1];
    sha256_to_hex(digest, hex_str);

    strncpy(machine_code, hex_str, max_len - 1);
    machine_code[max_len - 1] = '\0';

    return TRUE;
}

static void generate_code_seq(char *seq) {
    uint32_t random_val = 0;
    HCRYPTPROV hProvider = 0;

    if (CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProvider, sizeof(random_val), (BYTE *)&random_val);
        CryptReleaseContext(hProvider, 0);
    } else {
        random_val = (uint32_t)GetTickCount() ^ (uint32_t)time(NULL);
    }

    snprintf(seq, CODE_SEQ_LEN + 1, "%08x", random_val);
}

static BOOL compute_signature(const char *machine_code, uint32_t gen_time, uint32_t expire_time, const char *code_seq, const char *username, const char *email, char *sig_hex) {
#ifdef ECDSA_SIGN_ENABLED
    char combined[768];
    char safe_username[USERNAME_LEN] = {0};
    char safe_email[EMAIL_LEN] = {0};

    if (username) {
        strncpy(safe_username, username, USERNAME_LEN - 1);
        safe_username[USERNAME_LEN - 1] = '\0';
    }
    if (email) {
        strncpy(safe_email, email, EMAIL_LEN - 1);
        safe_email[EMAIL_LEN - 1] = '\0';
    }

    memset(combined, 0, sizeof(combined));
    snprintf(combined, sizeof(combined), "%s|%08x|%08x|%s|%s|%s",
             machine_code, gen_time, expire_time,
             code_seq, safe_username, safe_email);

    return ECDSA_SignData((const uint8_t *)combined, strlen(combined), sig_hex);
#else
    (void)machine_code; (void)gen_time; (void)expire_time;
    (void)code_seq; (void)username; (void)email; (void)sig_hex;
    return FALSE;
#endif
}

static size_t build_verify_data(const char *machine_code, uint32_t gen_time, uint32_t expire_time, const char *code_seq, const char *username, const char *email, char *out, size_t out_size) {
    char safe_username[USERNAME_LEN] = {0};
    char safe_email[EMAIL_LEN] = {0};

    if (username) {
        strncpy(safe_username, username, USERNAME_LEN - 1);
        safe_username[USERNAME_LEN - 1] = '\0';
    }
    if (email) {
        strncpy(safe_email, email, EMAIL_LEN - 1);
        safe_email[EMAIL_LEN - 1] = '\0';
    }

    memset(out, 0, out_size);
    return (size_t)snprintf(out, out_size, "%s|%08x|%08x|%s|%s|%s",
                            machine_code, gen_time, expire_time,
                            code_seq, safe_username, safe_email);
}

BOOL GenerateActivationCode(const char *machine_code, uint64_t total_seconds, const char *username, const char *email, char *activation_code, size_t max_len, uint32_t current_time) {
    char sig_hex[ECDSA_SIG_HEX_SIZE] = {0};
    char code_seq[CODE_SEQ_LEN + 1] = {0};
    char payload[256] = {0};
    char hex_code[ACTIVATION_CODE_LEN] = {0};
    uint32_t gen_time = current_time;
    uint32_t expire_time = 0;

    char normalized_machine[MACHINE_CODE_LEN * 2] = {0};
    if (!machine_code || !NormalizeMachineCode(machine_code, normalized_machine, sizeof(normalized_machine))) {
        return FALSE;
    }
    machine_code = normalized_machine;

    generate_code_seq(code_seq);

    if (total_seconds > 0) {
        uint64_t expire_calc = (uint64_t)gen_time + total_seconds;
        expire_time = (uint32_t)expire_calc;
    }

    if (!compute_signature(machine_code, gen_time, expire_time, code_seq, username, email, sig_hex)) {
        return FALSE;
    }

    snprintf(payload, sizeof(payload), "%08x%08x%s%s", gen_time, expire_time, code_seq, sig_hex);

    uint32_t crc = calculate_crc32(payload, strlen(payload));

    snprintf(hex_code, sizeof(hex_code), "%08x%s", crc, payload);

    memset(activation_code, 0, max_len);
    int obf_len = ObfuscateCode(hex_code, activation_code, max_len);

    if (obf_len == 0) {

        strncpy(activation_code, hex_code, max_len - 1);
    }

    return TRUE;
}

static void CleanString(const char *input, char *output, size_t max_len, int tolower_flag, const char *obfuscate_charset) {
    int len = strlen(input);
    int j = 0;
    for (int i = 0; i < len && j < (int)max_len; i++) {

        if (input[i] != '-' && input[i] != ' ' && input[i] != '\t' && input[i] != '\n' && input[i] != '\r') {

            if (IsObfuscatedChar(input[i], obfuscate_charset)) {
                output[j++] = input[i];
            }
            else if (tolower_flag && input[i] >= 'A' && input[i] <= 'Z') {
                output[j++] = input[i] + 32;
            } else {
                output[j++] = input[i];
            }
        }
    }
    if (j >= (int)max_len) {
        j = (int)max_len - 1;
    }
    output[j] = '\0';
}

int ValidateActivationCode(const char *machine_code, const char *username, const char *email, const char *activation_code, uint32_t *out_expire_time, uint32_t current_time, char *out_code_seq) {

    char charset[Obfuscate_CHARSET_LEN + 1];
    GetObfuscateCharset(charset);

    char clean_machine[200] = {0};
    if (!NormalizeMachineCode(machine_code, clean_machine, sizeof(clean_machine))) {
        SecureZeroMemory(charset, sizeof(charset));
        return ACT_INVALID;
    }

    char clean_activation[400];
    char decoded_activation[256];
    memset(clean_activation, 0, sizeof(clean_activation));
    memset(decoded_activation, 0, sizeof(decoded_activation));
    CleanString(activation_code, clean_activation, sizeof(clean_activation), 0, charset);

    const size_t EXPECTED_HEX_LEN = CRC32_LEN + 8 + 8 + CODE_SEQ_LEN + ECDSA_SIG_HEX_LEN;

    int format = DetectCodeFormat(clean_activation, charset);

    if (format == 1) {
        if (DeobfuscateCode(clean_activation, decoded_activation, sizeof(decoded_activation)) == 0) {
            SecureZeroMemory(charset, sizeof(charset));
            return ACT_INVALID;
        }
    } else if (format == 0) {
        strncpy(decoded_activation, clean_activation, sizeof(decoded_activation) - 1);
    } else {
        SecureZeroMemory(charset, sizeof(charset));
        return ACT_INVALID;
    }

    SecureZeroMemory(charset, sizeof(charset));

    char *actual_code = decoded_activation;

    if (strlen(actual_code) != EXPECTED_HEX_LEN) {
        return ACT_INVALID;
    }

    char crc_hex[CRC32_LEN + 1] = {0};
    char payload[256] = {0};
    strncpy(crc_hex, actual_code, CRC32_LEN);
    strncpy(payload, actual_code + CRC32_LEN, strlen(actual_code) - CRC32_LEN);
    crc_hex[CRC32_LEN] = '\0';
    payload[strlen(actual_code) - CRC32_LEN] = '\0';

    uint32_t stored_crc = (uint32_t)strtoul(crc_hex, NULL, 16);
    uint32_t calc_crc = calculate_crc32(payload, strlen(payload));

    if (stored_crc != calc_crc) {
        return ACT_INVALID;
    }

    char gen_hex[9] = {0};
    char expire_hex[9] = {0};
    char code_seq[CODE_SEQ_LEN + 1] = {0};
    strncpy(gen_hex, payload, 8);
    strncpy(expire_hex, payload + 8, 8);
    strncpy(code_seq, payload + 16, CODE_SEQ_LEN);
    gen_hex[8] = '\0';
    expire_hex[8] = '\0';
    code_seq[CODE_SEQ_LEN] = '\0';

    uint32_t gen_time = (uint32_t)strtoul(gen_hex, NULL, 16);
    uint32_t expire_time = (uint32_t)strtoul(expire_hex, NULL, 16);
    const char *sig_part = payload + 16 + CODE_SEQ_LEN;

    if (gen_time > (uint32_t)(current_time + 60) || gen_time == 0) {
        return ACT_INVALID;
    }
    if (gen_time < (uint32_t)(current_time - 365 * 86400 * 10)) {
        return ACT_INVALID;
    }

    char verify_data[768] = {0};
    size_t verify_len = build_verify_data(clean_machine, gen_time, expire_time, code_seq, username, email, verify_data, sizeof(verify_data));
    if (verify_len == 0) {
        return ACT_INVALID;
    }

    if (expire_time > 0 && expire_time < current_time) {
        if (ECDSA_VerifyWithEmbedded((const uint8_t *)verify_data, verify_len, sig_part)) {
            if (out_expire_time) *out_expire_time = expire_time;
            return ACT_EXPIRED_FUTURE;
        }
        return ACT_INVALID;
    }

    if (IsActivationCodeUsed(code_seq)) {
        if (out_expire_time) *out_expire_time = expire_time;
        return ACT_USED;
    }

    if (expire_time > 0 && expire_time < gen_time) {
        return ACT_INVALID;
    }
    if (expire_time > (uint32_t)(current_time + 365 * 86400 * 10)) {
        return ACT_INVALID;
    }

    if (ECDSA_VerifyWithEmbedded((const uint8_t *)verify_data, verify_len, sig_part)) {
        if (out_expire_time) *out_expire_time = expire_time;
        if (out_code_seq) {
            strncpy(out_code_seq, code_seq, CODE_SEQ_LEN);
            out_code_seq[CODE_SEQ_LEN] = '\0';
        }
        return ACT_VALID;
    }

    return ACT_INVALID;
}

BOOL SaveActivationStatus(BOOL activated, const char *machine_code, uint32_t expire_time, const char *username, const char *email, const char *code_seq, uint32_t current_time) {

    char *old_used_codes = NULL;
    int old_used_count = 0;
    int old_total_count = 0;
    size_t old_data_size = 0;
    uint8_t *old_data = NULL;

    if (DecryptLicenseFile(LICENSE_FILE, &old_data, &old_data_size)) {
        if (old_data_size >= BASE_FILE_SIZE) {

            size_t old_used_bytes = 0;
            find_online_footer(old_data, old_data_size, &old_used_bytes);
            old_total_count = (int)(old_used_bytes / CODE_SEQ_LEN);
            if (old_total_count > 0) {
                old_used_codes = (char *)malloc(old_used_bytes);
                if (old_used_codes) {

                    memcpy(old_used_codes, old_data + BASE_FILE_SIZE, old_used_bytes);

                    for (int i = 0; i < old_total_count; i++) {
                        if (old_used_codes[i * CODE_SEQ_LEN] != '\0') {
                            old_used_count++;
                        }
                    }
                }
            }
        }
        free(old_data);
        old_data = NULL;
    }

    int need_add = 0;
    if (code_seq && strlen(code_seq) == CODE_SEQ_LEN) {
        if (!IsActivationCodeUsed(code_seq)) {
            need_add = 1;
        }
    }

    int new_total_used = old_used_count + need_add;
    size_t new_data_size = BASE_FILE_SIZE + new_total_used * CODE_SEQ_LEN;

    uint8_t *buffer = (uint8_t *)malloc(new_data_size);
    if (!buffer) {
        if (old_used_codes) free(old_used_codes);
        return FALSE;
    }
    memset(buffer, 0, new_data_size);

    size_t pub_key_len = 0;
    const uint8_t *pub_key = GetEmbeddedPublicKey(&pub_key_len);
    uint8_t combined[512];
    size_t mc_len = strlen(machine_code);
    memset(combined, 0, sizeof(combined));
    memcpy(combined, machine_code, mc_len);
    if (pub_key && pub_key_len > 0) {
        memcpy(combined + mc_len, pub_key, pub_key_len);
    }

    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_hash(combined, mc_len + pub_key_len, digest);

    uint8_t status = activated ? 1 : 0;
    uint32_t last_seen_time = current_time;

    int offset = 0;
    memcpy(buffer + offset, &status, sizeof(uint8_t));           offset += sizeof(uint8_t);
    memcpy(buffer + offset, &expire_time, sizeof(uint32_t));       offset += sizeof(uint32_t);
    memcpy(buffer + offset, &last_seen_time, sizeof(uint32_t));    offset += sizeof(uint32_t);

    char buf_username[USERNAME_LEN] = {0};
    char buf_email[EMAIL_LEN] = {0};
    if (username) strncpy(buf_username, username, USERNAME_LEN - 1);
    if (email) strncpy(buf_email, email, EMAIL_LEN - 1);
    memcpy(buffer + offset, buf_username, USERNAME_LEN);          offset += USERNAME_LEN;
    memcpy(buffer + offset, buf_email, EMAIL_LEN);                 offset += EMAIL_LEN;
    memcpy(buffer + offset, digest, SHA256_DIGEST_SIZE);           offset += SHA256_DIGEST_SIZE;

    if (old_used_codes) {
        for (int i = 0; i < old_total_count; i++) {
            if (old_used_codes[i * CODE_SEQ_LEN] != '\0') {
                memcpy(buffer + offset, old_used_codes + i * CODE_SEQ_LEN, CODE_SEQ_LEN);
                offset += CODE_SEQ_LEN;
            }
        }
    }

    if (need_add && code_seq) {
        memcpy(buffer + offset, code_seq, CODE_SEQ_LEN);
        offset += CODE_SEQ_LEN;
    }

    BOOL result = EncryptLicenseFile(buffer, new_data_size, LICENSE_FILE);

    free(buffer);
    if (old_used_codes) free(old_used_codes);

    return result;
}

BOOL SaveOnlineActivation(const char *activation_code, const char *machine_code,
                          uint32_t expire_time, const char *username,
                          const char *email, uint32_t current_time) {
    if (!activation_code || !*activation_code || !machine_code) return FALSE;

    char *old_used_codes = NULL;
    int old_total_count = 0;
    uint8_t *old_data = NULL;
    size_t old_data_size = 0;

    if (DecryptLicenseFile(LICENSE_FILE, &old_data, &old_data_size)) {
        if (old_data_size >= BASE_FILE_SIZE) {
            size_t old_used_bytes = 0;
            find_online_footer(old_data, old_data_size, &old_used_bytes);
            old_total_count = (int)(old_used_bytes / CODE_SEQ_LEN);
            if (old_total_count > 0) {
                old_used_codes = (char *)malloc(old_used_bytes);
                if (old_used_codes) {
                    memcpy(old_used_codes, old_data + BASE_FILE_SIZE, old_used_bytes);
                } else {
                    old_total_count = 0;
                }
            }
        }
        free(old_data);
    }

    size_t new_data_size = BASE_FILE_SIZE
                         + (size_t)old_total_count * CODE_SEQ_LEN
                         + ONLINE_FOOTER_SIZE;
    uint8_t *buffer = (uint8_t *)malloc(new_data_size);
    if (!buffer) {
        if (old_used_codes) free(old_used_codes);
        return FALSE;
    }
    memset(buffer, 0, new_data_size);

    uint8_t digest[SHA256_DIGEST_SIZE];
    compute_binding_digest(ACT_SOURCE_ONLINE, machine_code, digest);

    int offset = 0;
    uint8_t status = ACT_SOURCE_ONLINE;
    uint32_t last_seen_time = current_time;
    memcpy(buffer + offset, &status, sizeof(uint8_t));        offset += sizeof(uint8_t);
    memcpy(buffer + offset, &expire_time, sizeof(uint32_t));  offset += sizeof(uint32_t);
    memcpy(buffer + offset, &last_seen_time, sizeof(uint32_t)); offset += sizeof(uint32_t);

    char buf_username[USERNAME_LEN] = {0};
    char buf_email[EMAIL_LEN] = {0};
    if (username) strncpy(buf_username, username, USERNAME_LEN - 1);
    if (email) strncpy(buf_email, email, EMAIL_LEN - 1);
    memcpy(buffer + offset, buf_username, USERNAME_LEN);      offset += USERNAME_LEN;
    memcpy(buffer + offset, buf_email, EMAIL_LEN);            offset += EMAIL_LEN;
    memcpy(buffer + offset, digest, SHA256_DIGEST_SIZE);      offset += SHA256_DIGEST_SIZE;

    if (old_used_codes) {
        memcpy(buffer + offset, old_used_codes, (size_t)old_total_count * CODE_SEQ_LEN);
        offset += old_total_count * CODE_SEQ_LEN;
        free(old_used_codes);
    }

    memcpy(buffer + offset, ONLINE_FOOTER_MAGIC, 4);           offset += 4;
    strncpy((char *)(buffer + offset), activation_code, ONLINE_CODE_STORE_LEN - 1);
    offset += ONLINE_CODE_STORE_LEN;
    memcpy(buffer + offset, &last_seen_time, sizeof(uint32_t)); offset += 4;

    BOOL result = EncryptLicenseFile(buffer, new_data_size, LICENSE_FILE);
    free(buffer);
    return result;
}

BOOL LoadOnlineAuth(char *code, size_t code_len, uint32_t *last_verify) {
    if (code && code_len) code[0] = '\0';
    if (last_verify) *last_verify = 0;

    uint8_t *data = NULL;
    size_t data_size = 0;
    if (!DecryptLicenseFile(LICENSE_FILE, &data, &data_size)) {
        return FALSE;
    }

    size_t used_size = 0;
    const uint8_t *footer = find_online_footer(data, data_size, &used_size);
    BOOL ok = FALSE;
    if (footer) {
        const char *stored_code = (const char *)(footer + 4);
        if (code && code_len) {
            strncpy(code, stored_code, code_len - 1);
            code[code_len - 1] = '\0';
        }
        if (last_verify) {
            memcpy(last_verify, footer + 4 + ONLINE_CODE_STORE_LEN, sizeof(uint32_t));
        }
        ok = TRUE;
    }
    free(data);
    return ok;
}

int GetActivationSource(void) {
    uint8_t *data = NULL;
    size_t data_size = 0;
    if (!DecryptLicenseFile(LICENSE_FILE, &data, &data_size)) {
        return ACT_SOURCE_NONE;
    }
    int source = ACT_SOURCE_NONE;
    if (data_size >= 1 && (data[0] == ACT_SOURCE_OFFLINE || data[0] == ACT_SOURCE_ONLINE)) {
        source = (int)data[0];
    }
    free(data);
    return source;
}

BOOL ClearOnlineActivation(void) {
    uint8_t *data = NULL;
    size_t data_size = 0;
    if (!DecryptLicenseFile(LICENSE_FILE, &data, &data_size)) {
        return TRUE;
    }
    if (data_size < BASE_FILE_SIZE || data[0] != ACT_SOURCE_ONLINE) {
        free(data);
        return TRUE;
    }

    size_t used_size = 0;
    find_online_footer(data, data_size, &used_size);
    int used_count = (int)(used_size / CODE_SEQ_LEN);

    size_t new_size = BASE_FILE_SIZE + (size_t)used_count * CODE_SEQ_LEN;
    uint8_t *buffer = (uint8_t *)malloc(new_size ? new_size : 1);
    if (!buffer) { free(data); return FALSE; }
    memset(buffer, 0, new_size);

    char machine[MACHINE_CODE_LEN] = {0};
    GenerateMachineCode(machine, sizeof(machine));
    uint8_t digest[SHA256_DIGEST_SIZE];
    compute_binding_digest(ACT_SOURCE_ONLINE, machine, digest);

    memcpy(buffer + 137, digest, SHA256_DIGEST_SIZE);
    if (used_count > 0) {
        memcpy(buffer + BASE_FILE_SIZE, data + BASE_FILE_SIZE,
               (size_t)used_count * CODE_SEQ_LEN);
    }
    free(data);

    BOOL result = EncryptLicenseFile(buffer, new_size, LICENSE_FILE);
    free(buffer);
    return result;
}

BOOL LoadActivationStatus(char *machine_code, uint32_t *expire_time, char *username, char *email) {

    uint8_t *data = NULL;
    size_t data_size = 0;

    if (!DecryptLicenseFile(LICENSE_FILE, &data, &data_size)) {

        return FALSE;
    }

    if (data_size < BASE_FILE_SIZE) {
        free(data);
        return FALSE;
    }

    uint8_t status = data[0];
    uint32_t stored_expire = *(uint32_t*)(data + 1);
    uint32_t stored_last_seen = *(uint32_t*)(data + 5);
    uint8_t *stored_digest = data + 137;
    char *stored_username = (char*)(data + 9);
    char *stored_email = (char*)(data + 73);

    if (status != ACT_SOURCE_OFFLINE && status != ACT_SOURCE_ONLINE) {
        free(data);
        return FALSE;
    }

    uint8_t current_digest[SHA256_DIGEST_SIZE];
    compute_binding_digest((int)status, machine_code, current_digest);

    if (memcmp(stored_digest, current_digest, SHA256_DIGEST_SIZE) != 0) {
        free(data);
        return FALSE;
    }

    if (expire_time) *expire_time = stored_expire;
    if (username) {
        strncpy(username, stored_username, USERNAME_LEN - 1);
        username[USERNAME_LEN - 1] = '\0';
    }
    if (email) {
        strncpy(email, stored_email, EMAIL_LEN - 1);
        email[EMAIL_LEN - 1] = '\0';
    }

    free(data);
    return TRUE;
}

BOOL CheckTimeRollback(uint32_t *out_last_seen_time, uint32_t current_time) {
    uint32_t file_last_seen = 0;

    uint8_t *data = NULL;
    size_t data_size = 0;

    if (DecryptLicenseFile(LICENSE_FILE, &data, &data_size)) {
        if (data_size >= BASE_FILE_SIZE) {
            uint8_t status = data[0];
            if (status != ACT_SOURCE_OFFLINE && status != ACT_SOURCE_ONLINE) {
                file_last_seen = 0;
            } else {
                file_last_seen = *(uint32_t*)(data + 5);
            }
        }
        free(data);
    }

    if (file_last_seen == 0) {
        if (out_last_seen_time) *out_last_seen_time = 0;
        return TRUE;
    }

    if (current_time < file_last_seen) {
        if (out_last_seen_time) *out_last_seen_time = file_last_seen;
        return FALSE;
    }

    if (out_last_seen_time) *out_last_seen_time = file_last_seen;
    return TRUE;
}

void UpdateLastSeenTime(uint32_t current_time) {

    uint8_t *data = NULL;
    size_t data_size = 0;

    if (!DecryptLicenseFile(LICENSE_FILE, &data, &data_size)) {
        return;
    }

    if (data_size >= BASE_FILE_SIZE) {
        uint8_t status = data[0];
        uint32_t stored_last_seen = *(uint32_t*)(data + 5);

        if (status == ACT_SOURCE_OFFLINE || status == ACT_SOURCE_ONLINE) {

            if (current_time > stored_last_seen) {

                memcpy(data + 5, &current_time, sizeof(uint32_t));

                EncryptLicenseFile(data, data_size, LICENSE_FILE);
            }
        }
    }

    free(data);
}

void ClearActivationStatus() {
    wchar_t abs_path[MAX_PATH] = {0};
    MakeAbsolutePath(LICENSE_FILE, abs_path);
    if (_wremove(abs_path) != 0) {

        Sleep(100);
        _wremove(abs_path);
    }
}

BOOL IsLicenseExpired(uint32_t expire_time, uint32_t current_time) {
    if (expire_time == 0) return FALSE;
    return current_time > expire_time;
}

int GetRemainingDays(uint32_t expire_time, uint32_t current_time) {
    if (expire_time == 0) return -1;
    int64_t diff = (int64_t)expire_time - (int64_t)current_time;
    if (diff <= 0) return 0;
    return (int)(diff / 86400);
}

uint32_t GetNtpVerifiedTime(uint32_t fallback_time) {
    uint32_t ntp_time = 0;

    if (GetNtpTime(&ntp_time)) {
        return ntp_time;
    }

    return fallback_time;
}

uint64_t LicenseTimeToSeconds(const LicenseTime* time) {
    if (!time) return 0;

    if (time->years == 0 && time->months == 0 && time->days == 0 &&
        time->hours == 0 && time->minutes == 0 && time->seconds == 0) {
        return 0;
    }
    uint64_t total = 0;
    total += (uint64_t)time->years * SECONDS_PER_YEAR;
    total += (uint64_t)time->months * SECONDS_PER_MONTH;
    total += (uint64_t)time->days * SECONDS_PER_DAY;
    total += (uint64_t)time->hours * SECONDS_PER_HOUR;
    total += (uint64_t)time->minutes * SECONDS_PER_MINUTE;
    total += (uint64_t)time->seconds;
    return total;
}

void FormatTotalSeconds(uint64_t seconds, char* buf, size_t max_len) {
    if (!buf || max_len == 0) return;
    if (seconds == 0) {
        strncpy(buf, "永久", max_len - 1);
        buf[max_len - 1] = '\0';
        return;
    }

    int years = (int)(seconds / SECONDS_PER_YEAR);
    uint64_t remaining = seconds % SECONDS_PER_YEAR;

    int months = (int)(remaining / SECONDS_PER_MONTH);
    remaining = remaining % SECONDS_PER_MONTH;

    int days = (int)(remaining / SECONDS_PER_DAY);
    remaining = remaining % SECONDS_PER_DAY;

    int hours = (int)(remaining / SECONDS_PER_HOUR);
    remaining = remaining % SECONDS_PER_HOUR;

    int minutes = (int)(remaining / SECONDS_PER_MINUTE);
    int secs = (int)(remaining % SECONDS_PER_MINUTE);

    char temp[256];
    int len = 0;

    if (years > 0) len += snprintf(temp + len, sizeof(temp) - len, "%d年", years);
    if (months > 0) len += snprintf(temp + len, sizeof(temp) - len, "%d月", months);
    if (days > 0) len += snprintf(temp + len, sizeof(temp) - len, "%d天", days);
    if (hours > 0) len += snprintf(temp + len, sizeof(temp) - len, "%d小时", hours);
    if (minutes > 0) len += snprintf(temp + len, sizeof(temp) - len, "%d分", minutes);
    if (secs > 0 || len == 0) len += snprintf(temp + len, sizeof(temp) - len, "%d秒", secs);

    strncpy(buf, temp, max_len - 1);
    buf[max_len - 1] = '\0';
}

void FormatExpireTime(uint32_t expire_time, char *buf, size_t max_len) {
    if (expire_time == 0) {
        strncpy(buf, "永久授权", max_len - 1);
        buf[max_len - 1] = '\0';
        return;
    }
    time_t t = (time_t)expire_time;
    struct tm tm_info_buf;
    struct tm *tm_info = &tm_info_buf;

    if (localtime_s(tm_info, &t) == 0) {
        strftime(buf, max_len, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(buf, "未知", max_len - 1);
        buf[max_len - 1] = '\0';
    }
}

static int compare_times(uint32_t t1, uint32_t t2) {
    if (t1 > t2 + NTP_TIME_TOLERANCE) return 1;
    if (t1 + NTP_TIME_TOLERANCE < t2) return -1;
    return 0;
}

BOOL VerifyTimeIntegrity(const char *machine_code, uint32_t *verified_time, int *time_source) {
    uint32_t local_time = (uint32_t)time(NULL);
    uint32_t ntp_time = 0;
    uint32_t max_anchor_time = 0;

    if (time_source) *time_source = TIME_SOURCE_LOCAL;

    if (GetNtpTime(&ntp_time)) {
        int cmp = compare_times(local_time, ntp_time);

        if (cmp > 0) {
            if (verified_time) *verified_time = ntp_time;
            if (time_source) *time_source = TIME_SOURCE_NTP;

            if (CheckTimeAnchors(machine_code, ntp_time, &max_anchor_time)) {
                UpdateTimeAnchors(machine_code, ntp_time);
                return TRUE;
            }
            return FALSE;
        }
        else if (cmp < 0) {
            if (verified_time) *verified_time = ntp_time;
            if (time_source) *time_source = TIME_SOURCE_NTP;
            return FALSE;
        }
        else {
            if (verified_time) *verified_time = local_time;
            if (time_source) *time_source = TIME_SOURCE_NTP;
            UpdateTimeAnchors(machine_code, local_time);
            return TRUE;
        }
    }

    if (!CheckTimeAnchors(machine_code, local_time, &max_anchor_time)) {
        if (verified_time) *verified_time = max_anchor_time;
        if (time_source) *time_source = TIME_SOURCE_ANCHOR;
        return FALSE;
    }

    if (verified_time) *verified_time = local_time;
    if (time_source) *time_source = TIME_SOURCE_LOCAL;
    UpdateTimeAnchors(machine_code, local_time);
    return TRUE;
}

BOOL VerifyTimeIntegrityWithTime(const char *machine_code, uint32_t pre_synced_time, uint32_t *verified_time, int *time_source) {
    uint32_t local_time = (uint32_t)time(NULL);
    uint32_t max_anchor_time = 0;

    if (time_source) *time_source = TIME_SOURCE_LOCAL;

    int cmp = compare_times(local_time, pre_synced_time);

    if (cmp > 0) {
        if (verified_time) *verified_time = pre_synced_time;
        if (time_source) *time_source = TIME_SOURCE_NTP;

        if (CheckTimeAnchors(machine_code, pre_synced_time, &max_anchor_time)) {
            UpdateTimeAnchors(machine_code, pre_synced_time);
            return TRUE;
        }
        return FALSE;
    }
    else if (cmp < 0) {
        if (verified_time) *verified_time = pre_synced_time;
        if (time_source) *time_source = TIME_SOURCE_NTP;
        return FALSE;
    }
    else {
        if (verified_time) *verified_time = local_time;
        if (time_source) *time_source = TIME_SOURCE_NTP;
        UpdateTimeAnchors(machine_code, local_time);
        return TRUE;
    }
}

BOOL InitializeTimeProtection(const char *machine_code, uint32_t current_time) {

    UpdateTimeAnchors(machine_code, current_time);
    return TRUE;
}

static void GenerateKeyStream(uint8_t *output, size_t length, const uint8_t *key3, uint32_t seed) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) {
        S[i] = (uint8_t)i;
    }

    uint32_t j = 0;
    for (int i = 0; i < 256; i++) {
        uint32_t seed_part = (seed >> (i % 4 * 8)) & 0xFF;
        j = (j + S[i] + key3[i % 8] + seed_part) & 0xFF;
        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    uint32_t idx_i = 0, idx_j = 0;
    for (size_t n = 0; n < length; n++) {
        idx_i = (idx_i + 1) & 0xFF;
        idx_j = (idx_j + S[idx_i]) & 0xFF;

        uint8_t temp = S[idx_i];
        S[idx_i] = S[idx_j];
        S[idx_j] = temp;

        output[n] = S[(S[idx_i] + S[idx_j]) & 0xFF];
    }
}

static void EncryptData(uint8_t *data, size_t length, uint32_t seed) {
    uint8_t key1[FILE_KEY1_LEN], key2[FILE_KEY2_LEN], key3[FILE_KEY3_LEN];
    GetFileKey1(key1);
    GetFileKey2(key2);
    GetFileKey3(key3);

    uint8_t *keystream = (uint8_t *)malloc(length);

    if (!keystream) {
        SecureZeroMemory(key1, sizeof(key1));
        SecureZeroMemory(key2, sizeof(key2));
        SecureZeroMemory(key3, sizeof(key3));
        return;
    }

    for (size_t i = 0; i < length; i++) {
        data[i] ^= key1[i % FILE_KEY1_LEN];
    }

    for (size_t i = length; i > 0; i--) {
        data[i - 1] ^= key2[(i - 1) % FILE_KEY2_LEN];
    }

    GenerateKeyStream(keystream, length, key3, seed);
    for (size_t i = 0; i < length; i++) {
        data[i] ^= keystream[i];
    }

    free(keystream);
    SecureZeroMemory(key1, sizeof(key1));
    SecureZeroMemory(key2, sizeof(key2));
    SecureZeroMemory(key3, sizeof(key3));
}

static void DecryptData(uint8_t *data, size_t length, uint32_t seed) {
    uint8_t key1[FILE_KEY1_LEN], key2[FILE_KEY2_LEN], key3[FILE_KEY3_LEN];
    GetFileKey1(key1);
    GetFileKey2(key2);
    GetFileKey3(key3);

    uint8_t *keystream = (uint8_t *)malloc(length);

    if (!keystream) {
        SecureZeroMemory(key1, sizeof(key1));
        SecureZeroMemory(key2, sizeof(key2));
        SecureZeroMemory(key3, sizeof(key3));
        return;
    }

    GenerateKeyStream(keystream, length, key3, seed);
    for (size_t i = 0; i < length; i++) {
        data[i] ^= keystream[i];
    }

    for (size_t i = length; i > 0; i--) {
        data[i - 1] ^= key2[(i - 1) % FILE_KEY2_LEN];
    }

    for (size_t i = 0; i < length; i++) {
        data[i] ^= key1[i % FILE_KEY1_LEN];
    }

    free(keystream);
    SecureZeroMemory(key1, sizeof(key1));
    SecureZeroMemory(key2, sizeof(key2));
    SecureZeroMemory(key3, sizeof(key3));
}

static BOOL LockLicenseFile(void);
static void UnlockLicenseFile(void);
static void SetLicenseFileAttributes(void);
static void SyncLicenseBackups(const uint8_t *encrypted_data, size_t data_size);
static BOOL RestoreFromBackup(uint8_t **out_data, size_t *out_size,
                               char *out_source, BOOL *out_tampered);

static BOOL SaveLicenseToAppData(const uint8_t *data, size_t data_size);
static BOOL LoadLicenseFromAppData(uint8_t **out_data, size_t *out_size);
static BOOL GetAppDataBackupPath(wchar_t *out_path);

static BOOL EncryptLicenseFile(const uint8_t *data, size_t length, const char *filename) {

    uint8_t *encrypted = (uint8_t *)malloc(length + FILE_ENCRYPT_HEADER_SIZE);
    if (!encrypted) {
        SetLicenseFileIOError("内存分配失败：申请 %zu 字节（加密数据缓冲区）时返回 NULL。可能是系统内存不足或堆损坏。",
                              length + FILE_ENCRYPT_HEADER_SIZE);
        return FALSE;
    }

    uint32_t seed = (uint32_t)(time(NULL) * 1000 + GetTickCount());
    if (seed == 0) seed = GetFileKey3Seed();

    memcpy(encrypted, FILE_ENCRYPT_MAGIC, 4);
    encrypted[4] = FILE_ENCRYPT_VERSION;
    memcpy(encrypted + 5, &seed, 4);
    memcpy(encrypted + 9, &length, 4);

    memcpy(encrypted + FILE_ENCRYPT_HEADER_SIZE, data, length);

    EncryptData(encrypted + FILE_ENCRYPT_HEADER_SIZE, length, seed);

    UnlockLicenseFile();

    wchar_t abs_path[MAX_PATH] = {0};
    MakeAbsolutePath(filename, abs_path);

    g_lastLicenseFileIOError[0] = '\0';

    DWORD attrs_before_clear = GetFileAttributesW(abs_path);
    if (attrs_before_clear != INVALID_FILE_ATTRIBUTES) {
        DWORD bad_attrs = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
        if (attrs_before_clear & bad_attrs) {
            DWORD keep_attrs = attrs_before_clear & ~bad_attrs;
            SetFileAttributesW(abs_path, (keep_attrs == 0) ? FILE_ATTRIBUTE_NORMAL : keep_attrs);
        }
    }

    FILE *fp = _wfopen(abs_path, L"wb");
    if (!fp) {

        DWORD win32_err = GetLastError();
        int c_err = errno;

        char utf8_path[MAX_PATH * 4] = {0};
        WideCharToMultiByte(CP_UTF8, 0, abs_path, -1, utf8_path, sizeof(utf8_path), NULL, NULL);

        wchar_t parent_dir[MAX_PATH] = {0};
        wcscpy_s(parent_dir, MAX_PATH, abs_path);
        wchar_t *last_slash = wcsrchr(parent_dir, L'\\');
        if (last_slash) {
            *last_slash = L'\0';
        }
        DWORD parent_attr = GetFileAttributesW(parent_dir);
        BOOL parent_exists = (parent_attr != INVALID_FILE_ATTRIBUTES &&
                              (parent_attr & FILE_ATTRIBUTE_DIRECTORY));

        DWORD file_attr = GetFileAttributesW(abs_path);
        BOOL file_is_readonly = FALSE;
        BOOL file_exists = (file_attr != INVALID_FILE_ATTRIBUTES);
        if (file_exists) {
            file_is_readonly = (file_attr & FILE_ATTRIBUTE_READONLY) ? TRUE : FALSE;
        }

        char c_err_desc[256] = {0};
        strerror_s(c_err_desc, sizeof(c_err_desc), c_err);

        wchar_t w_win32_msg[512] = {0};
        char utf8_win32_msg[1024] = {0};
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, win32_err, 0, w_win32_msg, 512, NULL);

        int wlen = (int)wcslen(w_win32_msg);
        while (wlen > 0 && (w_win32_msg[wlen-1] == L'\r' || w_win32_msg[wlen-1] == L'\n')) {
            w_win32_msg[--wlen] = L'\0';
        }
        WideCharToMultiByte(CP_UTF8, 0, w_win32_msg, -1, utf8_win32_msg, sizeof(utf8_win32_msg), NULL, NULL);

        SetLicenseFileIOError(
            "无法创建/写入 license-SkyBox.dat 文件：_wfopen 返回 NULL。\n"
            "  · 目标路径：%s\n"
            "  · 父目录：%s (存在=%s)\n"
            "  · 原文件是否已存在：%s (只读属性=%s)\n"
            "  · Win32 错误码：%lu (0x%08lX) - %s\n"
            "  · C 运行时 errno：%d - %s\n"
            "常见原因与解决方法：\n"
            "  1) 父目录不存在 → 请手工创建该目录，或确保 exe 在可写位置运行；\n"
            "  2) 文件被其他进程占用（如 license-SkyBox.dat 正被数据查看器打开）→ 关闭占用软件后重试；\n"
            "  3) 父目录位于 Program Files / C:\\ 根目录等受保护位置 → 右键程序 → 以管理员身份运行；\n"
            "  4) 文件被设置为只读属性 → 右键 license-SkyBox.dat → 属性 → 取消勾选『只读』；\n"
            "  5) 杀毒软件拦截写入 → 临时关闭杀毒软件或将本程序加入白名单后重试。",
            utf8_path,
            parent_dir[0] ? L"" : L"(无法解析)",
            parent_exists ? "是" : "否",
            file_exists ? "是" : "否",
            file_is_readonly ? "是" : "否",
            win32_err, win32_err,
            utf8_win32_msg[0] ? utf8_win32_msg : "(无系统描述)",
            c_err,
            c_err_desc[0] ? c_err_desc : "(无描述)");

        free(encrypted);
        return FALSE;
    }

    size_t write_size = FILE_ENCRYPT_HEADER_SIZE + length;
    size_t written = fwrite(encrypted, 1, write_size, fp);
    if (written != write_size) {

        DWORD win32_err = GetLastError();
        int c_err = errno;
        char utf8_path[MAX_PATH * 4] = {0};
        WideCharToMultiByte(CP_UTF8, 0, abs_path, -1, utf8_path, sizeof(utf8_path), NULL, NULL);
        char c_err_desc[256] = {0};
        strerror_s(c_err_desc, sizeof(c_err_desc), c_err);

        wchar_t drive_root[8] = {0};
        ULARGE_INTEGER free_bytes = {0};
        BOOL has_disk_info = FALSE;
        if (abs_path[0] && abs_path[1] == L':' && abs_path[2] == L'\\') {
            drive_root[0] = abs_path[0];
            drive_root[1] = L':';
            drive_root[2] = L'\\';
            drive_root[3] = L'\0';
            has_disk_info = GetDiskFreeSpaceExW(drive_root, &free_bytes, NULL, NULL);
        }

        SetLicenseFileIOError(
            "写入 license-SkyBox.dat 时字节数不完整：预期 %zu 字节，实际只写入 %zu 字节。\n"
            "  · 目标路径：%s\n"
            "  · Win32 错误码：%lu  ｜  C 运行时 errno：%d (%s)\n"
            "  · %s所在磁盘可用空间：%s\n"
            "常见原因：\n"
            "  1) 磁盘已满 → 清理磁盘空间后重试；\n"
            "  2) 用户磁盘配额（企业/学校电脑常见）→ 联系管理员解除配额；\n"
            "  3) 写入过程被杀毒软件/安全软件拦截 → 临时关闭后重试；\n"
            "  4) 介质故障（U盘/硬盘坏道）→ 换一个位置存放 exe 再试。",
            write_size, written,
            utf8_path,
            win32_err, c_err, c_err_desc[0] ? c_err_desc : "",
            has_disk_info ? L"" : L"(无法获取)",
            has_disk_info ? "请检查磁盘剩余容量" : "（无法查询磁盘剩余空间）");

        fclose(fp);
        free(encrypted);
        return FALSE;
    }
    fclose(fp);

    SyncLicenseBackups(encrypted, write_size);
    LockLicenseFile();

    free(encrypted);

    return TRUE;
}

static BOOL DecryptLicenseFile(const char *filename, uint8_t **out_data, size_t *out_length) {

    wchar_t abs_path[MAX_PATH] = {0};
    MakeAbsolutePath(filename, abs_path);

    FILE *fp = _wfopen(abs_path, L"rb");

    if (!fp) {
        uint8_t *backup_data = NULL;
        size_t backup_size = 0;
        char source = 'N';
        BOOL tampered = FALSE;

        if (RestoreFromBackup(&backup_data, &backup_size, &source, &tampered) && backup_data) {

            FILE *restore_fp = _wfopen(abs_path, L"wb");
            if (restore_fp) {
                fwrite(backup_data, 1, backup_size, restore_fp);
                fclose(restore_fp);
                SetLicenseFileAttributes();
                LockLicenseFile();
            }

            uint8_t *file_data = backup_data;
            long file_size = (long)backup_size;

            if (file_size <= 0 || file_size > 10 * 1024 * 1024) {
                free(file_data);
                return FALSE;
            }

            if (file_size >= FILE_ENCRYPT_HEADER_SIZE &&
                memcmp(file_data, FILE_ENCRYPT_MAGIC, 4) == 0 &&
                file_data[4] == FILE_ENCRYPT_VERSION) {

                uint32_t seed = 0;
                uint32_t original_length = 0;

                memcpy(&seed, file_data + 5, 4);
                memcpy(&original_length, file_data + 9, 4);

                if (file_size != (long)(FILE_ENCRYPT_HEADER_SIZE + original_length)) {
                    free(file_data);
                    return FALSE;
                }

                DecryptData(file_data + FILE_ENCRYPT_HEADER_SIZE, original_length, seed);

                uint8_t *decrypted = (uint8_t *)malloc(original_length);
                if (!decrypted) {
                    free(file_data);
                    return FALSE;
                }
                memcpy(decrypted, file_data + FILE_ENCRYPT_HEADER_SIZE, original_length);
                free(file_data);

                *out_data = decrypted;
                *out_length = original_length;
                return TRUE;
            } else {

                *out_data = file_data;
                *out_length = file_size;
                return TRUE;
            }
        }

        return FALSE;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 10 * 1024 * 1024) {
        fclose(fp);
        return FALSE;
    }

    uint8_t *file_data = (uint8_t *)malloc(file_size);
    if (!file_data) {
        fclose(fp);
        return FALSE;
    }

    size_t read_size = fread(file_data, 1, file_size, fp);
    fclose(fp);

    if (read_size != (size_t)file_size) {
        free(file_data);
        return FALSE;
    }

    if (file_size >= FILE_ENCRYPT_HEADER_SIZE &&
        memcmp(file_data, FILE_ENCRYPT_MAGIC, 4) == 0 &&
        file_data[4] == FILE_ENCRYPT_VERSION) {

        uint32_t seed = 0;
        uint32_t original_length = 0;

        memcpy(&seed, file_data + 5, 4);
        memcpy(&original_length, file_data + 9, 4);

        if (file_size != (long)(FILE_ENCRYPT_HEADER_SIZE + original_length)) {
            free(file_data);
            return FALSE;
        }

        uint8_t *decrypted = (uint8_t *)malloc(original_length);
        if (!decrypted) {
            free(file_data);
            return FALSE;
        }

        memcpy(decrypted, file_data + FILE_ENCRYPT_HEADER_SIZE, original_length);
        DecryptData(decrypted, original_length, seed);

        free(file_data);
        *out_data = decrypted;
        *out_length = original_length;

        return TRUE;
    } else {

        *out_data = file_data;
        *out_length = file_size;

        return TRUE;
    }
}

static BOOL GetLicenseFullPath(wchar_t *out_path) {
    if (!out_path) return FALSE;

    wchar_t module_path[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, module_path, MAX_PATH);

    wchar_t *last_slash = wcsrchr(module_path, L'\\');
    if (!last_slash) return FALSE;

    *(last_slash + 1) = L'\0';
    return wcscpy_s(out_path, MAX_PATH, module_path) == 0 &&
           wcscat_s(out_path, MAX_PATH, L"license-SkyBox.dat") == 0;
}

static BOOL LockLicenseFile(void) {
    wchar_t full_path[MAX_PATH] = {0};
    if (!GetLicenseFullPath(full_path)) return FALSE;

    if (g_hLicenseFileLock) {
        CloseHandle(g_hLicenseFileLock);
        g_hLicenseFileLock = NULL;
    }

    if (GetFileAttributesW(full_path) == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    g_hLicenseFileLock = CreateFileW(
        full_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    return (g_hLicenseFileLock != INVALID_HANDLE_VALUE && g_hLicenseFileLock != NULL);
}

static void UnlockLicenseFile(void) {
    if (g_hLicenseFileLock) {
        CloseHandle(g_hLicenseFileLock);
        g_hLicenseFileLock = NULL;
    }
}

static BOOL SaveLicenseToRegistry(const uint8_t *data, size_t data_size) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, LICENSE_REG_ROOT, 0, NULL,
                        0, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    LONG result = RegSetValueExW(hKey, LICENSE_REG_VALUE, 0, REG_BINARY,
                                  data, (DWORD)data_size);
    if (result == ERROR_SUCCESS) {

        DWORD flags = 0x4C494331;
        RegSetValueExW(hKey, LICENSE_REG_FLAGS, 0, REG_DWORD,
                        (const BYTE *)&flags, sizeof(flags));
    }

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

static BOOL LoadLicenseFromRegistry(uint8_t **out_data, size_t *out_size) {
    *out_data = NULL;
    *out_size = 0;

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, LICENSE_REG_ROOT, 0,
                      KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    DWORD flags = 0;
    DWORD flags_size = sizeof(flags);
    if (RegQueryValueExW(hKey, LICENSE_REG_FLAGS, NULL, NULL,
                          (BYTE *)&flags, &flags_size) != ERROR_SUCCESS ||
        flags != 0x4C494331) {
        RegCloseKey(hKey);
        return FALSE;
    }

    DWORD data_size = 0;
    if (RegQueryValueExW(hKey, LICENSE_REG_VALUE, NULL, NULL,
                          NULL, &data_size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }

    if (data_size == 0 || data_size > 10 * 1024 * 1024) {
        RegCloseKey(hKey);
        return FALSE;
    }

    uint8_t *data = (uint8_t *)malloc(data_size);
    if (!data) {
        RegCloseKey(hKey);
        return FALSE;
    }

    if (RegQueryValueExW(hKey, LICENSE_REG_VALUE, NULL, NULL,
                          data, &data_size) != ERROR_SUCCESS) {
        free(data);
        RegCloseKey(hKey);
        return FALSE;
    }

    RegCloseKey(hKey);
    *out_data = data;
    *out_size = data_size;
    return TRUE;
}

static BOOL SaveLicenseToAds(const uint8_t *data, size_t data_size) {
    wchar_t full_path[MAX_PATH] = {0};
    if (!GetLicenseFullPath(full_path)) return FALSE;

    wchar_t ads_path[MAX_PATH + 64] = {0};
    wcscpy_s(ads_path, MAX_PATH + 64, full_path);
    wcscat_s(ads_path, MAX_PATH + 64, L":");
    wcscat_s(ads_path, MAX_PATH + 64, L"license-SkyBox");

    HANDLE hFile = CreateFileW(
        ads_path,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written = 0;
    BOOL result = WriteFile(hFile, data, (DWORD)data_size, &written, NULL);
    CloseHandle(hFile);

    return (result && written == data_size);
}

static BOOL LoadLicenseFromAds(uint8_t **out_data, size_t *out_size) {
    *out_data = NULL;
    *out_size = 0;

    wchar_t full_path[MAX_PATH] = {0};
    if (!GetLicenseFullPath(full_path)) return FALSE;

    wchar_t ads_path[MAX_PATH + 64] = {0};
    wcscpy_s(ads_path, MAX_PATH + 64, full_path);
    wcscat_s(ads_path, MAX_PATH + 64, L":");
    wcscat_s(ads_path, MAX_PATH + 64, L"license-SkyBox");

    HANDLE hFile = CreateFileW(
        ads_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    LARGE_INTEGER li_size;
    if (!GetFileSizeEx(hFile, &li_size) || li_size.QuadPart <= 0) {
        CloseHandle(hFile);
        return FALSE;
    }

    uint64_t file_size = (uint64_t)li_size.QuadPart;
    if (file_size > 10 * 1024 * 1024) {
        CloseHandle(hFile);
        return FALSE;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)file_size);
    if (!data) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD read = 0;
    BOOL result = ReadFile(hFile, data, (DWORD)file_size, &read, NULL);
    CloseHandle(hFile);

    if (!result || read != (DWORD)file_size) {
        free(data);
        return FALSE;
    }

    *out_data = data;
    *out_size = (size_t)file_size;
    return TRUE;
}

static BOOL GetAppDataBackupPath(wchar_t *out_path) {
    if (!out_path) return FALSE;

    wchar_t local_app_data[MAX_PATH] = {0};
    if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local_app_data) != S_OK) {

        DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) return FALSE;
    }

    wcscpy_s(out_path, MAX_PATH, local_app_data);
    wcscat_s(out_path, MAX_PATH, L"\\");
    wcscat_s(out_path, MAX_PATH, LICENSE_APPDATA_DIR);

    DWORD attrs = GetFileAttributesW(out_path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {

        if (!CreateDirectoryW(out_path, NULL)) {

        }
    }

    return TRUE;
}

static BOOL SaveLicenseToAppData(const uint8_t *data, size_t data_size) {
    wchar_t dir_path[MAX_PATH] = {0};
    wchar_t file_path[MAX_PATH] = {0};

    if (!GetAppDataBackupPath(dir_path)) return FALSE;

    CreateDirectoryW(dir_path, NULL);

    wcscpy_s(file_path, MAX_PATH, dir_path);
    wcscat_s(file_path, MAX_PATH, L"\\");
    wcscat_s(file_path, MAX_PATH, LICENSE_APPDATA_FILE);

    size_t total_size = 8 + data_size;
    uint8_t *buffer = (uint8_t *)malloc(total_size);
    if (!buffer) return FALSE;

    DWORD magic = LICENSE_APPDATA_MAGIC;
    memcpy(buffer, &magic, 4);

    uint32_t data_size_32 = (uint32_t)data_size;
    memcpy(buffer + 4, &data_size_32, 4);

    memcpy(buffer + 8, data, data_size);

    HANDLE hFile = CreateFileW(
        file_path,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        free(buffer);
        return FALSE;
    }

    DWORD written = 0;
    BOOL result = WriteFile(hFile, buffer, (DWORD)total_size, &written, NULL);
    CloseHandle(hFile);
    free(buffer);

    return (result && written == (DWORD)total_size);
}

static BOOL LoadLicenseFromAppData(uint8_t **out_data, size_t *out_size) {
    *out_data = NULL;
    *out_size = 0;

    wchar_t file_path[MAX_PATH] = {0};

    wchar_t dir_path[MAX_PATH] = {0};
    if (!GetAppDataBackupPath(dir_path)) return FALSE;

    wcscpy_s(file_path, MAX_PATH, dir_path);
    wcscat_s(file_path, MAX_PATH, L"\\");
    wcscat_s(file_path, MAX_PATH, LICENSE_APPDATA_FILE);

    HANDLE hFile = CreateFileW(
        file_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    LARGE_INTEGER li_size;
    if (!GetFileSizeEx(hFile, &li_size) || li_size.QuadPart <= 8) {
        CloseHandle(hFile);
        return FALSE;
    }

    uint64_t file_size = (uint64_t)li_size.QuadPart;
    if (file_size > 10 * 1024 * 1024) {
        CloseHandle(hFile);
        return FALSE;
    }

    uint8_t *raw_data = (uint8_t *)malloc((size_t)file_size);
    if (!raw_data) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD read = 0;
    BOOL result = ReadFile(hFile, raw_data, (DWORD)file_size, &read, NULL);
    CloseHandle(hFile);

    if (!result || read != (DWORD)file_size) {
        free(raw_data);
        return FALSE;
    }

    if (file_size < 8) {
        free(raw_data);
        return FALSE;
    }

    DWORD magic = 0;
    memcpy(&magic, raw_data, 4);
    if (magic != LICENSE_APPDATA_MAGIC) {
        free(raw_data);
        return FALSE;
    }

    uint32_t data_size = 0;
    memcpy(&data_size, raw_data + 4, 4);
    if (data_size == 0 || data_size > 10 * 1024 * 1024 ||
        (uint64_t)data_size + 8 != file_size) {
        free(raw_data);
        return FALSE;
    }

    uint8_t *data = (uint8_t *)malloc(data_size);
    if (!data) {
        free(raw_data);
        return FALSE;
    }

    memcpy(data, raw_data + 8, data_size);
    free(raw_data);

    *out_data = data;
    *out_size = data_size;
    return TRUE;
}

static void SetLicenseFileAttributes(void) {
    wchar_t full_path[MAX_PATH] = {0};
    if (!GetLicenseFullPath(full_path)) return;

    SetFileAttributesW(full_path, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
}

static void SyncLicenseBackups(const uint8_t *encrypted_data, size_t data_size) {

    SaveLicenseToRegistry(encrypted_data, data_size);

    SaveLicenseToAppData(encrypted_data, data_size);

    SaveLicenseToAds(encrypted_data, data_size);

    SetLicenseFileAttributes();
}

static BOOL RestoreFromBackup(uint8_t **out_data, size_t *out_size,
                               char *out_source, BOOL *out_tampered) {
    *out_data = NULL;
    *out_size = 0;
    *out_source = 'N';
    *out_tampered = FALSE;

    if (LoadLicenseFromRegistry(out_data, out_size) && *out_size > 0) {
        *out_source = 'R';
        return TRUE;
    }

    if (LoadLicenseFromAppData(out_data, out_size) && *out_size > 0) {
        *out_source = 'D';
        return TRUE;
    }

    if (LoadLicenseFromAds(out_data, out_size) && *out_size > 0) {
        *out_source = 'A';
        return TRUE;
    }

    *out_tampered = TRUE;
    return FALSE;
}

BOOL InitLicenseBackupDirectory(void) {
    wchar_t dir_path[MAX_PATH] = {0};

    if (!GetAppDataBackupPath(dir_path)) {
        return FALSE;
    }

    DWORD attrs = GetFileAttributesW(dir_path);
    if (attrs != INVALID_FILE_ATTRIBUTES) {

        return TRUE;
    }

    if (CreateDirectoryW(dir_path, NULL)) {
        return TRUE;
    }

    return FALSE;
}
