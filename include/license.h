#ifndef LICENSE_H
#define LICENSE_H

#include "platform.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define MACHINE_CODE_LEN 65

#define ACTIVATION_CODE_LEN 161

#define ECDSA_SIG_HEX_LEN 128

#define USERNAME_LEN 64

#define EMAIL_LEN 64

#define CODE_SEQ_LEN 8

#define LICENSE_BASE_SIZE 169

#define CRC32_LEN 8

#define ACT_VALID 0

#define ACT_USED 1

#define ACT_INVALID 2

#define ACT_EXPIRED_FUTURE 3

#define ACT_TIME_TAMPERED 4

#define NTP_TIME_TOLERANCE 60

#define SECONDS_PER_MINUTE  60
#define SECONDS_PER_HOUR    3600
#define SECONDS_PER_DAY     86400
#define SECONDS_PER_MONTH   (SECONDS_PER_DAY * 30)
#define SECONDS_PER_YEAR    (SECONDS_PER_DAY * 365)

#define LICENSE_MAX_USED_CODES 256

typedef struct {
    int years;
    int months;
    int days;
    int hours;
    int minutes;
    int seconds;
} LicenseTime;

typedef struct {
    int valid;
    int encrypted;
    int binding_ok;
    int source;
    uint32_t expire_time;
    uint32_t last_seen_time;
    char username[USERNAME_LEN];
    char email[EMAIL_LEN];
    uint8_t binding_digest[32];
    char binding_digest_hex[65];
    int used_code_count;
    char used_codes[LICENSE_MAX_USED_CODES][CODE_SEQ_LEN + 1];
    char online_code[21];
    uint32_t online_last_verify;
    uint32_t raw_size;
} LicenseFileInfo;

#ifdef __cplusplus
extern "C" {
#endif

uint64_t LicenseTimeToSeconds(const LicenseTime* time);

void FormatTotalSeconds(uint64_t seconds, char* buf, size_t max_len);

lic_bool GenerateMachineCode(char *machine_code, size_t max_len);

lic_bool ObfuscateMachineCode(const char *original_machine_code, char *obfuscated_out, size_t max_len);

lic_bool DeobfuscateMachineCode(const char *input_machine_code, char *deobfuscated_out, size_t max_len);

lic_bool NormalizeMachineCode(const char *input_machine_code, char *normalized_out, size_t max_len);

lic_bool GenerateActivationCode(const char *machine_code, uint64_t total_seconds, const char *username, const char *email, char *activation_code, size_t max_len, uint32_t current_time);

int ValidateActivationCode(const char *machine_code, const char *username, const char *email, const char *activation_code, uint32_t *out_expire_time, uint32_t current_time, char *out_code_seq);

lic_bool SaveActivationStatus(lic_bool activated, const char *machine_code, uint32_t expire_time, const char *username, const char *email, const char *code_seq, uint32_t current_time);

lic_bool LoadActivationStatus(char *machine_code, uint32_t *expire_time, char *username, char *email);

lic_bool IsLicenseExpired(uint32_t expire_time, uint32_t current_time);

int GetRemainingDays(uint32_t expire_time, uint32_t current_time);

void FormatExpireTime(uint32_t expire_time, char *buf, size_t max_len);

lic_bool CheckTimeRollback(uint32_t *out_last_seen_time, uint32_t current_time);

void UpdateLastSeenTime(uint32_t current_time);

void ClearActivationStatus(void);

lic_bool IsActivationCodeUsed(const char *code_seq);

void MarkActivationCodeUsed(const char *code_seq);

lic_bool SaveOnlineActivation(const char *activation_code, const char *machine_code,
                              uint32_t expire_time, const char *username,
                              const char *email, uint32_t current_time);

lic_bool LoadOnlineAuth(char *code, size_t code_len, uint32_t *last_verify);

int GetActivationSource(void);

lic_bool ClearOnlineActivation(void);

lic_bool VerifyTimeIntegrity(const char *machine_code, uint32_t *verified_time, int *time_source);

lic_bool VerifyTimeIntegrityWithTime(const char *machine_code, uint32_t pre_synced_time, uint32_t *verified_time, int *time_source);

lic_bool InitializeTimeProtection(const char *machine_code, uint32_t current_time);

uint32_t GetNtpVerifiedTime(uint32_t fallback_time);

lic_bool InitLicenseBackupDirectory(void);

int License_DecryptFile(const char *path, uint8_t **out_data, size_t *out_len);

int License_ReadFileInfo(const char *path, LicenseFileInfo *info);

#ifdef __cplusplus
}
#endif

#endif
