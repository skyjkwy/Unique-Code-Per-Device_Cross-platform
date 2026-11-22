#include "license.h"
#include "license_dll.h"
#include "platform.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int failures = 0;

static void check(int condition, const char *name) {
    printf("[%s] %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) failures++;
}

int main(void) {
    char machine[MACHINE_CODE_LEN] = {0};
    check(GenerateMachineCode(machine, sizeof(machine)), "generate machine code");
    printf("machine code: %s\n", machine);
    check(strlen(machine) == 64, "machine code length");

    char obfuscated[MACHINE_CODE_LEN * 2] = {0};
    char normalized[MACHINE_CODE_LEN * 2] = {0};
    check(ObfuscateMachineCode(machine, obfuscated, sizeof(obfuscated)),
          "obfuscate machine code");
    check(NormalizeMachineCode(obfuscated, normalized, sizeof(normalized)),
          "normalize obfuscated machine code");
    check(strcmp(normalized, machine) == 0, "machine code round-trip");

    uint32_t now = (uint32_t)time(NULL);
    LicenseTime one_day = {0, 0, 1, 0, 0, 0};
    uint64_t seconds = LicenseTimeToSeconds(&one_day);
    check(seconds == 86400, "duration conversion");

    char code[ACTIVATION_CODE_LEN] = {0};
    check(GenerateActivationCode(machine, seconds, "tester", "test@example.com",
                                 code, sizeof(code), now),
          "generate activation code");
    check(strlen(code) > 0, "activation code not empty");

    uint32_t expire = 0;
    char seq[CODE_SEQ_LEN + 1] = {0};
    int result = ValidateActivationCode(machine, "tester", "test@example.com",
                                        code, &expire, now + 10, seq);
    check(result == ACT_VALID, "validate activation code");
    check(expire == now + (uint32_t)seconds, "expire time matches");
    check(strlen(seq) == CODE_SEQ_LEN, "code sequence extracted");

    result = ValidateActivationCode(machine, "other-user", "test@example.com",
                                    code, &expire, now + 10, seq);
    check(result != ACT_VALID, "reject wrong username");

    result = ValidateActivationCode(machine, "tester", "other@example.com",
                                    code, &expire, now + 10, seq);
    check(result != ACT_VALID, "reject wrong email");

    char tampered[ACTIVATION_CODE_LEN] = {0};
    lic_strcpy(tampered, sizeof(tampered), code);
    size_t len = strlen(tampered);
    if (len > 0) {
        tampered[len - 1] = (tampered[len - 1] == 'z') ? 'y' : 'z';
    }
    result = ValidateActivationCode(machine, "tester", "test@example.com",
                                    tampered, &expire, now + 10, seq);
    check(result != ACT_VALID, "reject tampered code");

    char permanent[ACTIVATION_CODE_LEN] = {0};
    check(GenerateActivationCode(machine, 0, "tester", "",
                                 permanent, sizeof(permanent), now),
          "generate permanent code");
    expire = 12345;
    result = ValidateActivationCode(machine, "tester", "",
                                    permanent, &expire, now + 10, seq);
    check(result == ACT_VALID && expire == 0, "validate permanent code");

    char time_buf[64] = {0};
    FormatExpireTime(now, time_buf, sizeof(time_buf));
    check(time_buf[0] != '\0', "format expire time");

    char duration_buf[128] = {0};
    FormatTotalSeconds(seconds, duration_buf, sizeof(duration_buf));
    printf("duration: %s\n", duration_buf);
    check(duration_buf[0] != '\0', "format duration");

    char license_path[LICENSE_PATH_MAX] = {0};
    check(lic_resolve_exe_relative("license-SkyBox.dat", license_path, sizeof(license_path)) == 0,
          "resolve license path");

    check(SaveActivationStatus(TRUE, machine, expire, "tester", "test@example.com",
                               seq, now + 10),
          "save activation status");

    char loaded_user[USERNAME_LEN] = {0};
    char loaded_email[EMAIL_LEN] = {0};
    uint32_t loaded_expire = 0;
    check(LoadActivationStatus(machine, &loaded_expire, loaded_user, loaded_email),
          "load activation status");
    check(loaded_expire == expire, "loaded expire matches");
    check(strcmp(loaded_user, "tester") == 0, "loaded username matches");
    check(strcmp(loaded_email, "test@example.com") == 0, "loaded email matches");

    LicenseFileInfo file_info;
    check(License_ReadFileInfo(license_path, &file_info) == LICENSE_OK,
          "read license file info");
    check(file_info.valid && file_info.encrypted, "license file is valid and encrypted");
    check(file_info.binding_ok == 1, "license binding matches");
    check(file_info.used_code_count == 1, "license file records used code");
    check(strcmp(file_info.used_codes[0], seq) == 0, "used code matches");

    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;
    check(License_DecryptFile(license_path, &decrypted, &decrypted_len) == LICENSE_OK,
          "decrypt license file");
    check(decrypted_len >= LICENSE_BASE_SIZE, "decrypted size valid");
    free(decrypted);

    ClearActivationStatus();
    check(!lic_file_exists(license_path), "clear removes primary license file");
    check(!LoadActivationStatus(machine, &loaded_expire, loaded_user, loaded_email),
          "clear removes backups as well");

    const char *abc = "abc";
    uint8_t digest[SHA256_DIGEST_SIZE];
    char hex[SHA256_DIGEST_SIZE * 2 + 1];
    sha256_hash((const uint8_t *)abc, 3, digest);
    sha256_to_hex(digest, hex);
    check(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
          "sha256 known vector");

    printf("\n%s (%d failure%s)\n", failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
