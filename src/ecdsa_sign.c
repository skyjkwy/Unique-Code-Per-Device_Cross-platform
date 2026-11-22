#include "ecdsa.h"
#include "key.h"
#include "sha256.h"
#include "embedded_privkey.h"
#include <bcrypt.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

BOOL ECDSA_SignData(const uint8_t *data, size_t data_len, char *sig_hex) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL success = FALSE;
    NTSTATUS status;

    if (sizeof(EMBEDDED_PRIVATE_KEY) != ECDSA_PRIVKEY_BLOB_SIZE) return FALSE;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB, &hKey,
                                 (PUCHAR)EMBEDDED_PRIVATE_KEY,
                                 (ULONG)sizeof(EMBEDDED_PRIVATE_KEY), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_hash(data, data_len, hash);

    uint8_t sig[ECDSA_SIG_SIZE];
    ULONG sig_len = ECDSA_SIG_SIZE;
    status = BCryptSignHash(hKey, NULL, hash, SHA256_DIGEST_SIZE,
                            sig, sig_len, &sig_len, 0);
    if (!BCRYPT_SUCCESS(status) || sig_len != ECDSA_SIG_SIZE) goto cleanup;

    for (int i = 0; i < ECDSA_SIG_SIZE; i++) {
        sprintf(sig_hex + i * 2, "%02x", sig[i]);
    }
    sig_hex[ECDSA_SIG_HEX_SIZE - 1] = '\0';
    success = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}
