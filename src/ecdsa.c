#include "ecdsa.h"
#include "key.h"
#include "sha256.h"

#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

BOOL ECDSA_GenerateKeyPair(const char *private_key_path, const char *public_key_path) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL success = FALSE;
    NTSTATUS status;

    if (!private_key_path || !public_key_path) return FALSE;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptGenerateKeyPair(hAlg, &hKey, 256, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptFinalizeKeyPair(hKey, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    {
        uint8_t priv_blob[ECDSA_PRIVKEY_BLOB_SIZE];
        ULONG priv_blob_len = 0;
        status = BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 priv_blob, sizeof(priv_blob), &priv_blob_len, 0);
        if (!BCRYPT_SUCCESS(status) || priv_blob_len != ECDSA_PRIVKEY_BLOB_SIZE) goto cleanup;

        FILE *fp = lic_fopen(private_key_path, "wb");
        if (!fp) goto cleanup;
        if (fwrite(priv_blob, 1, priv_blob_len, fp) != priv_blob_len) {
            fclose(fp);
            goto cleanup;
        }
        fclose(fp);
        SecureZeroMemory(priv_blob, sizeof(priv_blob));
    }

    {
        uint8_t pub_blob[ECDSA_PUBKEY_BLOB_SIZE];
        ULONG pub_blob_len = 0;
        status = BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                 pub_blob, sizeof(pub_blob), &pub_blob_len, 0);
        if (!BCRYPT_SUCCESS(status) || pub_blob_len != ECDSA_PUBKEY_BLOB_SIZE) goto cleanup;

        FILE *fp = lic_fopen(public_key_path, "wb");
        if (!fp) goto cleanup;
        if (fwrite(pub_blob, 1, pub_blob_len, fp) != pub_blob_len) {
            fclose(fp);
            goto cleanup;
        }
        fclose(fp);
    }

    success = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}

BOOL ECDSA_VerifyWithEmbedded(const uint8_t *data, size_t data_len, const char *sig_hex) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL success = FALSE;
    NTSTATUS status;

    size_t pub_key_len = 0;
    const uint8_t *pub_key = GetEmbeddedPublicKey(&pub_key_len);
    if (!pub_key || pub_key_len != ECDSA_PUBKEY_BLOB_SIZE) return FALSE;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey,
                                 (PUCHAR)pub_key, (ULONG)pub_key_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_hash(data, data_len, hash);

    uint8_t sig[ECDSA_SIG_SIZE];
    for (int i = 0; i < ECDSA_SIG_SIZE; i++) {
        unsigned int byte_val;
        if (sscanf(sig_hex + i * 2, "%2x", &byte_val) != 1) goto cleanup;
        sig[i] = (uint8_t)byte_val;
    }

    status = BCryptVerifySignature(hKey, NULL, hash, SHA256_DIGEST_SIZE,
                                   sig, ECDSA_SIG_SIZE, 0);
    success = BCRYPT_SUCCESS(status);

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}
