#include "sha256.h"
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

void sha256_init(SHA256_CTX *ctx) {
    ctx->handle = NULL;
    ctx->inited = FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status == 0) {
        status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        if (status == 0) {
            ctx->handle = hHash;
            ctx->inited = TRUE;
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
}

void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    if (ctx->inited && ctx->handle) {
        BCryptHashData(ctx->handle, (PUCHAR)data, (ULONG)len, 0);
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
    if (ctx->inited && ctx->handle) {
        ULONG result = 0;
        BCryptFinishHash(ctx->handle, digest, SHA256_DIGEST_SIZE, 0);
        BCryptDestroyHash(ctx->handle);
        ctx->handle = NULL;
        ctx->inited = FALSE;
    }
}

void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status == 0) {
        status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        if (status == 0) {
            BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
            BCryptFinishHash(hHash, digest, SHA256_DIGEST_SIZE, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
}

void sha256_to_hex(const uint8_t digest[SHA256_DIGEST_SIZE], char *hex_str) {
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        hex_str[i * 2] = hex[digest[i] >> 4];
        hex_str[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    hex_str[SHA256_DIGEST_SIZE * 2] = '\0';
}

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[SHA256_DIGEST_SIZE]) {
    uint8_t k[SHA256_BLOCK_SIZE];
    uint8_t ipad[SHA256_BLOCK_SIZE];
    uint8_t opad[SHA256_BLOCK_SIZE];
    uint8_t keyhash[SHA256_DIGEST_SIZE];
    SHA256_CTX ctx;
    size_t i;

    memset(k, 0, sizeof(k));
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_hash(key, key_len, keyhash);
        memcpy(k, keyhash, SHA256_DIGEST_SIZE);
    } else if (key_len > 0) {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, ipad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, keyhash);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, keyhash, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, out);
}

void hmac_sha256_to_hex(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        char hex_str[SHA256_DIGEST_SIZE * 2 + 1]) {
    uint8_t digest[SHA256_DIGEST_SIZE];
    hmac_sha256(key, key_len, data, data_len, digest);
    sha256_to_hex(digest, hex_str);
}
