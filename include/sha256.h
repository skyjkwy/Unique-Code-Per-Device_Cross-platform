#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint32_t datalen;
    uint8_t data[64];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);
void sha256_to_hex(const uint8_t digest[SHA256_DIGEST_SIZE], char *hex_str);

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[SHA256_DIGEST_SIZE]);
void hmac_sha256_to_hex(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        char hex_str[SHA256_DIGEST_SIZE * 2 + 1]);

#ifdef __cplusplus
}
#endif

#endif
