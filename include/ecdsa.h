#ifndef ECDSA_H
#define ECDSA_H

#include "platform.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ECDSA_SIG_SIZE       64

#define ECDSA_SIG_HEX_SIZE   129

#define ECDSA_PUBKEY_BLOB_SIZE  72

#define ECDSA_PRIVKEY_BLOB_SIZE 104

lic_bool ECDSA_GenerateKeyPair(const char *private_key_path, const char *public_key_path);

lic_bool ECDSA_SignData(const uint8_t *data, size_t data_len, char *sig_hex);

lic_bool ECDSA_VerifyWithEmbedded(const uint8_t *data, size_t data_len, const char *sig_hex);

#ifdef __cplusplus
}
#endif

#endif
