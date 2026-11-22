#ifndef KEY_H
#define KEY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ECDSA_PUBKEY_SIZE 72
#define XOR_KEY_LEN 8
#define FILE_ENCRYPT_MAGIC "LICE"
#define FILE_ENCRYPT_VERSION 0x01
#define FILE_KEY1_LEN 16
#define FILE_KEY2_LEN 16
#define FILE_KEY3_LEN 8
#define Obfuscate_CHARSET_LEN 16
#define FILE_ENCRYPT_HEADER_SIZE 13
#define AUTH_API_SECRET_LEN 64
#define MACHINE_CHARSET_LEN 16

const uint8_t* GetEmbeddedPublicKey(size_t *out_size);

void GetXorKey(uint8_t *out);
void GetObfuscateCharset(char *out);
void GetFileKey1(uint8_t *out);
void GetFileKey2(uint8_t *out);
void GetFileKey3(uint8_t *out);
uint32_t GetFileKey3Seed(void);
void GetAuthApiSecret(char *out);
void GetMachineObfuscateCharset(char *out);
void GetMachineXorKey(uint8_t *out);

void KeyXorBuf(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
