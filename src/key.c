#include "key.h"
#include "platform.h"
#include <string.h>

#include "embedded_pubkey.h"

#define STATIC_XOR 0xA5

static const uint8_t ENC_XOR_KEY[] = {
    0x4A^STATIC_XOR, 0x6F^STATIC_XOR, 0x68^STATIC_XOR, 0x6E^STATIC_XOR,
    0x20^STATIC_XOR, 0x44^STATIC_XOR, 0x6F^STATIC_XOR, 0x65^STATIC_XOR
};

static const char ENC_Obfuscate_CHARSET[] = {
    'K'^STATIC_XOR, '3'^STATIC_XOR, 'x'^STATIC_XOR, 'P'^STATIC_XOR,
    '7'^STATIC_XOR, 'n'^STATIC_XOR, '9'^STATIC_XOR, 'R'^STATIC_XOR,
    'q'^STATIC_XOR, '5'^STATIC_XOR, 'H'^STATIC_XOR, 'c'^STATIC_XOR,
    '2'^STATIC_XOR, 'T'^STATIC_XOR, '8'^STATIC_XOR, 'w'^STATIC_XOR,
    'V'^STATIC_XOR, 'm'^STATIC_XOR, '4'^STATIC_XOR, 'Y'^STATIC_XOR
};

static const uint8_t ENC_FILE_KEY1[] = {
    0xA3^STATIC_XOR, 0x5F^STATIC_XOR, 0xB7^STATIC_XOR, 0xD9^STATIC_XOR,
    0xC1^STATIC_XOR, 0x8E^STATIC_XOR, 0x24^STATIC_XOR, 0xF6^STATIC_XOR,
    0x3D^STATIC_XOR, 0x72^STATIC_XOR, 0x0B^STATIC_XOR, 0x98^STATIC_XOR,
    0x5E^STATIC_XOR, 0x4A^STATIC_XOR, 0x1C^STATIC_XOR, 0x6F^STATIC_XOR
};

static const uint8_t ENC_FILE_KEY2[] = {
    0x8B^STATIC_XOR, 0x42^STATIC_XOR, 0xE5^STATIC_XOR, 0x17^STATIC_XOR,
    0x9F^STATIC_XOR, 0xD3^STATIC_XOR, 0xA8^STATIC_XOR, 0x36^STATIC_XOR,
    0xC4^STATIC_XOR, 0x5E^STATIC_XOR, 0x71^STATIC_XOR, 0x09^STATIC_XOR,
    0xB2^STATIC_XOR, 0x6D^STATIC_XOR, 0xF8^STATIC_XOR, 0xAC^STATIC_XOR
};

static const uint8_t ENC_FILE_KEY3[] = {
    0x3F^STATIC_XOR, 0x92^STATIC_XOR, 0xC7^STATIC_XOR, 0xE8^STATIC_XOR,
    0x51^STATIC_XOR, 0x06^STATIC_XOR, 0xAD^STATIC_XOR, 0xB4^STATIC_XOR
};

static const uint32_t ENC_FILE_KEY3_SEED = 0x4F7385E1 ^ STATIC_XOR;

static const char ENC_AUTH_API_SECRET[] = {
    'W'^STATIC_XOR, 'M'^STATIC_XOR, 'e'^STATIC_XOR, '0'^STATIC_XOR,
    'Z'^STATIC_XOR, 'm'^STATIC_XOR, 'F'^STATIC_XOR, 'c'^STATIC_XOR,
    'h'^STATIC_XOR, 'a'^STATIC_XOR, 'i'^STATIC_XOR, 'V'^STATIC_XOR,
    'O'^STATIC_XOR, 'M'^STATIC_XOR, 'Q'^STATIC_XOR, 'F'^STATIC_XOR,
    '0'^STATIC_XOR, 'G'^STATIC_XOR, 'B'^STATIC_XOR, 'N'^STATIC_XOR,
    'T'^STATIC_XOR, 'S'^STATIC_XOR, '3'^STATIC_XOR, '0'^STATIC_XOR,
    'W'^STATIC_XOR, 'C'^STATIC_XOR, 'o'^STATIC_XOR, 'z'^STATIC_XOR,
    'S'^STATIC_XOR, 'O'^STATIC_XOR, 'G'^STATIC_XOR, 'h'^STATIC_XOR,
    'e'^STATIC_XOR, 'r'^STATIC_XOR, 'S'^STATIC_XOR, '7'^STATIC_XOR,
    'M'^STATIC_XOR, 'g'^STATIC_XOR, 'H'^STATIC_XOR, '2'^STATIC_XOR,
    'J'^STATIC_XOR, 'H'^STATIC_XOR, 'l'^STATIC_XOR, 'C'^STATIC_XOR,
    'o'^STATIC_XOR, 'V'^STATIC_XOR, 'I'^STATIC_XOR, 'G'^STATIC_XOR,
    'j'^STATIC_XOR, '8'^STATIC_XOR, 'r'^STATIC_XOR, '9'^STATIC_XOR,
    'q'^STATIC_XOR, 'L'^STATIC_XOR, 'b'^STATIC_XOR, 'w'^STATIC_XOR,
    'M'^STATIC_XOR, 'y'^STATIC_XOR, 'o'^STATIC_XOR, 's'^STATIC_XOR,
    'o'^STATIC_XOR, 'C'^STATIC_XOR, 'd'^STATIC_XOR, 'F'^STATIC_XOR
};

static const char ENC_Machine_CHARSET[] = {
    'L'^STATIC_XOR, 'B'^STATIC_XOR, '6'^STATIC_XOR, 'D'^STATIC_XOR,
    'f'^STATIC_XOR, 'j'^STATIC_XOR, 'Q'^STATIC_XOR, 's'^STATIC_XOR,
    'A'^STATIC_XOR, '1'^STATIC_XOR, 'N'^STATIC_XOR, 'p'^STATIC_XOR,
    'Z'^STATIC_XOR, 'E'^STATIC_XOR, 'h'^STATIC_XOR, 'r'^STATIC_XOR
};

static const uint8_t ENC_Machine_XOR_KEY[] = {
    0x53^STATIC_XOR, 0x6B^STATIC_XOR, 0x79^STATIC_XOR, 0x2D^STATIC_XOR,
    0x4D^STATIC_XOR, 0x43^STATIC_XOR, 0x30^STATIC_XOR, 0x31^STATIC_XOR
};

static void decrypt_to_buffer(const void *enc_data, size_t len, void *out) {
    uint8_t temp[64];
    memcpy(temp, enc_data, len);
    for (size_t i = 0; i < len; i++) {
        temp[i] ^= STATIC_XOR;
    }
    memcpy(out, temp, len);
    SecureZeroMemory(temp, len);
}

const uint8_t* GetEmbeddedPublicKey(size_t *out_size) {
    if (out_size) *out_size = sizeof(EMBEDDED_PUBLIC_KEY);
    return EMBEDDED_PUBLIC_KEY;
}

void GetXorKey(uint8_t *out) {
    decrypt_to_buffer(ENC_XOR_KEY, XOR_KEY_LEN, out);
}

void GetObfuscateCharset(char *out) {
    decrypt_to_buffer(ENC_Obfuscate_CHARSET, Obfuscate_CHARSET_LEN, out);
    out[Obfuscate_CHARSET_LEN] = '\0';
}

void GetFileKey1(uint8_t *out) {
    decrypt_to_buffer(ENC_FILE_KEY1, FILE_KEY1_LEN, out);
}

void GetFileKey2(uint8_t *out) {
    decrypt_to_buffer(ENC_FILE_KEY2, FILE_KEY2_LEN, out);
}

void GetFileKey3(uint8_t *out) {
    decrypt_to_buffer(ENC_FILE_KEY3, FILE_KEY3_LEN, out);
}

uint32_t GetFileKey3Seed(void) {
    uint32_t seed;
    decrypt_to_buffer(&ENC_FILE_KEY3_SEED, sizeof(seed), &seed);
    return seed;
}

void GetAuthApiSecret(char *out) {
    decrypt_to_buffer(ENC_AUTH_API_SECRET, AUTH_API_SECRET_LEN, out);
    out[AUTH_API_SECRET_LEN] = '\0';
}

void GetMachineObfuscateCharset(char *out) {
    decrypt_to_buffer(ENC_Machine_CHARSET, MACHINE_CHARSET_LEN, out);
    out[MACHINE_CHARSET_LEN] = '\0';
}

void GetMachineXorKey(uint8_t *out) {
    decrypt_to_buffer(ENC_Machine_XOR_KEY, XOR_KEY_LEN, out);
}

void KeyXorBuf(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t i;

    if (!p || len == 0) return;
    for (i = 0; i < len; i++) p[i] ^= STATIC_XOR;
}
