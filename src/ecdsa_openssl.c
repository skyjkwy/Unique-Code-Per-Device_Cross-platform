#include "ecdsa.h"
#include "key.h"
#include "sha256.h"

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <stdio.h>
#include <string.h>

#ifdef ECDSA_SIGN_ENABLED
#include "embedded_privkey.h"
#endif

#define CNG_CURVE_BYTES 32
#define CNG_PUB_MAGIC  "ECS1"
#define CNG_PRIV_MAGIC "ECS2"
#define CNG_PUB_MAGIC_ALT  "ECK1"
#define CNG_PRIV_MAGIC_ALT "ECK4"

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void write_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static EC_KEY *key_from_public_blob(const uint8_t *blob, size_t len) {
    if (!blob || len != ECDSA_PUBKEY_BLOB_SIZE) return NULL;
    if (memcmp(blob, CNG_PUB_MAGIC, 4) != 0 &&
        memcmp(blob, CNG_PUB_MAGIC_ALT, 4) != 0) return NULL;
    if (read_u32_le(blob + 4) != CNG_CURVE_BYTES) return NULL;

    BIGNUM *x = BN_bin2bn(blob + 8, CNG_CURVE_BYTES, NULL);
    BIGNUM *y = BN_bin2bn(blob + 40, CNG_CURVE_BYTES, NULL);
    if (!x || !y) {
        BN_free(x);
        BN_free(y);
        return NULL;
    }

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key || EC_KEY_set_public_key_affine_coordinates(key, x, y) != 1) {
        EC_KEY_free(key);
        key = NULL;
    }

    BN_free(x);
    BN_free(y);
    return key;
}

#ifdef ECDSA_SIGN_ENABLED
static EC_KEY *key_from_private_blob(const uint8_t *blob, size_t len) {
    if (!blob || len != ECDSA_PRIVKEY_BLOB_SIZE) return NULL;
    if (memcmp(blob, CNG_PRIV_MAGIC, 4) != 0 &&
        memcmp(blob, CNG_PRIV_MAGIC_ALT, 4) != 0) return NULL;
    if (read_u32_le(blob + 4) != CNG_CURVE_BYTES) return NULL;

    BIGNUM *d = BN_bin2bn(blob + 72, CNG_CURVE_BYTES, NULL);
    if (!d) return NULL;

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) {
        BN_clear_free(d);
        return NULL;
    }

    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub = EC_POINT_new(group);
    BN_CTX *ctx = BN_CTX_new();
    int ok = pub && ctx && EC_KEY_set_private_key(key, d) == 1 &&
             EC_POINT_mul(group, pub, d, NULL, NULL, ctx) == 1 &&
             EC_KEY_set_public_key(key, pub) == 1;

    EC_POINT_free(pub);
    BN_CTX_free(ctx);
    if (!ok) {
        EC_KEY_free(key);
        key = NULL;
    }

    BN_clear_free(d);
    return key;
}
#endif

static void sig_to_hex(const ECDSA_SIG *sig, char *sig_hex) {
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    uint8_t rbuf[CNG_CURVE_BYTES];
    uint8_t sbuf[CNG_CURVE_BYTES];
    static const char *hex = "0123456789abcdef";

    ECDSA_SIG_get0(sig, &r, &s);
    if (!r || !s) {
        sig_hex[0] = '\0';
        return;
    }

    if (BN_bn2binpad(r, rbuf, CNG_CURVE_BYTES) != CNG_CURVE_BYTES ||
        BN_bn2binpad(s, sbuf, CNG_CURVE_BYTES) != CNG_CURVE_BYTES) {
        sig_hex[0] = '\0';
        return;
    }

    for (int i = 0; i < CNG_CURVE_BYTES; i++) {
        sig_hex[i * 2] = hex[rbuf[i] >> 4];
        sig_hex[i * 2 + 1] = hex[rbuf[i] & 0x0F];
        sig_hex[64 + i * 2] = hex[sbuf[i] >> 4];
        sig_hex[64 + i * 2 + 1] = hex[sbuf[i] & 0x0F];
    }
    sig_hex[ECDSA_SIG_HEX_SIZE - 1] = '\0';
}

static ECDSA_SIG *sig_from_hex(const char *sig_hex) {
    if (!sig_hex || strlen(sig_hex) < ECDSA_SIG_SIZE * 2) return NULL;

    uint8_t rbuf[CNG_CURVE_BYTES];
    uint8_t sbuf[CNG_CURVE_BYTES];
    for (int i = 0; i < CNG_CURVE_BYTES; i++) {
        unsigned int v = 0;
        if (sscanf(sig_hex + i * 2, "%2x", &v) != 1) return NULL;
        rbuf[i] = (uint8_t)v;
        if (sscanf(sig_hex + 64 + i * 2, "%2x", &v) != 1) return NULL;
        sbuf[i] = (uint8_t)v;
    }

    BIGNUM *r = BN_bin2bn(rbuf, CNG_CURVE_BYTES, NULL);
    BIGNUM *s = BN_bin2bn(sbuf, CNG_CURVE_BYTES, NULL);
    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!r || !s || !sig) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return NULL;
    }
    ECDSA_SIG_set0(sig, r, s);
    return sig;
}

lic_bool ECDSA_VerifyWithEmbedded(const uint8_t *data, size_t data_len, const char *sig_hex) {
    size_t pub_key_len = 0;
    const uint8_t *pub_key = GetEmbeddedPublicKey(&pub_key_len);
    EC_KEY *key = key_from_public_blob(pub_key, pub_key_len);
    if (!key) return FALSE;

    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_hash(data, data_len, hash);

    ECDSA_SIG *sig = sig_from_hex(sig_hex);
    int ok = 0;
    if (sig) {
        ok = ECDSA_do_verify(hash, SHA256_DIGEST_SIZE, sig, key) == 1;
        ECDSA_SIG_free(sig);
    }
    EC_KEY_free(key);
    return ok ? TRUE : FALSE;
}

lic_bool ECDSA_SignData(const uint8_t *data, size_t data_len, char *sig_hex) {
#ifdef ECDSA_SIGN_ENABLED
    if (!sig_hex) return FALSE;
    EC_KEY *key = key_from_private_blob(EMBEDDED_PRIVATE_KEY, sizeof(EMBEDDED_PRIVATE_KEY));
    if (!key) return FALSE;

    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256_hash(data, data_len, hash);

    ECDSA_SIG *sig = ECDSA_do_sign(hash, SHA256_DIGEST_SIZE, key);
    lic_bool ok = FALSE;
    if (sig) {
        sig_to_hex(sig, sig_hex);
        ok = sig_hex[0] != '\0' ? TRUE : FALSE;
        ECDSA_SIG_free(sig);
    }

    EC_KEY_free(key);
    return ok;
#else
    (void)data;
    (void)data_len;
    (void)sig_hex;
    return FALSE;
#endif
}

lic_bool ECDSA_GenerateKeyPair(const char *private_key_path, const char *public_key_path) {
    if (!private_key_path || !public_key_path) return FALSE;

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return FALSE;
    if (EC_KEY_generate_key(key) != 1) {
        EC_KEY_free(key);
        return FALSE;
    }

    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *point = EC_KEY_get0_public_key(key);
    const BIGNUM *d = EC_KEY_get0_private_key(key);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    uint8_t xbuf[CNG_CURVE_BYTES];
    uint8_t ybuf[CNG_CURVE_BYTES];
    uint8_t dbuf[CNG_CURVE_BYTES];
    uint8_t pub_blob[ECDSA_PUBKEY_BLOB_SIZE];
    uint8_t priv_blob[ECDSA_PRIVKEY_BLOB_SIZE];

    lic_bool ok = FALSE;
    if (!x || !y || !point || !d) goto cleanup;
    if (EC_POINT_get_affine_coordinates(group, point, x, y, NULL) != 1) goto cleanup;
    if (BN_bn2binpad(x, xbuf, CNG_CURVE_BYTES) != CNG_CURVE_BYTES) goto cleanup;
    if (BN_bn2binpad(y, ybuf, CNG_CURVE_BYTES) != CNG_CURVE_BYTES) goto cleanup;
    if (BN_bn2binpad(d, dbuf, CNG_CURVE_BYTES) != CNG_CURVE_BYTES) goto cleanup;

    memcpy(pub_blob, CNG_PUB_MAGIC, 4);
    write_u32_le(pub_blob + 4, CNG_CURVE_BYTES);
    memcpy(pub_blob + 8, xbuf, CNG_CURVE_BYTES);
    memcpy(pub_blob + 40, ybuf, CNG_CURVE_BYTES);

    memcpy(priv_blob, CNG_PRIV_MAGIC, 4);
    write_u32_le(priv_blob + 4, CNG_CURVE_BYTES);
    memcpy(priv_blob + 8, xbuf, CNG_CURVE_BYTES);
    memcpy(priv_blob + 40, ybuf, CNG_CURVE_BYTES);
    memcpy(priv_blob + 72, dbuf, CNG_CURVE_BYTES);

    FILE *fp = lic_fopen(private_key_path, "wb");
    if (fp) {
        size_t wr = fwrite(priv_blob, 1, sizeof(priv_blob), fp);
        fclose(fp);
        if (wr == sizeof(priv_blob)) {
            fp = lic_fopen(public_key_path, "wb");
            if (fp) {
                wr = fwrite(pub_blob, 1, sizeof(pub_blob), fp);
                fclose(fp);
                ok = wr == sizeof(pub_blob) ? TRUE : FALSE;
            }
        }
    }

    lic_secure_zero(priv_blob, sizeof(priv_blob));
    lic_secure_zero(dbuf, sizeof(dbuf));

cleanup:
    BN_free(x);
    BN_free(y);
    EC_KEY_free(key);
    return ok;
}
