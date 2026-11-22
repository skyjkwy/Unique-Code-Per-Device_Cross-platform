#include "pe_digest.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>

#define PE_DOS_MAGIC     0x5A4D
#define PE_FILE_SIG      0x00004550u
#define PE_OPT_MAGIC32   0x010B
#define PE_OPT_MAGIC32P  0x020B

#define PE_EXCL_TIMESTAMP   1
#define PE_EXCL_CHECKSUM    2
#define PE_EXCL_SECURITYDIR 3

typedef struct {
    uint32_t off;
    uint32_t len;
} PeRange;

typedef struct {
    uint32_t pe_off;
    uint16_t num_sections;
    uint16_t opt_size;
    uint32_t header_size;
    uint32_t ddir_base;
} PeLayout;

static int PeRead16(const uint8_t *p, uint16_t *out) {
    if (!p) return 0;
    *out = *(const uint16_t *)(const void *)p;
    return 1;
}

static int PeRead32(const uint8_t *p, uint32_t *out) {
    if (!p) return 0;
    *out = *(const uint32_t *)(const void *)p;
    return 1;
}

static int PeReadLayout(const uint8_t *d, size_t n, PeLayout *out) {
    uint32_t pe_off = 0;
    uint32_t sig = 0;
    uint16_t num_sections = 0;
    uint16_t opt_size = 0;
    uint16_t magic = 0;
    uint32_t size_headers = 0;
    size_t opt = 0;
    size_t sec = 0;

    if (!d || !out || n < 0x40) return 0;
    if (d[0] != 'M' || d[1] != 'Z') return 0;

    PeRead32(d + 0x3C, &pe_off);
    if (pe_off < 0x40 || (size_t)pe_off + 24 > n) return 0;

    PeRead32(d + pe_off, &sig);
    if (sig != PE_FILE_SIG) return 0;

    PeRead16(d + pe_off + 6, &num_sections);
    PeRead16(d + pe_off + 20, &opt_size);

    opt = (size_t)pe_off + 24;
    if (opt_size < 2 || opt + opt_size > n) return 0;

    PeRead16(d + opt, &magic);
    if (magic == PE_OPT_MAGIC32) {
        out->ddir_base = 96;
    } else if (magic == PE_OPT_MAGIC32P) {
        out->ddir_base = 112;
    } else {
        return 0;
    }

    PeRead32(d + opt + 60, &size_headers);
    if (size_headers == 0 || size_headers > n) return 0;

    sec = opt + opt_size;
    if (sec + (size_t)num_sections * 40 > n) return 0;

    out->pe_off = pe_off;
    out->num_sections = num_sections;
    out->opt_size = opt_size;
    out->header_size = size_headers;
    return 1;
}

static int IsSkippedSection(const uint8_t *name) {
    static const char *kSkip[] = { ".text", ".rdata", ".idata" };
    int i;
    for (i = 0; i < (int)(sizeof(kSkip) / sizeof(kSkip[0])); i++) {
        size_t len = strlen(kSkip[i]);
        if (memcmp(name, kSkip[i], len) == 0) return 1;
    }
    return 0;
}

static uint32_t SectionRawSize(const uint8_t *s) {
    return *(const uint32_t *)(const void *)(s + 16);
}

static uint32_t SectionRawPtr(const uint8_t *s) {
    return *(const uint32_t *)(const void *)(s + 20);
}

int PeComputeTextDigest(const uint8_t *file_data,
                        size_t file_size,
                        char out_hex[PE_DIGEST_HEX_LEN + 1]) {
    PeLayout lay;
    const uint8_t *table = NULL;
    uint16_t i = 0;

    if (!out_hex) return 0;
    if (!PeReadLayout(file_data, file_size, &lay)) return 0;

    table = file_data + (size_t)lay.pe_off + 24 + lay.opt_size;
    for (i = 0; i < lay.num_sections; i++) {
        const uint8_t *s = table + (size_t)i * 40;
        uint32_t raw_size = 0;
        uint32_t raw_ptr = 0;
        uint8_t digest[SHA256_DIGEST_SIZE];

        if (memcmp(s, ".text", 5) != 0) continue;

        raw_size = SectionRawSize(s);
        raw_ptr = SectionRawPtr(s);
        if (raw_size == 0) return 0;
        if ((size_t)raw_ptr + raw_size > file_size) return 0;

        sha256_hash(file_data + raw_ptr, raw_size, digest);
        sha256_to_hex(digest, out_hex);
        return 1;
    }

    return 0;
}

static int PeExclusions(const PeLayout *lay, PeRange ex[3], int *nex) {
    int i = 0;

    ex[0].off = lay->pe_off + 8;
    ex[0].len = 4;
    ex[1].off = lay->pe_off + 24 + 64;
    ex[1].len = 4;
    ex[2].off = lay->pe_off + 24 + lay->ddir_base + 32;
    ex[2].len = 8;
    *nex = 3;

    for (i = 0; i < *nex; i++) {
        if ((uint64_t)ex[i].off + ex[i].len > (uint64_t)lay->header_size) return 0;
    }

    for (i = 1; i < *nex; i++) {
        PeRange tmp = ex[i];
        int j = i - 1;
        while (j >= 0 && ex[j].off > tmp.off) {
            ex[j + 1] = ex[j];
            j--;
        }
        ex[j + 1] = tmp;
    }
    return 1;
}

static int PeHeaderDigest(const uint8_t *d, const PeLayout *lay,
                          const PeRange *ex, int nex, uint8_t digest[32]) {
    SHA256_CTX ctx;
    uint32_t pos = 0;
    int i = 0;

    sha256_init(&ctx);
    for (i = 0; i < nex; i++) {
        if (ex[i].off > pos) {
            sha256_update(&ctx, d + pos, (size_t)(ex[i].off - pos));
        }
        pos = ex[i].off + ex[i].len;
    }
    if (pos < lay->header_size) {
        sha256_update(&ctx, d + pos, (size_t)(lay->header_size - pos));
    }
    sha256_final(&ctx, digest);
    return 1;
}

void PeDescribeSections(const uint8_t *file_data, size_t file_size) {
    PeLayout lay;
    PeRange ex[3];
    int nex = 0;
    int i = 0;
    const uint8_t *table = NULL;
    uint8_t digest[SHA256_DIGEST_SIZE];
    char hex[PE_DIGEST_HEX_LEN + 1];

    if (!file_data || !PeReadLayout(file_data, file_size, &lay)) return;
    if (!PeExclusions(&lay, ex, &nex)) return;
    if (!PeHeaderDigest(file_data, &lay, ex, nex, digest)) return;

    sha256_to_hex(digest, hex);
    printf("  header   off=0x%-6x image=0x%-6x code=0x%-6x init=0x%-6x checksum=0x%08x\n",
           lay.header_size,
           *(const uint32_t *)(const void *)(file_data + lay.pe_off + 24 + 56),
           *(const uint32_t *)(const void *)(file_data + lay.pe_off + 24 + 4),
           *(const uint32_t *)(const void *)(file_data + lay.pe_off + 24 + 8),
           *(const uint32_t *)(const void *)(file_data + lay.pe_off + 24 + 64));
    printf("  header   hash=%s\n", hex);

    table = file_data + (size_t)lay.pe_off + 24 + lay.opt_size;
    for (i = 0; i < (int)lay.num_sections; i++) {
        const uint8_t *s = table + (size_t)i * 40;
        uint32_t raw_size = SectionRawSize(s);
        uint32_t raw_ptr = SectionRawPtr(s);
        uint32_t va = *(const uint32_t *)(const void *)(s + 12);
        uint32_t vsize = *(const uint32_t *)(const void *)(s + 8);

        if (IsSkippedSection(s)) {
            printf("  section  %-8.8s va=0x%08x vsize=0x%-6x raw=0x%-6x ptr=0x%-6x skipped\n",
                   (const char *)s, va, vsize, raw_size, raw_ptr);
            continue;
        }
        if (raw_size == 0) {
            printf("  section  %-8.8s va=0x%08x vsize=0x%-6x raw=0x%-6x ptr=0x%-6x empty\n",
                   (const char *)s, va, vsize, raw_size, raw_ptr);
            continue;
        }
        if ((size_t)raw_ptr + raw_size > file_size) continue;
        sha256_hash(file_data + raw_ptr, raw_size, digest);
        sha256_to_hex(digest, hex);
        printf("  section  %-8.8s va=0x%08x vsize=0x%-6x raw=0x%-6x ptr=0x%-6x hash=%s\n",
               (const char *)s, va, vsize, raw_size, raw_ptr, hex);
    }
}

int PeComputeStructDigest(const uint8_t *file_data,
                          size_t file_size,
                          char out_hex[PE_DIGEST_HEX_LEN + 1]) {
    static const char kMarker[] = "SKYBOX-PE-STRUCT-V1";
    PeLayout lay;
    PeRange ex[3];
    int nex = 0;
    int i = 0;
    uint32_t pos = 0;
    const uint8_t *table = NULL;
    SHA256_CTX ctx;
    uint8_t digest[SHA256_DIGEST_SIZE];

    if (!out_hex) return 0;
    if (!PeReadLayout(file_data, file_size, &lay)) return 0;
    if (!PeExclusions(&lay, ex, &nex)) return 0;

    sha256_init(&ctx);

    sha256_update(&ctx, (const uint8_t *)kMarker, sizeof(kMarker) - 1);

    for (i = 0; i < nex; i++) {
        if (ex[i].off > pos) {
            sha256_update(&ctx, file_data + pos, (size_t)(ex[i].off - pos));
        }
        pos = ex[i].off + ex[i].len;
    }
    if (pos < lay.header_size) {
        sha256_update(&ctx, file_data + pos, (size_t)(lay.header_size - pos));
    }

    table = file_data + (size_t)lay.pe_off + 24 + lay.opt_size;
    for (i = 0; i < (int)lay.num_sections; i++) {
        const uint8_t *s = table + (size_t)i * 40;
        uint32_t raw_size = SectionRawSize(s);
        uint32_t raw_ptr = SectionRawPtr(s);
        uint32_t va = *(const uint32_t *)(const void *)(s + 12);
        int ok = 1;

        if (IsSkippedSection(s)) continue;
        if (raw_size == 0) continue;
        if ((size_t)raw_ptr + raw_size > file_size) ok = 0;

        sha256_update(&ctx, s, 8);
        sha256_update(&ctx, (const uint8_t *)&va, sizeof(va));
        sha256_update(&ctx, (const uint8_t *)&raw_size, sizeof(raw_size));
        if (ok) {
            sha256_update(&ctx, file_data + raw_ptr, (size_t)raw_size);
        }

        if (!ok) {

            sha256_final(&ctx, digest);
            return 0;
        }
    }

    sha256_final(&ctx, digest);
    sha256_to_hex(digest, out_hex);
    return 1;
}
