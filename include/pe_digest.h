#ifndef PE_DIGEST_H
#define PE_DIGEST_H

#include <stddef.h>
#include <stdint.h>

#define PE_DIGEST_HEX_LEN 64

#ifdef __cplusplus
extern "C" {
#endif

int PeComputeTextDigest(const uint8_t *file_data,
                        size_t file_size,
                        char out_hex[PE_DIGEST_HEX_LEN + 1]);

int PeComputeStructDigest(const uint8_t *file_data,
                          size_t file_size,
                          char out_hex[PE_DIGEST_HEX_LEN + 1]);

void PeDescribeSections(const uint8_t *file_data, size_t file_size);

#ifdef __cplusplus
}
#endif

#endif
