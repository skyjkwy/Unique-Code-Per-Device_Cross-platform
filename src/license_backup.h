#ifndef LICENSE_BACKUP_H
#define LICENSE_BACKUP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int LicenseBackup_Init(void);
int LicenseBackup_Save(const uint8_t *data, size_t size, const char *primary_path);
int LicenseBackup_Load(const char *primary_path, uint8_t **data, size_t *size, char *source, int *tampered);
int LicenseBackup_Clear(const char *primary_path);

#ifdef __cplusplus
}
#endif

#endif
