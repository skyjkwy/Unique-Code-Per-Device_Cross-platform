#include "license_backup.h"
#include "platform.h"

#include <stdlib.h>
#include <string.h>

#define BACKUP_DIR_NAME  "SkySoftware"
#define BACKUP_FILE_NAME "license-SkyBox.dat"
#define BACKUP_HIDDEN    ".license-SkyBox.cache"

static int data_backup_path(char *out, size_t cap, int create) {
    char dir[LICENSE_PATH_MAX];
    if (lic_data_dir(dir, sizeof(dir), BACKUP_DIR_NAME, create) != 0) return -1;
    lic_snprintf(out, cap, "%s/%s", dir, BACKUP_FILE_NAME);
    return 0;
}

static int hidden_backup_path(char *out, size_t cap) {
    char dir[LICENSE_PATH_MAX];
    if (lic_exe_dir(dir, sizeof(dir)) != 0) return -1;
    lic_snprintf(out, cap, "%s/%s", dir, BACKUP_HIDDEN);
    return 0;
}

int LicenseBackup_Init(void) {
    char path[LICENSE_PATH_MAX];
    return data_backup_path(path, sizeof(path), 1) == 0 ? 0 : -1;
}

int LicenseBackup_Save(const uint8_t *data, size_t size, const char *primary_path) {
    (void)primary_path;
    if (!data || size == 0) return -1;

    int ok = 0;
    char path[LICENSE_PATH_MAX];

    if (data_backup_path(path, sizeof(path), 1) == 0 &&
        lic_write_all(path, data, size, 1) == 0) {
        ok = 1;
    }

    if (hidden_backup_path(path, sizeof(path)) == 0 &&
        lic_write_all(path, data, size, 1) == 0) {
        ok = 1;
    }

    return ok ? 0 : -1;
}

int LicenseBackup_Load(const char *primary_path, uint8_t **data, size_t *size,
                       char *source, int *tampered) {
    (void)primary_path;
    if (!data || !size || !source || !tampered) return -1;
    *data = NULL;
    *size = 0;
    *source = 'N';
    *tampered = 0;

    char path[LICENSE_PATH_MAX];

    if (data_backup_path(path, sizeof(path), 0) == 0 &&
        lic_read_all(path, data, size, 10 * 1024 * 1024) == 0 && *size > 0) {
        *source = 'D';
        return 0;
    }

    if (hidden_backup_path(path, sizeof(path)) == 0 &&
        lic_read_all(path, data, size, 10 * 1024 * 1024) == 0 && *size > 0) {
        *source = 'H';
        return 0;
    }

    *tampered = 1;
    return -1;
}

int LicenseBackup_Clear(const char *primary_path) {
    (void)primary_path;

    char path[LICENSE_PATH_MAX];
    if (data_backup_path(path, sizeof(path), 0) == 0) {
        lic_remove(path);
    }
    if (hidden_backup_path(path, sizeof(path)) == 0) {
        lic_remove(path);
    }
    return 0;
}
