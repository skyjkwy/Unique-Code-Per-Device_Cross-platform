#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <stdint.h>

#include "license_dll.h"
#include "license.h"

namespace LicenseCore {

struct Info {
    int status = LICENSE_STATUS_NOT_ACTIVATED;
    QString username;
    QString email;
    QString machineCode;
    uint32_t expireTime = 0;
    uint32_t remainingDays = 0;
    uint32_t currentTime = 0;
    int source = LICENSE_SOURCE_NONE;
};

struct FileInfo {
    bool valid = false;
    bool encrypted = false;
    bool bindingOk = false;
    int source = 0;
    uint32_t expireTime = 0;
    uint32_t lastSeenTime = 0;
    QString username;
    QString email;
    QString bindingDigestHex;
    QStringList usedCodes;
    QString onlineCode;
    uint32_t onlineLastVerify = 0;
    uint32_t rawSize = 0;
};

bool init(QString *error);
void shutdown();
bool isActivated();
QString machineCode();
QString obfuscatedMachineCode();
Info info();
bool activate(const QString &code, const QString &user, const QString &email, QString *error);
bool clear(QString *error);
QString lastError();

uint32_t ntpNow(bool *ok);
QString generateCode(const QString &machine, uint64_t seconds,
                     const QString &user, const QString &email, QString *error);
QString generateCodeAt(const QString &machine, uint64_t seconds,
                       const QString &user, const QString &email,
                       uint32_t now, QString *error);
QString formatTotalSeconds(uint64_t seconds);
QString formatExpireTime(uint32_t time);
bool normalizeMachine(const QString &input, QString *output);

bool readLicenseFile(const QString &path, FileInfo *out, QString *error);
bool decryptLicenseFile(const QString &path, QByteArray *out, QString *error);

} // namespace LicenseCore
