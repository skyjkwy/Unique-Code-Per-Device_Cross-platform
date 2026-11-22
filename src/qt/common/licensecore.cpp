#include "licensecore.h"
#include "ntp_client.h"

#include <QFileInfo>

#include <ctime>
#include <cstdlib>

namespace LicenseCore {

static QString errorText() {
    char buf[1024] = {0};
    License_GetLastErrorMsg(buf, sizeof(buf));
    QString text = QString::fromUtf8(buf);
    return text.isEmpty() ? QStringLiteral("未知错误") : text;
}

bool init(QString *error) {
    LicenseConfig cfg{1, 300, 3000, 3};
    int rc = License_Init(&cfg);
    if (rc != LICENSE_OK) {
        if (error) {
            *error = errorText();
            if (error->isEmpty()) {
                *error = QStringLiteral("授权系统初始化失败（错误码 %1）").arg(rc);
            }
        }
        return false;
    }
    return true;
}

void shutdown() {
    License_Shutdown();
}

bool isActivated() {
    return License_IsActivated() ? true : false;
}

QString machineCode() {
    char buf[MACHINE_CODE_LEN] = {0};
    if (License_GetMachineCode(buf, sizeof(buf)) != LICENSE_OK) {
        return QString();
    }
    return QString::fromUtf8(buf);
}

QString obfuscatedMachineCode() {
    char buf[MACHINE_CODE_LEN] = {0};
    if (License_GetObfuscatedMachineCode(buf, sizeof(buf)) != LICENSE_OK) {
        return QString();
    }
    return QString::fromUtf8(buf);
}

Info info() {
    Info result;
    LicenseInfo li;
    if (License_GetInfo(&li) != LICENSE_OK) {
        return result;
    }
    result.status = li.status;
    result.username = QString::fromUtf8(li.username);
    result.email = QString::fromUtf8(li.email);
    result.machineCode = QString::fromUtf8(li.machine_code);
    result.expireTime = li.expire_time;
    result.remainingDays = li.remaining_days;
    result.currentTime = li.current_time;
    result.source = li.source;
    return result;
}

bool activate(const QString &code, const QString &user, const QString &email, QString *error) {
    QByteArray codeUtf8 = code.toUtf8();
    QByteArray userUtf8 = user.toUtf8();
    QByteArray emailUtf8 = email.toUtf8();

    int rc = License_Activate(codeUtf8.constData(), userUtf8.constData(), emailUtf8.constData());
    if (rc != LICENSE_OK) {
        if (error) *error = errorText();
        return false;
    }
    return true;
}

bool clear(QString *error) {
    int rc = License_Clear();
    if (rc != LICENSE_OK) {
        if (error) *error = errorText();
        return false;
    }
    return true;
}

QString lastError() {
    return errorText();
}

uint32_t ntpNow(bool *ok) {
    uint32_t t = 0;
    if (GetNtpTime(&t)) {
        if (ok) *ok = true;
        return t;
    }
    if (ok) *ok = false;
    return static_cast<uint32_t>(std::time(nullptr));
}

QString generateCode(const QString &machine, uint64_t seconds,
                     const QString &user, const QString &email, QString *error) {
    bool ntpOk = false;
    uint32_t now = ntpNow(&ntpOk);
    return generateCodeAt(machine, seconds, user, email, now, error);
}

QString generateCodeAt(const QString &machine, uint64_t seconds,
                       const QString &user, const QString &email,
                       uint32_t now, QString *error) {
    QByteArray machineUtf8 = machine.toUtf8();
    QByteArray userUtf8 = user.toUtf8();
    QByteArray emailUtf8 = email.toUtf8();

    char code[ACTIVATION_CODE_LEN] = {0};
    if (!GenerateActivationCode(machineUtf8.constData(), seconds,
                                userUtf8.constData(), emailUtf8.constData(),
                                code, sizeof(code), now)) {
        if (error) {
            *error = QStringLiteral("生成激活码失败：机器码格式不正确，"
                                    "或当前构建未启用发码私钥。");
        }
        return QString();
    }

    return QString::fromUtf8(code);
}

QString formatTotalSeconds(uint64_t seconds) {
    char buf[256] = {0};
    FormatTotalSeconds(seconds, buf, sizeof(buf));
    return QString::fromUtf8(buf);
}

QString formatExpireTime(uint32_t t) {
    char buf[128] = {0};
    FormatExpireTime(t, buf, sizeof(buf));
    return QString::fromUtf8(buf);
}

bool normalizeMachine(const QString &input, QString *output) {
    if (!output) return false;
    QByteArray in = input.toUtf8();
    char out[MACHINE_CODE_LEN * 2] = {0};
    if (!NormalizeMachineCode(in.constData(), out, sizeof(out))) {
        return false;
    }
    *output = QString::fromUtf8(out);
    return true;
}

bool readLicenseFile(const QString &path, FileInfo *out, QString *error) {
    if (!out) return false;
    *out = FileInfo{};

    QByteArray pathUtf8 = path.toUtf8();
    LicenseFileInfo fi;
    if (License_ReadFileInfo(pathUtf8.constData(), &fi) != LICENSE_OK) {
        if (error) {
            *error = QStringLiteral("无法解析授权文件。请确认文件存在且格式正确。");
        }
        return false;
    }

    out->valid = fi.valid != 0;
    out->encrypted = fi.encrypted != 0;
    out->bindingOk = fi.binding_ok != 0;
    out->source = fi.source;
    out->expireTime = fi.expire_time;
    out->lastSeenTime = fi.last_seen_time;
    out->username = QString::fromUtf8(fi.username);
    out->email = QString::fromUtf8(fi.email);
    out->bindingDigestHex = QString::fromUtf8(fi.binding_digest_hex);
    out->onlineCode = QString::fromUtf8(fi.online_code);
    out->onlineLastVerify = fi.online_last_verify;
    out->rawSize = fi.raw_size;

    out->usedCodes.clear();
    for (int i = 0; i < fi.used_code_count; ++i) {
        out->usedCodes << QString::fromUtf8(fi.used_codes[i]);
    }
    return true;
}

bool decryptLicenseFile(const QString &path, QByteArray *out, QString *error) {
    if (!out) return false;
    out->clear();

    QByteArray pathUtf8 = path.toUtf8();
    uint8_t *data = nullptr;
    size_t len = 0;
    if (License_DecryptFile(pathUtf8.constData(), &data, &len) != LICENSE_OK || !data) {
        if (error) *error = QStringLiteral("读取或解密授权文件失败。");
        return false;
    }

    out->append(reinterpret_cast<const char *>(data), static_cast<int>(len));
    std::free(data);
    return true;
}

} // namespace LicenseCore
