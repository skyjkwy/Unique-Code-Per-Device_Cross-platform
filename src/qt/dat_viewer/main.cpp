#include <QApplication>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

#include "licensecore.h"
#include "theme.h"

class DatViewerWindow : public QWidget {
public:
    DatViewerWindow() {
        buildUi();
        loadDefault();
    }

private:
    QLineEdit *pathEdit = nullptr;
    QComboBox *modeCombo = nullptr;
    QPlainTextEdit *viewEdit = nullptr;

    void buildUi() {
        setWindowTitle(QStringLiteral("授权文件查看器"));
        resize(820, 700);

        auto *root = new QVBoxLayout(this);
        root->setContentsMargins(26, 22, 26, 22);
        root->setSpacing(12);

        auto *title = new QLabel(QStringLiteral("license-SkyBox.dat 查看器"), this);
        title->setObjectName(QStringLiteral("title"));
        root->addWidget(title);

        auto *hint = new QLabel(
            QStringLiteral("用于检查授权文件是否加密、状态、到期时间、机器绑定与已使用激活码序列。"),
            this);
        hint->setObjectName(QStringLiteral("hint"));
        hint->setWordWrap(true);
        root->addWidget(hint);

        auto *fileGroup = new QGroupBox(QStringLiteral("授权文件"), this);
        auto *fileLayout = new QVBoxLayout(fileGroup);

        auto *pathRow = new QHBoxLayout();
        pathEdit = new QLineEdit(fileGroup);
        pathEdit->setPlaceholderText(QStringLiteral("选择 license-SkyBox.dat"));
        auto *browseButton = new QPushButton(QStringLiteral("选择..."), fileGroup);
        browseButton->setObjectName(QStringLiteral("secondary"));
        auto *refreshButton = new QPushButton(QStringLiteral("刷新"), fileGroup);
        pathRow->addWidget(pathEdit, 1);
        pathRow->addWidget(browseButton);
        pathRow->addWidget(refreshButton);
        fileLayout->addLayout(pathRow);

        auto *modeRow = new QHBoxLayout();
        modeRow->addWidget(new QLabel(QStringLiteral("查看方式："), fileGroup));
        modeCombo = new QComboBox(fileGroup);
        modeCombo->addItem(QStringLiteral("解析视图"));
        modeCombo->addItem(QStringLiteral("十六进制"));
        modeRow->addWidget(modeCombo);
        modeRow->addStretch(1);
        fileLayout->addLayout(modeRow);

        root->addWidget(fileGroup);

        viewEdit = new QPlainTextEdit(this);
        viewEdit->setReadOnly(true);
        viewEdit->setLineWrapMode(QPlainTextEdit::NoWrap);
        QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        mono.setPointSize(10);
        viewEdit->setFont(mono);
        root->addWidget(viewEdit, 1);

        connect(browseButton, &QPushButton::clicked, this, [this]() {
            QString file = QFileDialog::getOpenFileName(
                this, QStringLiteral("选择授权文件"), pathEdit->text(),
                QStringLiteral("授权文件 (*.dat);;所有文件 (*)"));
            if (!file.isEmpty()) {
                pathEdit->setText(file);
                render();
            }
        });
        connect(refreshButton, &QPushButton::clicked, this, [this]() { render(); });
        connect(modeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, [this](int) { render(); });
        connect(pathEdit, &QLineEdit::returnPressed, this, [this]() { render(); });
    }

    void loadDefault() {
        QString defaultPath = QCoreApplication::applicationDirPath()
                              + QStringLiteral("/license-SkyBox.dat");
        if (QFileInfo::exists(defaultPath)) {
            pathEdit->setText(defaultPath);
            render();
        } else {
            viewEdit->setPlainText(
                QStringLiteral("未自动找到 license-SkyBox.dat。\n"
                               "请点击“选择...”定位授权文件，或把文件放在本程序同目录后点击“刷新”。"));
        }
    }

    void render() {
        const QString path = pathEdit->text().trimmed();
        if (path.isEmpty()) {
            viewEdit->setPlainText(QStringLiteral("请选择授权文件。"));
            return;
        }

        if (modeCombo->currentIndex() == 1) {
            renderHex(path);
            return;
        }

        QFileInfo fi(path);
        if (!fi.exists()) {
            viewEdit->setPlainText(QStringLiteral("文件不存在：") + path);
            return;
        }

        LicenseCore::FileInfo info;
        QString error;
        bool parsed = LicenseCore::readLicenseFile(path, &info, &error);

        QStringList lines;
        lines << QStringLiteral("文件路径：") + fi.absoluteFilePath();
        lines << QStringLiteral("文件大小：%1 字节").arg(fi.size());
        lines << QStringLiteral("");

        if (!parsed) {
            lines << QStringLiteral("解析结果：失败");
            lines << QStringLiteral("原因：") + error;
            lines << QStringLiteral("");
            lines << QStringLiteral("提示：该文件可能不是授权文件，或已被损坏。可切换到“十六进制”查看原始内容。");
            viewEdit->setPlainText(lines.join(QLatin1Char('\n')));
            return;
        }

        lines << QStringLiteral("解析结果：成功");
        lines << QStringLiteral("是否加密：") + (info.encrypted ? QStringLiteral("是")
                                                               : QStringLiteral("否（明文）"));
        lines << QStringLiteral("授权状态：%1").arg(
            info.source == 1 ? QStringLiteral("1（离线激活码）")
                             : (info.source == 2 ? QStringLiteral("2（在线激活）")
                                                 : QStringLiteral("%1（未知）").arg(info.source)));
        lines << QStringLiteral("到期时间：") + LicenseCore::formatExpireTime(info.expireTime);
        lines << QStringLiteral("最后校验：") + LicenseCore::formatExpireTime(info.lastSeenTime);
        if (info.expireTime == 0) {
            lines << QStringLiteral("剩余时间：永久");
        } else {
            qint64 days = remainingDays(info.expireTime, info.lastSeenTime);
            lines << QStringLiteral("剩余时间：%1 天（按最后校验时间估算）").arg(days);
        }
        lines << QStringLiteral("用户名：") + info.username;
        lines << QStringLiteral("邮箱：") + info.email;
        lines << QStringLiteral("机器绑定：") + (info.bindingOk ? QStringLiteral("匹配当前机器")
                                                                : QStringLiteral("不匹配（可能来自其他设备）"));
        lines << QStringLiteral("绑定摘要：") + info.bindingDigestHex;
        lines << QStringLiteral("解密后大小：%1 字节").arg(info.rawSize);
        lines << QStringLiteral("");
        lines << QStringLiteral("已使用激活码序列（%1 个）：").arg(info.usedCodes.size());
        if (info.usedCodes.isEmpty()) {
            lines << QStringLiteral("  （无）");
        } else {
            for (const QString &seq : info.usedCodes) {
                lines << QStringLiteral("  ") + seq;
            }
        }

        if (!info.onlineCode.isEmpty()) {
            lines << QStringLiteral("");
            lines << QStringLiteral("在线激活码：") + info.onlineCode;
            lines << QStringLiteral("在线最后校验：") + LicenseCore::formatExpireTime(info.onlineLastVerify);
        }

        viewEdit->setPlainText(lines.join(QLatin1Char('\n')));
    }

    static qint64 remainingDays(uint32_t expireTime, uint32_t lastSeenTime) {
        if (expireTime == 0) return -1;
        if (expireTime <= lastSeenTime) return 0;
        return (static_cast<qint64>(expireTime) - static_cast<qint64>(lastSeenTime)) / 86400;
    }

    void renderHex(const QString &path) {
        QFileInfo fi(path);
        if (!fi.exists()) {
            viewEdit->setPlainText(QStringLiteral("文件不存在：") + path);
            return;
        }

        QByteArray data;
        QString error;
        bool decrypted = LicenseCore::decryptLicenseFile(path, &data, &error);
        if (!decrypted) {
            QFile raw(path);
            if (raw.open(QIODevice::ReadOnly)) {
                data = raw.readAll();
                raw.close();
            }
        }

        QStringList lines;
        lines << QStringLiteral("文件路径：") + fi.absoluteFilePath();
        lines << QStringLiteral("文件大小：%1 字节").arg(fi.size());
        lines << QStringLiteral("内容：") + (decrypted ? QStringLiteral("解密后数据")
                                                       : QStringLiteral("原始文件数据（解密失败）"));
        lines << QStringLiteral("");

        const int width = 16;
        for (int offset = 0; offset < data.size(); offset += width) {
            QByteArray chunk = data.mid(offset, width);
            QString hexPart;
            QString asciiPart;
            for (int i = 0; i < width; ++i) {
                if (i < chunk.size()) {
                    unsigned char c = static_cast<unsigned char>(chunk.at(i));
                    hexPart += QStringLiteral("%1 ").arg(c, 2, 16, QLatin1Char('0'));
                    asciiPart += (c >= 32 && c < 127) ? QLatin1Char(static_cast<char>(c))
                                                      : QLatin1Char('.');
                } else {
                    hexPart += QStringLiteral("   ");
                }
                if (i == 7) hexPart += QLatin1Char(' ');
            }
            lines << QStringLiteral("%1  %2 |%3|")
                         .arg(offset, 8, 16, QLatin1Char('0'))
                         .arg(hexPart.toUpper(), asciiPart);
        }

        viewEdit->setPlainText(lines.join(QLatin1Char('\n')));
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("授权文件查看器"));
    applyLicenseTheme(app);

    DatViewerWindow window;
    window.show();
    return app.exec();
}
