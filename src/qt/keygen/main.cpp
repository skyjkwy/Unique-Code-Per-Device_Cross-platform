#include <QApplication>
#include <QByteArray>
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

#include "ecdsa.h"
#include "theme.h"

class KeygenWindow : public QWidget {
public:
    KeygenWindow() {
        buildUi();
    }

private:
    QLineEdit *dirEdit = nullptr;
    QPlainTextEdit *logEdit = nullptr;

    void buildUi() {
        setWindowTitle(QStringLiteral("ECDSA 密钥对生成器"));
        resize(720, 560);

        auto *root = new QVBoxLayout(this);
        root->setContentsMargins(26, 22, 26, 22);
        root->setSpacing(12);

        auto *title = new QLabel(QStringLiteral("ECDSA P-256 密钥对生成器"), this);
        title->setObjectName(QStringLiteral("title"));
        root->addWidget(title);

        auto *hint = new QLabel(
            QStringLiteral("私钥 sky.bin 用于发码，必须严格保密；公钥 sky_share.bin 会嵌入客户端。\n"
                           "更换密钥后需要重新编译客户端与发码工具，旧激活码将失效。"),
            this);
        hint->setObjectName(QStringLiteral("hint"));
        hint->setWordWrap(true);
        root->addWidget(hint);

        auto *dirGroup = new QGroupBox(QStringLiteral("输出目录"), this);
        auto *dirLayout = new QHBoxLayout(dirGroup);
        dirEdit = new QLineEdit(dirGroup);
        QString defaultDir = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("key"));
        dirEdit->setText(QDir::toNativeSeparators(defaultDir));
        auto *browseButton = new QPushButton(QStringLiteral("浏览..."), dirGroup);
        browseButton->setObjectName(QStringLiteral("secondary"));
        dirLayout->addWidget(dirEdit, 1);
        dirLayout->addWidget(browseButton);
        root->addWidget(dirGroup);

        auto *actionRow = new QHBoxLayout();
        auto *generateButton = new QPushButton(QStringLiteral("生成密钥对"), this);
        auto *openButton = new QPushButton(QStringLiteral("打开输出目录"), this);
        openButton->setObjectName(QStringLiteral("secondary"));
        actionRow->addWidget(generateButton);
        actionRow->addWidget(openButton);
        actionRow->addStretch(1);
        root->addLayout(actionRow);

        auto *logGroup = new QGroupBox(QStringLiteral("执行结果"), this);
        auto *logLayout = new QVBoxLayout(logGroup);
        logEdit = new QPlainTextEdit(logGroup);
        logEdit->setReadOnly(true);
        logEdit->setPlaceholderText(QStringLiteral("尚未生成密钥。"));
        logLayout->addWidget(logEdit);
        root->addWidget(logGroup, 1);

        connect(browseButton, &QPushButton::clicked, this, [this]() {
            QString dir = QFileDialog::getExistingDirectory(
                this, QStringLiteral("选择输出目录"), dirEdit->text());
            if (!dir.isEmpty()) {
                dirEdit->setText(QDir::toNativeSeparators(dir));
            }
        });

        connect(openButton, &QPushButton::clicked, this, [this]() {
            QString dir = dirEdit->text().trimmed();
            if (dir.isEmpty()) return;
            QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
        });

        connect(generateButton, &QPushButton::clicked, this, [this]() { doGenerate(); });
    }

    void log(const QString &text) {
        logEdit->appendPlainText(text);
    }

    void doGenerate() {
        QString dir = dirEdit->text().trimmed();
        if (dir.isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("提示"),
                                 QStringLiteral("请先选择输出目录。"));
            return;
        }

        QDir outDir(dir);
        if (!outDir.exists() && !outDir.mkpath(QStringLiteral("."))) {
            QMessageBox::critical(this, QStringLiteral("错误"),
                                  QStringLiteral("无法创建输出目录。"));
            return;
        }

        const QString privPath = outDir.filePath(QStringLiteral("sky.bin"));
        const QString pubPath = outDir.filePath(QStringLiteral("sky_share.bin"));

        if (QFileInfo::exists(privPath) || QFileInfo::exists(pubPath)) {
            auto answer = QMessageBox::question(
                this, QStringLiteral("确认覆盖"),
                QStringLiteral("输出目录已存在 sky.bin 或 sky_share.bin，继续将覆盖旧密钥。\n"
                               "覆盖后旧激活码会全部失效，确定继续吗？"),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (answer != QMessageBox::Yes) return;
        }

        QString error;
        QByteArray privUtf8 = privPath.toUtf8();
        QByteArray pubUtf8 = pubPath.toUtf8();
        if (!ECDSA_GenerateKeyPair(privUtf8.constData(), pubUtf8.constData())) {
            error = QStringLiteral("生成 ECDSA P-256 密钥对失败。\n"
                                   "请检查输出目录是否可写。");
            QMessageBox::critical(this, QStringLiteral("生成失败"), error);
            log(QStringLiteral("生成失败：") + error);
            return;
        }

        log(QStringLiteral("已生成私钥：") + QDir::toNativeSeparators(privPath));
        log(QStringLiteral("已生成公钥：") + QDir::toNativeSeparators(pubPath));
        log(QStringLiteral(""));
        log(QStringLiteral("后续步骤："));
        log(QStringLiteral("1. 将 sky.bin 与 sky_share.bin 放入项目 key/ 目录；"));
        log(QStringLiteral("2. 重新运行 CMake 构建，使新公钥/私钥嵌入程序；"));
        log(QStringLiteral("3. 妥善备份 sky.bin，切勿随客户端分发。"));

        QMessageBox::information(this, QStringLiteral("生成成功"),
                                 QStringLiteral("密钥对已生成。请按下方步骤重新构建项目。"));
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("ECDSA 密钥对生成器"));
    applyLicenseTheme(app);

    KeygenWindow window;
    window.show();
    return app.exec();
}
