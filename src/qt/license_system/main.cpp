#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include "licensecore.h"
#include "theme.h"

class ActivationWindow : public QWidget {
public:
    ActivationWindow() {
        buildUi();
        refresh();
    }

protected:
    void closeEvent(QCloseEvent *event) override {
        LicenseCore::shutdown();
        QWidget::closeEvent(event);
    }

private:
    QLineEdit *machineEdit = nullptr;
    QLineEdit *usernameEdit = nullptr;
    QLineEdit *emailEdit = nullptr;
    QPlainTextEdit *codeEdit = nullptr;
    QLabel *statusValue = nullptr;
    QLabel *expireValue = nullptr;
    QLabel *remainingValue = nullptr;
    QLabel *sourceValue = nullptr;
    QLabel *timeValue = nullptr;
    QLabel *hintValue = nullptr;

    void buildUi() {
        setWindowTitle(QStringLiteral("一机一码授权中心"));
        resize(720, 680);

        auto *root = new QVBoxLayout(this);
        root->setContentsMargins(26, 22, 26, 22);
        root->setSpacing(12);

        auto *title = new QLabel(QStringLiteral("一机一码授权中心"), this);
        title->setObjectName(QStringLiteral("title"));
        root->addWidget(title);

        auto *subtitle = new QLabel(
            QStringLiteral("机器码与当前设备硬件绑定，激活码由开发者签发。"), this);
        subtitle->setObjectName(QStringLiteral("hint"));
        root->addWidget(subtitle);

        auto *machineGroup = new QGroupBox(QStringLiteral("本机机器码"), this);
        auto *machineLayout = new QHBoxLayout(machineGroup);
        machineEdit = new QLineEdit(machineGroup);
        machineEdit->setReadOnly(true);
        machineEdit->setPlaceholderText(QStringLiteral("正在读取机器码..."));
        auto *copyButton = new QPushButton(QStringLiteral("复制机器码"), machineGroup);
        auto *copyObfButton = new QPushButton(QStringLiteral("复制混淆码"), machineGroup);
        copyObfButton->setObjectName(QStringLiteral("secondary"));
        machineLayout->addWidget(machineEdit, 1);
        machineLayout->addWidget(copyButton);
        machineLayout->addWidget(copyObfButton);
        root->addWidget(machineGroup);

        auto *statusGroup = new QGroupBox(QStringLiteral("授权状态"), this);
        auto *statusForm = new QFormLayout(statusGroup);
        statusValue = new QLabel(QStringLiteral("-"), statusGroup);
        expireValue = new QLabel(QStringLiteral("-"), statusGroup);
        remainingValue = new QLabel(QStringLiteral("-"), statusGroup);
        sourceValue = new QLabel(QStringLiteral("-"), statusGroup);
        timeValue = new QLabel(QStringLiteral("-"), statusGroup);
        statusForm->addRow(QStringLiteral("状态："), statusValue);
        statusForm->addRow(QStringLiteral("到期时间："), expireValue);
        statusForm->addRow(QStringLiteral("剩余时间："), remainingValue);
        statusForm->addRow(QStringLiteral("激活来源："), sourceValue);
        statusForm->addRow(QStringLiteral("可信时间："), timeValue);
        root->addWidget(statusGroup);

        auto *activateGroup = new QGroupBox(QStringLiteral("激活 / 续期"), this);
        auto *activateLayout = new QVBoxLayout(activateGroup);

        codeEdit = new QPlainTextEdit(activateGroup);
        codeEdit->setPlaceholderText(
            QStringLiteral("在此粘贴激活码（支持混淆码，会自动按原样校验）"));
        codeEdit->setFixedHeight(96);
        activateLayout->addWidget(codeEdit);

        auto *form = new QFormLayout();
        usernameEdit = new QLineEdit(activateGroup);
        usernameEdit->setPlaceholderText(QStringLiteral("必须与发码时填写的用户名完全一致"));
        emailEdit = new QLineEdit(activateGroup);
        emailEdit->setPlaceholderText(QStringLiteral("必须与发码时填写的邮箱完全一致（可为空）"));
        form->addRow(QStringLiteral("用户名："), usernameEdit);
        form->addRow(QStringLiteral("邮箱："), emailEdit);
        activateLayout->addLayout(form);

        auto *buttonRow = new QHBoxLayout();
        auto *activateButton = new QPushButton(QStringLiteral("验证并激活"), activateGroup);
        auto *clearButton = new QPushButton(QStringLiteral("清除本机授权"), activateGroup);
        clearButton->setObjectName(QStringLiteral("secondary"));
        auto *refreshButton = new QPushButton(QStringLiteral("刷新状态"), activateGroup);
        refreshButton->setObjectName(QStringLiteral("secondary"));
        buttonRow->addWidget(activateButton);
        buttonRow->addWidget(refreshButton);
        buttonRow->addStretch(1);
        buttonRow->addWidget(clearButton);
        activateLayout->addLayout(buttonRow);

        hintValue = new QLabel(QString(), activateGroup);
        hintValue->setObjectName(QStringLiteral("hint"));
        hintValue->setWordWrap(true);
        activateLayout->addWidget(hintValue);

        root->addWidget(activateGroup, 1);

        connect(copyButton, &QPushButton::clicked, this, [this]() {
            QApplication::clipboard()->setText(machineEdit->text());
            hintValue->setText(QStringLiteral("机器码已复制到剪贴板。"));
            QTimer::singleShot(3000, hintValue, [this]() { hintValue->clear(); });
        });
        connect(copyObfButton, &QPushButton::clicked, this, [this]() {
            QString obf = LicenseCore::obfuscatedMachineCode();
            if (obf.isEmpty()) obf = machineEdit->text();
            QApplication::clipboard()->setText(obf);
            hintValue->setText(QStringLiteral("混淆机器码已复制，可直接粘贴到发码工具。"));
            QTimer::singleShot(3000, hintValue, [this]() { hintValue->clear(); });
        });
        connect(activateButton, &QPushButton::clicked, this, [this]() { doActivate(); });
        connect(clearButton, &QPushButton::clicked, this, [this]() { doClear(); });
        connect(refreshButton, &QPushButton::clicked, this, [this]() { refresh(); });

        auto *timer = new QTimer(this);
        connect(timer, &QTimer::timeout, this, [this]() { refresh(); });
        timer->start(30000);
    }

    static bool looksLikeEmail(const QString &text) {
        if (text.isEmpty()) return true;
        int at = text.indexOf(QLatin1Char('@'));
        if (at <= 0 || at == text.size() - 1) return false;
        int dot = text.lastIndexOf(QLatin1Char('.'));
        return dot > at + 1 && dot < text.size() - 1;
    }

    void refresh() {
        machineEdit->setText(LicenseCore::machineCode());

        LicenseCore::Info info = LicenseCore::info();

        QString statusText;
        QString style;
        switch (info.status) {
            case LICENSE_STATUS_ACTIVATED:
                statusText = QStringLiteral("已激活");
                style = QStringLiteral("color:#059669;font-weight:600;");
                break;
            case LICENSE_STATUS_PERMANENT:
                statusText = QStringLiteral("已激活（永久授权）");
                style = QStringLiteral("color:#059669;font-weight:600;");
                break;
            case LICENSE_STATUS_EXPIRED:
                statusText = QStringLiteral("已过期");
                style = QStringLiteral("color:#dc2626;font-weight:600;");
                break;
            default:
                statusText = QStringLiteral("未激活");
                style = QStringLiteral("color:#dc2626;font-weight:600;");
                break;
        }
        statusValue->setText(statusText);
        statusValue->setStyleSheet(style);

        expireValue->setText(LicenseCore::formatExpireTime(info.expireTime));

        if (info.status == LICENSE_STATUS_PERMANENT) {
            remainingValue->setText(QStringLiteral("永久"));
        } else if (info.status == LICENSE_STATUS_ACTIVATED) {
            remainingValue->setText(QStringLiteral("%1 天").arg(info.remainingDays));
        } else {
            remainingValue->setText(QStringLiteral("-"));
        }

        switch (info.source) {
            case LICENSE_SOURCE_OFFLINE:
                sourceValue->setText(QStringLiteral("离线激活码"));
                break;
            case LICENSE_SOURCE_ONLINE:
                sourceValue->setText(QStringLiteral("在线激活"));
                break;
            default:
                sourceValue->setText(QStringLiteral("无"));
                break;
        }

        timeValue->setText(LicenseCore::formatExpireTime(info.currentTime));
    }

    void doActivate() {
        QString code = codeEdit->toPlainText().trimmed();
        QString user = usernameEdit->text().trimmed();
        QString email = emailEdit->text().trimmed();

        if (code.isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("提示"),
                                 QStringLiteral("请先粘贴激活码。"));
            return;
        }
        if (user.isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("提示"),
                                 QStringLiteral("请填写用户名，且必须与发码时填写的完全一致。"));
            return;
        }
        if (!looksLikeEmail(email)) {
            QMessageBox::warning(this, QStringLiteral("提示"),
                                 QStringLiteral("邮箱格式看起来不正确，请检查。"));
            return;
        }

        QString error;
        if (!LicenseCore::activate(code, user, email, &error)) {
            QMessageBox box(QMessageBox::Critical, QStringLiteral("激活失败"),
                            QStringLiteral("激活码未通过校验。"), QMessageBox::Ok, this);
            box.setDetailedText(error);
            box.exec();
            hintValue->setText(QStringLiteral("激活失败：%1").arg(error));
            refresh();
            return;
        }

        QMessageBox::information(this, QStringLiteral("激活成功"),
                                 QStringLiteral("授权已写入本机。"));
        codeEdit->clear();
        hintValue->clear();
        refresh();
    }

    void doClear() {
        auto answer = QMessageBox::question(
            this, QStringLiteral("确认清除"),
            QStringLiteral("确定要清除本机授权吗？清除后需要重新激活。"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (answer != QMessageBox::Yes) return;

        QString error;
        if (!LicenseCore::clear(&error)) {
            QMessageBox::critical(this, QStringLiteral("清除失败"), error);
            return;
        }
        QMessageBox::information(this, QStringLiteral("已清除"),
                                 QStringLiteral("本机授权已清除。"));
        refresh();
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("一机一码授权中心"));
    applyLicenseTheme(app);

    QString error;
    if (!LicenseCore::init(&error)) {
        QMessageBox::critical(nullptr, QStringLiteral("初始化失败"), error);
        return 1;
    }

    ActivationWindow window;
    window.show();
    int rc = app.exec();
    LicenseCore::shutdown();
    return rc;
}
