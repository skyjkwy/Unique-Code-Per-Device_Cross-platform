#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include "licensecore.h"
#include "theme.h"

class GeneratorWindow : public QWidget {
public:
    GeneratorWindow() {
        buildUi();
        syncTime();
    }

private:
    QPlainTextEdit *machineEdit = nullptr;
    QLineEdit *usernameEdit = nullptr;
    QLineEdit *emailEdit = nullptr;
    QCheckBox *permanentCheck = nullptr;
    QSpinBox *yearsSpin = nullptr;
    QSpinBox *monthsSpin = nullptr;
    QSpinBox *daysSpin = nullptr;
    QSpinBox *hoursSpin = nullptr;
    QSpinBox *minutesSpin = nullptr;
    QSpinBox *secondsSpin = nullptr;
    QPlainTextEdit *outputEdit = nullptr;
    QLabel *timeValue = nullptr;
    QLabel *hintValue = nullptr;
    uint32_t nowTime = 0;
    bool ntpOk = false;

    static QSpinBox *makeSpin(QWidget *parent, int max) {
        auto *spin = new QSpinBox(parent);
        spin->setRange(0, max);
        spin->setValue(0);
        spin->setMinimumWidth(70);
        return spin;
    }

    void buildUi() {
        setWindowTitle(QStringLiteral("一机一码发码工具"));
        resize(760, 760);

        auto *root = new QVBoxLayout(this);
        root->setContentsMargins(26, 22, 26, 22);
        root->setSpacing(12);

        auto *title = new QLabel(QStringLiteral("一机一码发码工具"), this);
        title->setObjectName(QStringLiteral("title"));
        root->addWidget(title);

        auto *subtitle = new QLabel(
            QStringLiteral("本工具内置发码私钥，请仅由授权管理员保管，切勿分发给最终用户。"),
            this);
        subtitle->setObjectName(QStringLiteral("hint"));
        subtitle->setWordWrap(true);
        root->addWidget(subtitle);

        auto *targetGroup = new QGroupBox(QStringLiteral("授权对象"), this);
        auto *targetLayout = new QVBoxLayout(targetGroup);

        machineEdit = new QPlainTextEdit(targetGroup);
        machineEdit->setPlaceholderText(
            QStringLiteral("粘贴用户提供的机器码（明文或混淆码均可）"));
        machineEdit->setFixedHeight(72);
        targetLayout->addWidget(machineEdit);

        auto *form = new QFormLayout();
        usernameEdit = new QLineEdit(targetGroup);
        usernameEdit->setPlaceholderText(QStringLiteral("用户名会写入激活码，必须与用户激活时填写的一致"));
        emailEdit = new QLineEdit(targetGroup);
        emailEdit->setPlaceholderText(QStringLiteral("邮箱可为空，非空时必须与用户激活时填写的一致"));
        form->addRow(QStringLiteral("用户名："), usernameEdit);
        form->addRow(QStringLiteral("邮箱："), emailEdit);
        targetLayout->addLayout(form);
        root->addWidget(targetGroup);

        auto *durationGroup = new QGroupBox(QStringLiteral("授权时长"), this);
        auto *durationLayout = new QVBoxLayout(durationGroup);

        permanentCheck = new QCheckBox(QStringLiteral("永久授权（不过期）"), durationGroup);
        durationLayout->addWidget(permanentCheck);

        auto *grid = new QGridLayout();
        yearsSpin = makeSpin(durationGroup, 99);
        monthsSpin = makeSpin(durationGroup, 999);
        daysSpin = makeSpin(durationGroup, 3650);
        hoursSpin = makeSpin(durationGroup, 99999);
        minutesSpin = makeSpin(durationGroup, 999999);
        secondsSpin = makeSpin(durationGroup, 999999);
        grid->addWidget(new QLabel(QStringLiteral("年"), durationGroup), 0, 0);
        grid->addWidget(yearsSpin, 0, 1);
        grid->addWidget(new QLabel(QStringLiteral("月"), durationGroup), 0, 2);
        grid->addWidget(monthsSpin, 0, 3);
        grid->addWidget(new QLabel(QStringLiteral("天"), durationGroup), 0, 4);
        grid->addWidget(daysSpin, 0, 5);
        grid->addWidget(new QLabel(QStringLiteral("时"), durationGroup), 1, 0);
        grid->addWidget(hoursSpin, 1, 1);
        grid->addWidget(new QLabel(QStringLiteral("分"), durationGroup), 1, 2);
        grid->addWidget(minutesSpin, 1, 3);
        grid->addWidget(new QLabel(QStringLiteral("秒"), durationGroup), 1, 4);
        grid->addWidget(secondsSpin, 1, 5);
        grid->setColumnStretch(6, 1);
        durationLayout->addLayout(grid);
        root->addWidget(durationGroup);

        auto *timeGroup = new QGroupBox(QStringLiteral("发码时间"), this);
        auto *timeLayout = new QHBoxLayout(timeGroup);
        timeValue = new QLabel(timeGroup);
        auto *syncButton = new QPushButton(QStringLiteral("同步网络时间"), timeGroup);
        syncButton->setObjectName(QStringLiteral("secondary"));
        timeLayout->addWidget(timeValue, 1);
        timeLayout->addWidget(syncButton);
        root->addWidget(timeGroup);

        auto *outputGroup = new QGroupBox(QStringLiteral("生成的激活码"), this);
        auto *outputLayout = new QVBoxLayout(outputGroup);
        outputEdit = new QPlainTextEdit(outputGroup);
        outputEdit->setReadOnly(true);
        outputEdit->setPlaceholderText(QStringLiteral("点击下方按钮生成激活码"));
        outputEdit->setFixedHeight(110);
        outputLayout->addWidget(outputEdit);

        auto *buttonRow = new QHBoxLayout();
        auto *generateButton = new QPushButton(QStringLiteral("生成激活码"), outputGroup);
        auto *copyButton = new QPushButton(QStringLiteral("复制激活码"), outputGroup);
        copyButton->setObjectName(QStringLiteral("secondary"));
        buttonRow->addWidget(generateButton);
        buttonRow->addWidget(copyButton);
        buttonRow->addStretch(1);
        outputLayout->addLayout(buttonRow);

        hintValue = new QLabel(QString(), outputGroup);
        hintValue->setObjectName(QStringLiteral("hint"));
        hintValue->setWordWrap(true);
        outputLayout->addWidget(hintValue);
        root->addWidget(outputGroup, 1);

        connect(permanentCheck, &QCheckBox::toggled, this, [this](bool checked) {
            yearsSpin->setEnabled(!checked);
            monthsSpin->setEnabled(!checked);
            daysSpin->setEnabled(!checked);
            hoursSpin->setEnabled(!checked);
            minutesSpin->setEnabled(!checked);
            secondsSpin->setEnabled(!checked);
        });
        connect(syncButton, &QPushButton::clicked, this, [this]() { syncTime(); });
        connect(generateButton, &QPushButton::clicked, this, [this]() { doGenerate(); });
        connect(copyButton, &QPushButton::clicked, this, [this]() {
            const QString code = outputEdit->toPlainText().trimmed();
            if (code.isEmpty()) {
                QMessageBox::warning(this, QStringLiteral("提示"),
                                     QStringLiteral("还没有生成激活码。"));
                return;
            }
            QApplication::clipboard()->setText(code);
            hintValue->setText(QStringLiteral("激活码已复制到剪贴板。"));
            QTimer::singleShot(3000, hintValue, [this]() { hintValue->clear(); });
        });
    }

    static bool looksLikeEmail(const QString &text) {
        if (text.isEmpty()) return true;
        int at = text.indexOf(QLatin1Char('@'));
        if (at <= 0 || at == text.size() - 1) return false;
        int dot = text.lastIndexOf(QLatin1Char('.'));
        return dot > at + 1 && dot < text.size() - 1;
    }

    void syncTime() {
        ntpOk = false;
        nowTime = LicenseCore::ntpNow(&ntpOk);
        timeValue->setText(
            QStringLiteral("发码基准时间：%1  ·  %2")
                .arg(LicenseCore::formatExpireTime(nowTime),
                     ntpOk ? QStringLiteral("NTP 已同步") : QStringLiteral("本地时间（NTP 不可用）")));
    }

    void doGenerate() {
        QString machine = machineEdit->toPlainText().trimmed();
        QString user = usernameEdit->text().trimmed();
        QString email = emailEdit->text().trimmed();

        if (machine.isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("提示"),
                                 QStringLiteral("请先粘贴用户的机器码。"));
            return;
        }

        QString normalized;
        if (!LicenseCore::normalizeMachine(machine, &normalized)) {
            QMessageBox::warning(this, QStringLiteral("机器码无效"),
                                 QStringLiteral("无法识别该机器码，请让用户重新复制。"));
            return;
        }

        if (user.isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("提示"),
                                 QStringLiteral("请填写用户名，激活时会进行一致性校验。"));
            return;
        }
        if (!looksLikeEmail(email)) {
            QMessageBox::warning(this, QStringLiteral("提示"),
                                 QStringLiteral("邮箱格式看起来不正确，请检查。"));
            return;
        }

        uint64_t seconds = 0;
        if (!permanentCheck->isChecked()) {
            LicenseTime time{yearsSpin->value(), monthsSpin->value(), daysSpin->value(),
                             hoursSpin->value(), minutesSpin->value(), secondsSpin->value()};
            seconds = LicenseTimeToSeconds(&time);
            if (seconds == 0) {
                QMessageBox::warning(this, QStringLiteral("提示"),
                                     QStringLiteral("请填写大于 0 的授权时长，或勾选永久授权。"));
                return;
            }
        }

        QString error;
        QString code = LicenseCore::generateCodeAt(normalized, seconds, user, email,
                                                   nowTime, &error);
        if (code.isEmpty()) {
            QMessageBox::critical(this, QStringLiteral("生成失败"), error);
            return;
        }

        outputEdit->setPlainText(code);

        QString durationText = LicenseCore::formatTotalSeconds(seconds);
        QString expireText;
        if (seconds == 0) {
            expireText = QStringLiteral("永久授权");
        } else {
            expireText = QStringLiteral("约 %1").arg(
                LicenseCore::formatExpireTime(nowTime + static_cast<uint32_t>(seconds)));
        }
        hintValue->setText(
            QStringLiteral("已生成：%1，到期时间 %2。请将激活码与用户名/邮箱一同交付用户。")
                .arg(durationText, expireText));
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("一机一码发码工具"));
    applyLicenseTheme(app);

    GeneratorWindow window;
    window.show();
    return app.exec();
}
