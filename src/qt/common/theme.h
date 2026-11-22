#pragma once

#include <QApplication>

inline void applyLicenseTheme(QApplication &app) {
    app.setStyleSheet(QStringLiteral(R"(
        QWidget {
            font-size: 10pt;
            color: #1f2937;
            background: #f5f7fb;
        }
        QGroupBox {
            background: #ffffff;
            border: 1px solid #dfe5ef;
            border-radius: 8px;
            margin-top: 14px;
            padding: 16px 14px 12px 14px;
            font-weight: 600;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            color: #374151;
        }
        QLineEdit, QPlainTextEdit, QSpinBox, QComboBox {
            background: #ffffff;
            border: 1px solid #cfd8e6;
            border-radius: 6px;
            padding: 6px 8px;
            selection-background-color: #2563eb;
        }
        QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus {
            border: 1px solid #2563eb;
        }
        QPushButton {
            background: #2563eb;
            color: #ffffff;
            border: none;
            border-radius: 6px;
            padding: 8px 16px;
            font-weight: 600;
        }
        QPushButton:hover { background: #1d4ed8; }
        QPushButton:pressed { background: #1e40af; }
        QPushButton:disabled { background: #9ca3af; }
        QPushButton#secondary {
            background: #e5e7eb;
            color: #374151;
        }
        QPushButton#secondary:hover { background: #d1d5db; }
        QLabel#title {
            font-size: 18pt;
            font-weight: 700;
            color: #111827;
        }
        QLabel#hint { color: #6b7280; font-size: 9pt; }
        QLabel#ok { color: #059669; font-weight: 600; }
        QLabel#bad { color: #dc2626; font-weight: 600; }
    )"));
}
