// Confirmation, progress, report and recovery-key dialogs.
#pragma once

#include <QDialog>
#include <QJsonArray>

class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QLabel;

/// Shows one or more plans (steps, equivalent commands, warnings) and asks
/// for confirmation, including the confirmation word of critical plans.
class ConfirmDialog : public QDialog
{
    Q_OBJECT

public:
    ConfirmDialog(const QJsonArray &plans, QWidget *parent = nullptr);
    QString confirmText() const;

private:
    QString m_word;
    QLineEdit *m_confirm = nullptr;
    QPushButton *m_run = nullptr;
};

/// Shown while the helper executes; displays progress and command output
/// ("touch your security key").
class ProgressDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ProgressDialog(const QString &title, QWidget *parent = nullptr);
    void append(const QString &line);

protected:
    void reject() override {} // cannot be cancelled

private:
    QPlainTextEdit *m_log = nullptr;
};

/// Shows a freshly generated recovery key once.
class RecoveryKeyDialog : public QDialog
{
    Q_OBJECT

public:
    RecoveryKeyDialog(const QString &key, int slot, QWidget *parent = nullptr);
};

/// Summarize execution reports in a message box with details.
void showReports(const QJsonArray &reports, QWidget *parent);
/// Text form of the reports, for the log tab.
QString reportsText(const QJsonArray &reports);
