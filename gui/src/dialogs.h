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
/// The plans can be replaced while the dialog is open (restore: the user
/// picks the backup file above the list).
class ConfirmDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ConfirmDialog(const QJsonArray &plans, QWidget *parent = nullptr);

    void setPlans(const QJsonArray &plans);
    /// No plan: show `text` instead and disable "Run".
    void setMessage(const QString &text);
    /// Add a widget above the plan list.
    void insertWidget(QWidget *widget);

    QJsonArray plans() const { return m_plans; }
    QString confirmText() const;

private:
    void updateRun();

    QJsonArray m_plans;
    QString m_word;
    class QVBoxLayout *m_layout = nullptr;
    QLabel *m_icon = nullptr;
    class QTextBrowser *m_browser = nullptr;
    QWidget *m_confirmRow = nullptr;
    QLabel *m_confirmLabel = nullptr;
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
/// Text form of the reports, for the details of the message box.
QString reportsText(const QJsonArray &reports);
/// The reports in English, for the log (always English).
QString reportsLog(const QJsonArray &reports);
