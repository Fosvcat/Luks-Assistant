#include "dialogs.h"

#include <QApplication>
#include <QClipboard>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QStyle>
#include <QTextBrowser>
#include <QVBoxLayout>

namespace {

QString esc(const QString &s) { return s.toHtmlEscaped(); }

QLabel *iconLabel(QStyle::StandardPixmap pixmap, QWidget *w)
{
    auto *l = new QLabel;
    const int size = w->style()->pixelMetric(QStyle::PM_MessageBoxIconSize);
    l->setPixmap(w->style()->standardIcon(pixmap).pixmap(size, size));
    l->setAlignment(Qt::AlignTop);
    return l;
}

} // namespace

ConfirmDialog::ConfirmDialog(const QJsonArray &plans, QWidget *parent)
    : QDialog(parent)
{
    setModal(true);
    resize(860, 560);

    m_layout = new QVBoxLayout(this);
    auto *top = new QHBoxLayout;
    m_icon = new QLabel;
    m_icon->setAlignment(Qt::AlignTop);
    top->addWidget(m_icon);
    auto *intro = new QLabel(tr("The following steps will run. Commands are equivalents with passwords hidden."));
    intro->setWordWrap(true);
    top->addWidget(intro, 1);
    m_layout->addLayout(top);

    m_browser = new QTextBrowser;
    m_layout->addWidget(m_browser, 1);

    m_confirmRow = new QWidget;
    auto *row = new QHBoxLayout(m_confirmRow);
    row->setContentsMargins(0, 0, 0, 0);
    m_confirmLabel = new QLabel;
    row->addWidget(m_confirmLabel);
    m_confirm = new QLineEdit;
    row->addWidget(m_confirm, 1);
    m_layout->addWidget(m_confirmRow);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Cancel"));
    m_run = buttons->addButton(tr("Run"), QDialogButtonBox::AcceptRole);
    m_run->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_confirm, &QLineEdit::textChanged, this, &ConfirmDialog::updateRun);
    m_layout->addWidget(buttons);

    setPlans(plans);
}

void ConfirmDialog::insertWidget(QWidget *widget)
{
    m_layout->insertWidget(1, widget);
}

void ConfirmDialog::setPlans(const QJsonArray &plans)
{
    m_plans = plans;
    m_word.clear();
    QString worst = QStringLiteral("Normal");
    QString html;
    for (const QJsonValue &pv : plans) {
        const QJsonObject p = pv.toObject();
        const QString danger = p.value(QStringLiteral("danger")).toString();
        if (danger == QLatin1String("Critical") || (danger == QLatin1String("High") && worst == QLatin1String("Normal")))
            worst = danger;
        if (m_word.isEmpty())
            m_word = p.value(QStringLiteral("confirm_word")).toString();
        html += QStringLiteral("<h3>%1</h3><p style=\"color:gray\">%2</p>")
                    .arg(esc(p.value(QStringLiteral("title")).toString()),
                         esc(p.value(QStringLiteral("device")).toString()));
        const QJsonArray warnings = p.value(QStringLiteral("warnings")).toArray();
        if (!warnings.isEmpty()) {
            html += QStringLiteral("<ul>");
            for (const QJsonValue &w : warnings)
                html += QStringLiteral("<li style=\"color:#d4720b\">%1</li>").arg(esc(w.toString()));
            html += QStringLiteral("</ul>");
        }
        html += QStringLiteral("<ol>");
        for (const QJsonValue &sv : p.value(QStringLiteral("steps")).toArray()) {
            const QJsonObject s = sv.toObject();
            html += QStringLiteral("<li>%1").arg(esc(s.value(QStringLiteral("desc")).toString()));
            const QString cmd = s.value(QStringLiteral("command")).toString();
            if (!cmd.isEmpty())
                html += QStringLiteral("<br><code style=\"color:gray\">$ %1</code>").arg(esc(cmd));
            html += QStringLiteral("</li>");
        }
        html += QStringLiteral("</ol>");
    }
    m_browser->setHtml(html);
    setWindowTitle(plans.size() == 1 ? plans.first().toObject().value(QStringLiteral("title")).toString()
                                     : tr("%1 operations").arg(plans.size()));
    const int size = style()->pixelMetric(QStyle::PM_MessageBoxIconSize);
    m_icon->setPixmap(style()
                          ->standardIcon(worst == QLatin1String("Normal") ? QStyle::SP_MessageBoxQuestion
                                                                          : QStyle::SP_MessageBoxWarning)
                          .pixmap(size, size));
    m_confirmLabel->setText(tr("Type <b>%1</b> to confirm:").arg(esc(m_word)));
    m_confirmRow->setVisible(!m_word.isEmpty());
    m_confirm->clear();
    updateRun();
    if (!m_word.isEmpty())
        m_confirm->setFocus();
}

void ConfirmDialog::setMessage(const QString &text)
{
    setPlans({});
    m_browser->setPlainText(text);
}

void ConfirmDialog::updateRun()
{
    m_run->setEnabled(!m_plans.isEmpty() && (m_word.isEmpty() || m_confirm->text().trimmed() == m_word));
}

QString ConfirmDialog::confirmText() const
{
    return m_word.isEmpty() ? QString() : m_confirm->text().trimmed();
}

ProgressDialog::ProgressDialog(const QString &title, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(title);
    setModal(true);
    resize(600, 320);
    auto *layout = new QVBoxLayout(this);
    auto *label = new QLabel(title);
    label->setWordWrap(true);
    layout->addWidget(label);
    auto *bar = new QProgressBar;
    bar->setRange(0, 0);
    layout->addWidget(bar);
    m_log = new QPlainTextEdit;
    m_log->setReadOnly(true);
    layout->addWidget(m_log, 1);
}

void ProgressDialog::append(const QString &line)
{
    for (const QString &l : line.split(QLatin1Char('\n'), Qt::SkipEmptyParts))
        m_log->appendPlainText(l.trimmed());
}

RecoveryKeyDialog::RecoveryKeyDialog(const QString &key, int slot, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Recovery key"));
    setModal(true);
    auto *layout = new QVBoxLayout(this);
    auto *top = new QHBoxLayout;
    top->addWidget(iconLabel(QStyle::SP_MessageBoxWarning, this));
    auto *text = new QLabel(tr("The recovery key was written to slot %1. It is shown only this once; write it down or print it and keep it offline.").arg(slot));
    text->setWordWrap(true);
    top->addWidget(text, 1);
    layout->addLayout(top);

    auto *edit = new QLineEdit(key);
    edit->setReadOnly(true);
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setPointSizeF(mono.pointSizeF() * 1.3);
    edit->setFont(mono);
    edit->setMinimumWidth(edit->fontMetrics().horizontalAdvance(key) + 40);
    auto *row = new QHBoxLayout;
    row->addWidget(edit, 1);
    auto *copy = new QPushButton(QIcon::fromTheme(QStringLiteral("edit-copy")), tr("Copy"));
    connect(copy, &QPushButton::clicked, this, [key] { QApplication::clipboard()->setText(key); });
    row->addWidget(copy);
    layout->addLayout(row);

    auto *saved = new QCheckBox(tr("I have saved this recovery key"));
    layout->addWidget(saved);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    buttons->button(QDialogButtonBox::Close)->setText(tr("Close"));
    buttons->button(QDialogButtonBox::Close)->setEnabled(false);
    connect(saved, &QCheckBox::toggled, buttons->button(QDialogButtonBox::Close), &QWidget::setEnabled);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::accept);
    layout->addWidget(buttons);
}

QString reportsText(const QJsonArray &reports)
{
    QStringList lines;
    for (const QJsonValue &rv : reports) {
        const QJsonObject r = rv.toObject();
        const bool ok = r.value(QStringLiteral("ok")).toBool();
        lines << QStringLiteral("%1 %2 — %3")
                     .arg(ok ? QStringLiteral("✓") : QStringLiteral("✗"),
                          r.value(QStringLiteral("title")).toString(),
                          r.value(QStringLiteral("device")).toString());
        const QString backup = r.value(QStringLiteral("backup_file")).toString();
        if (!backup.isEmpty())
            lines << QObject::tr("  Backup: %1").arg(backup);
        for (const QJsonValue &sv : r.value(QStringLiteral("steps")).toArray()) {
            const QJsonObject s = sv.toObject();
            lines << QStringLiteral("  %1 %2").arg(s.value(QStringLiteral("ok")).toBool() ? QStringLiteral("✓")
                                                                                         : QStringLiteral("✗"),
                                                   s.value(QStringLiteral("desc")).toString());
            const QString cmd = s.value(QStringLiteral("command")).toString();
            if (!cmd.isEmpty())
                lines << QStringLiteral("      $ ") + cmd;
            for (const QString &o : s.value(QStringLiteral("output")).toString().split(QLatin1Char('\n'), Qt::SkipEmptyParts))
                lines << QStringLiteral("      ") + o;
        }
        const QString error = r.value(QStringLiteral("error")).toString();
        if (!error.isEmpty())
            lines << QObject::tr("  Error: %1").arg(error);
    }
    return lines.join(QLatin1Char('\n'));
}

QString reportsLog(const QJsonArray &reports)
{
    QStringList lines;
    for (const QJsonValue &r : reports)
        lines << r.toObject().value(QStringLiteral("log")).toString().trimmed();
    return lines.join(QLatin1Char('\n'));
}

void showReports(const QJsonArray &reports, QWidget *parent)
{
    bool ok = true;
    QString error;
    QStringList titles;
    for (const QJsonValue &rv : reports) {
        const QJsonObject r = rv.toObject();
        ok &= r.value(QStringLiteral("ok")).toBool();
        titles << r.value(QStringLiteral("title")).toString();
        if (error.isEmpty())
            error = r.value(QStringLiteral("error")).toString();
    }
    QMessageBox box(ok ? QMessageBox::Information : QMessageBox::Critical,
                    ok ? QObject::tr("Done") : QObject::tr("failed"),
                    ok ? titles.join(QLatin1Char('\n')) : error, QMessageBox::Ok, parent);
    box.setDetailedText(reportsText(reports));
    box.exec();
}
