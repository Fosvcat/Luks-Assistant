#include "formdialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

// Rust serializes the field value as an externally tagged enum:
// {"Text": ".."}, {"Secret": ".."}, {"File": ".."}, {"SaveFile": ".."},
// {"Toggle": true}, {"Choice": {"options": [..], "index": 0}},
// {"Pcrs": [false, ..]}, "Label", "Separator".
QString valueType(const QJsonValue &v)
{
    if (v.isString())
        return v.toString();
    const QJsonObject o = v.toObject();
    return o.isEmpty() ? QString() : o.keys().first();
}

QLabel *hintLabel(const QString &text)
{
    auto *l = new QLabel(text);
    l->setWordWrap(true);
    l->setEnabled(false); // rendered in the style's inactive text color
    QFont f = l->font();
    f.setPointSizeF(f.pointSizeF() * 0.9);
    l->setFont(f);
    return l;
}

} // namespace

FormDialog::FormDialog(const QJsonObject &form, QWidget *parent)
    : QDialog(parent)
    , m_form(form)
{
    setWindowTitle(form.value(QStringLiteral("title")).toString());
    setModal(true);
    setMinimumWidth(560);

    auto *outer = new QVBoxLayout(this);
    auto *layout = new QFormLayout;
    layout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    outer->addLayout(layout);

    const QJsonArray fields = form.value(QStringLiteral("fields")).toArray();
    for (const QJsonValue &fv : fields) {
        const QJsonObject f = fv.toObject();
        const QString label = f.value(QStringLiteral("label")).toString();
        const QString hint = f.value(QStringLiteral("hint")).toString();
        const QJsonValue value = f.value(QStringLiteral("value"));
        FieldWidgets w;
        w.key = f.value(QStringLiteral("key")).toString();
        w.type = valueType(value);
        const QJsonValue inner = value.toObject().value(w.type);
        const QJsonObject showIf = f.value(QStringLiteral("show_if")).toObject();
        w.showKey = showIf.value(QStringLiteral("key")).toString();
        for (const QJsonValue &i : showIf.value(QStringLiteral("any_of")).toArray())
            w.showIndexes << i.toInt();
        auto addRow = [&](QWidget *field) {
            auto *l = new QLabel(label);
            l->setBuddy(field);
            layout->addRow(l, field);
            w.rows << l << field;
        };
        auto addHint = [&] {
            if (hint.isEmpty())
                return;
            QLabel *h = hintLabel(hint);
            layout->addRow(QString(), h);
            w.rows << h;
        };

        if (w.type == QLatin1String("Text") || w.type == QLatin1String("Secret")) {
            w.line = new QLineEdit(inner.toString());
            if (w.type == QLatin1String("Secret"))
                w.line->setEchoMode(QLineEdit::Password);
            w.line->setPlaceholderText(hint);
            w.line->setToolTip(hint);
            addRow(w.line);
        } else if (w.type == QLatin1String("File") || w.type == QLatin1String("SaveFile")) {
            auto *box = new QWidget;
            auto *row = new QHBoxLayout(box);
            row->setContentsMargins(0, 0, 0, 0);
            w.line = new QLineEdit(inner.toString());
            w.line->setPlaceholderText(hint);
            auto *browse = new QPushButton(tr("浏览…"));
            row->addWidget(w.line, 1);
            row->addWidget(browse);
            const bool save = w.type == QLatin1String("SaveFile");
            QLineEdit *line = w.line;
            connect(browse, &QPushButton::clicked, this, [this, line, save, label] {
                const QString start = line->text().isEmpty() ? QStringLiteral("/") : line->text();
                const QString path = save ? QFileDialog::getSaveFileName(this, label, start)
                                          : QFileDialog::getOpenFileName(this, label, QFileInfo(start).path());
                if (!path.isEmpty())
                    line->setText(path);
            });
            addRow(box);
        } else if (w.type == QLatin1String("Toggle")) {
            w.check = new QCheckBox(label);
            w.check->setChecked(inner.toBool());
            layout->addRow(QString(), w.check);
            w.rows << w.check;
            addHint();
        } else if (w.type == QLatin1String("Choice")) {
            w.combo = new QComboBox;
            const QJsonObject c = inner.toObject();
            for (const QJsonValue &o : c.value(QStringLiteral("options")).toArray())
                w.combo->addItem(o.toString());
            w.combo->setCurrentIndex(c.value(QStringLiteral("index")).toInt());
            connect(w.combo, &QComboBox::currentIndexChanged, this, &FormDialog::updateVisibility);
            addRow(w.combo);
            addHint();
        } else if (w.type == QLatin1String("Pcrs")) {
            auto *box = new QWidget;
            auto *grid = new QGridLayout(box);
            grid->setContentsMargins(0, 0, 0, 0);
            const QJsonArray set = inner.toArray();
            for (int i = 0; i < 24; ++i) {
                auto *cb = new QCheckBox(QString::number(i));
                cb->setChecked(set.at(i).toBool());
                connect(cb, &QCheckBox::toggled, this, &FormDialog::pcrsChanged);
                grid->addWidget(cb, i / 8, i % 8);
                w.pcrs.push_back(cb);
            }
            addRow(box);
        } else if (w.type == QLatin1String("Separator")) {
            auto *gap = new QWidget;
            gap->setFixedHeight(fontMetrics().height());
            layout->addRow(gap);
            w.rows << gap;
        } else {
            QLabel *l = hintLabel(label);
            layout->addRow(l);
            w.rows << l;
        }
        m_widgets.push_back(w);
    }

    m_notes = new QLabel;
    m_notes->setWordWrap(true);
    m_notes->setTextFormat(Qt::RichText);
    m_notes->hide();
    outer->addWidget(m_notes);

    m_error = new QLabel;
    m_error->setWordWrap(true);
    m_error->hide();
    outer->addWidget(m_error);

    outer->addStretch();
    m_buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    // Most forms lead to a plan to confirm; these two act at once.
    const QJsonValue kind = form.value(QStringLiteral("kind"));
    m_buttons->button(QDialogButtonBox::Ok)->setText(kind == QLatin1String("Verify")      ? tr("验证")
                                                     : kind == QLatin1String("BackupDir") ? tr("保存")
                                                                                          : tr("下一步"));
    m_buttons->button(QDialogButtonBox::Cancel)->setText(tr("取消"));
    connect(m_buttons, &QDialogButtonBox::accepted, this, &FormDialog::submitRequested);
    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    outer->addWidget(m_buttons);
    updateVisibility();
}

void FormDialog::updateVisibility()
{
    for (const FieldWidgets &w : m_widgets) {
        if (w.showKey.isEmpty())
            continue;
        int index = -1;
        for (const FieldWidgets &c : m_widgets)
            if (c.combo && c.key == w.showKey)
                index = c.combo->currentIndex();
        const bool shown = w.showIndexes.contains(index);
        for (QWidget *r : w.rows)
            r->setVisible(shown);
    }
    // Let the layout drop the hidden rows before shrinking to fit.
    layout()->activate();
    adjustSize();
}

QJsonObject FormDialog::form() const
{
    QJsonObject form = m_form;
    QJsonArray fields = form.value(QStringLiteral("fields")).toArray();
    for (int i = 0; i < fields.size() && i < m_widgets.size(); ++i) {
        QJsonObject f = fields.at(i).toObject();
        const FieldWidgets &w = m_widgets.at(i);
        QJsonValue value = f.value(QStringLiteral("value"));
        if (w.line) {
            value = QJsonObject{{w.type, w.line->text()}};
        } else if (w.check) {
            value = QJsonObject{{w.type, w.check->isChecked()}};
        } else if (w.combo) {
            QJsonObject c = value.toObject().value(w.type).toObject();
            c.insert(QStringLiteral("index"), w.combo->currentIndex());
            value = QJsonObject{{w.type, c}};
        } else if (!w.pcrs.isEmpty()) {
            QJsonArray set;
            for (QCheckBox *cb : w.pcrs)
                set.append(cb->isChecked());
            value = QJsonObject{{w.type, set}};
        }
        f.insert(QStringLiteral("value"), value);
        fields[i] = f;
    }
    form.insert(QStringLiteral("fields"), fields);
    return form;
}

QList<int> FormDialog::selectedPcrs() const
{
    QList<int> out;
    for (const FieldWidgets &w : m_widgets)
        for (int i = 0; i < w.pcrs.size(); ++i)
            if (w.pcrs.at(i)->isChecked())
                out << i;
    return out;
}


void FormDialog::setError(const QString &message)
{
    m_error->setText(QStringLiteral("<b>%1</b>").arg(message.toHtmlEscaped()));
    QPalette p = m_error->palette();
    p.setColor(QPalette::WindowText, QColor(0xda, 0x44, 0x53));
    m_error->setPalette(p);
    m_error->setVisible(!message.isEmpty());
}

void FormDialog::setBusy(bool busy)
{
    setCursor(busy ? Qt::WaitCursor : Qt::ArrowCursor);
    m_buttons->setEnabled(!busy);
}

void FormDialog::setNotes(const QStringList &notes)
{
    QStringList html;
    for (const QString &n : notes) {
        const bool warn = n.startsWith(QStringLiteral("⚠"));
        html << (warn ? QStringLiteral("<span style=\"color:#d4720b\">%1</span>").arg(n.toHtmlEscaped())
                      : n.toHtmlEscaped());
    }
    m_notes->setText(html.join(QStringLiteral("<br>")));
    m_notes->setVisible(!notes.isEmpty());
}
