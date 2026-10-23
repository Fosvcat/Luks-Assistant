// Dialog generated from a form description sent by the helper
// (luks_assistant_core::forms::Form): native widgets in a QFormLayout.
#pragma once

#include <QDialog>
#include <QJsonObject>
#include <QVector>

class QCheckBox;
class QComboBox;
class QDialogButtonBox;
class QLabel;
class QLineEdit;

class FormDialog : public QDialog
{
    Q_OBJECT

public:
    /// `pcrs`: the PCRs offered by a PCR picker; others are submitted unchecked.
    FormDialog(const QJsonObject &form, const QList<int> &pcrs, QWidget *parent = nullptr);

    /// The form with the values the user entered.
    QJsonObject form() const;
    /// Selected PCRs of the PCR picker, if the form has one.
    QList<int> selectedPcrs() const;

    void setError(const QString &message);
    void setBusy(bool busy);
    void setNotes(const QStringList &notes);

signals:
    void submitRequested();
    void pcrsChanged();

private:
    struct FieldWidgets {
        QString key;
        QString type; // Text, Secret, File, SaveFile, Toggle, Choice, Pcrs, Label, Separator
        QLineEdit *line = nullptr;
        QCheckBox *check = nullptr;
        QComboBox *combo = nullptr;
        QVector<QCheckBox *> pcrs; // indexed by PCR number; null when not offered
        // Everything that makes up the field's rows, hidden together.
        QVector<QWidget *> rows;
        // Shown only while the choice field showKey has one of showIndexes.
        QString showKey;
        QList<int> showIndexes;
        // Editable only while this toggle field is on.
        QString enabledBy;
    };

    void updateVisibility();
    void updateEnabled();

    QJsonObject m_form;
    QVector<FieldWidgets> m_widgets;
    // PCR forms: notes, warnings and errors in a fixed-height box, so the
    // dialog never changes size.
    class QTextBrowser *m_messages = nullptr;
    QStringList m_notesHtml;
    QString m_errorHtml;
    QLabel *m_error = nullptr;
    void showMessages();
    QDialogButtonBox *m_buttons = nullptr;
};
