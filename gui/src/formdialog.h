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
    FormDialog(const QJsonObject &form, QWidget *parent = nullptr);

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
        QString type; // Text, Secret, Toggle, Choice, Pcrs, Label
        QLineEdit *line = nullptr;
        QCheckBox *check = nullptr;
        QComboBox *combo = nullptr;
        QVector<QCheckBox *> pcrs;
    };

    QJsonObject m_form;
    QVector<FieldWidgets> m_widgets;
    QLabel *m_notes = nullptr;
    QLabel *m_error = nullptr;
    QDialogButtonBox *m_buttons = nullptr;
};
