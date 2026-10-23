#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QMainWindow>
#include <QPointer>

#include "helperclient.h"

namespace Ui {
class MainWindow;
}

class FormDialog;
class ProgressDialog;
class QTreeWidgetItem;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(const QStringList &extraDevices, QWidget *parent = nullptr);
    ~MainWindow() override;

private:
    void startHelper();
    void refreshAll();
    void loadDevice();
    void loadBackups();

    void fillSystem();
    void fillPicker();
    void fillSlots();
    void fillDetail();
    void fillHealth();
    void fillBoot();
    void fillBackups(const QJsonArray &rows);

    QJsonObject slot(int id) const;
    void slotContextMenu(const QPoint &pos);
    void openForm(const QJsonValue &kind, const QString &path = QString());
    void submitForm(FormDialog *dialog, const QString &path);
    void confirm(const QJsonArray &plans);
    void execute(const QJsonArray &ids, const QString &confirm);
    void fixIssue();
    void backupSelected();
    void restoreSelected();
    void saveBackupDir();
    void log(const QString &text);
    void showError(const QString &title, const QString &message);

    Ui::MainWindow *ui;
    HelperClient *m_helper;
    QStringList m_extra;
    QString m_path;
    int m_selected = 0;
    QJsonObject m_system;
    QJsonObject m_device;
    QJsonArray m_boot;
    QPointer<ProgressDialog> m_progress;
};
