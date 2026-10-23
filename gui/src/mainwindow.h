#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QMainWindow>
#include <QPointer>

#include <functional>

#include "helperclient.h"

namespace Ui {
class MainWindow;
}

class FormDialog;
class ProgressDialog;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(const QStringList &extraDevices, QWidget *parent = nullptr);
    ~MainWindow() override;

protected:
    void changeEvent(QEvent *event) override;

private:
    void retranslate();
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
    void backupContextMenu(const QPoint &pos);
    void installCopyMenu(QTreeWidget *tree, const QString &label,
                         const std::function<QString(const QTreeWidgetItem *)> &text);
    void openForm(const QJsonValue &kind, const QString &path = QString());
    void submitForm(FormDialog *dialog, const QString &path);
    void confirm(const QJsonArray &plans);
    void execute(const QJsonArray &ids, const QString &confirm);
    QStringList checkedVolumes() const;
    void updateBackupButtons();
    void backupVolumes(const QStringList &paths);
    void restoreVolume(const QString &path);
    void saveBackupDir();
    void openBackupDir();
    void exportLog();
    void changeLanguage(int index);
    void changeTheme(int index);
    /// Append to the log tab; `english` must already be English.
    void log(const QString &english);
    void showError(const QString &title, const QString &message);

    Ui::MainWindow *ui;
    HelperClient *m_helper;
    QPushButton *m_refresh;
    QStringList m_extra;
    QString m_path;
    int m_selected = 0;
    QJsonObject m_system;
    QJsonObject m_device;
    QJsonArray m_boot;
    QJsonArray m_backupRows;
    QPointer<ProgressDialog> m_progress;
};
