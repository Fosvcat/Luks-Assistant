#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "dialogs.h"
#include "formdialog.h"

#include <QDateTime>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QStandardItemModel>
#include <QStyle>
#include <QTreeWidget>

#include <algorithm>

namespace {

const auto S = [](const char *s) { return QString::fromUtf8(s); };

QString str(const QJsonObject &o, const char *key) { return o.value(QLatin1String(key)).toString(); }
QJsonArray arr(const QJsonObject &o, const char *key) { return o.value(QLatin1String(key)).toArray(); }

QIcon themed(std::initializer_list<const char *> names, QStyle::StandardPixmap fallback, const QStyle *style)
{
    for (const char *n : names) {
        const QIcon icon = QIcon::fromTheme(QString::fromLatin1(n));
        if (!icon.isNull())
            return icon;
    }
    return style->standardIcon(fallback);
}

QIcon kindIcon(const QString &kind, const QString &state, const QStyle *style)
{
    if (state == QLatin1String("bad"))
        return themed({"dialog-warning"}, QStyle::SP_MessageBoxWarning, style);
    if (kind == QLatin1String("passphrase") || kind == QLatin1String("secret") || kind == QLatin1String("luks1"))
        return themed({"dialog-password", "password-copy"}, QStyle::SP_DialogYesButton, style);
    if (kind == QLatin1String("keyfile"))
        return themed({"document-encrypted", "application-pgp-keys"}, QStyle::SP_FileIcon, style);
    if (kind == QLatin1String("recovery"))
        return themed({"document-save", "media-floppy"}, QStyle::SP_DialogSaveButton, style);
    if (kind == QLatin1String("tpm2"))
        return themed({"cpu", "security-high"}, QStyle::SP_ComputerIcon, style);
    if (kind == QLatin1String("fido2"))
        return themed({"drive-removable-media-usb", "media-flash"}, QStyle::SP_DriveFDIcon, style);
    if (kind == QLatin1String("pkcs11"))
        return themed({"auth-sim", "media-flash-smart-media"}, QStyle::SP_DriveCDIcon, style);
    if (kind == QLatin1String("empty"))
        return {};
    return themed({"emblem-system"}, QStyle::SP_FileDialogInfoView, style);
}

QIcon statusIcon(const QString &status, const QStyle *style)
{
    if (status == QLatin1String("Ok") || status == QLatin1String("ok"))
        return themed({"dialog-ok-apply", "emblem-ok-symbolic"}, QStyle::SP_DialogApplyButton, style);
    if (status == QLatin1String("Fail") || status == QLatin1String("critical"))
        return style->standardIcon(QStyle::SP_MessageBoxCritical);
    if (status == QLatin1String("Warn") || status == QLatin1String("warning"))
        return style->standardIcon(QStyle::SP_MessageBoxWarning);
    if (status == QLatin1String("Unknown"))
        return style->standardIcon(QStyle::SP_MessageBoxQuestion);
    return style->standardIcon(QStyle::SP_MessageBoxInformation);
}

void clearLayout(QLayout *layout)
{
    while (layout->count() > 0) {
        QLayoutItem *item = layout->takeAt(0);
        if (QWidget *w = item->widget())
            w->deleteLater();
        if (QLayout *l = item->layout())
            clearLayout(l);
        delete item;
    }
}

} // namespace

MainWindow::MainWindow(const QStringList &extraDevices, QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_helper(new HelperClient(this))
    , m_extra(extraDevices)
{
    ui->setupUi(this);
    setWindowIcon(QIcon::fromTheme(S("drive-harddisk-encrypted"), QIcon::fromTheme(S("security-high"))));
    ui->refreshButton->setIcon(QIcon::fromTheme(S("view-refresh")));
    ui->verifyButton->setIcon(QIcon::fromTheme(S("dialog-ok-apply")));
    ui->backupButton->setIcon(QIcon::fromTheme(S("document-save")));
    ui->restoreButton->setIcon(QIcon::fromTheme(S("document-revert")));
    ui->browseButton->setIcon(QIcon::fromTheme(S("document-open-folder")));
    ui->fixButton->setIcon(QIcon::fromTheme(S("tools-wizard")));

    auto *table = ui->slotTable;
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    table->verticalHeader()->setDefaultSectionSize(table->fontMetrics().height() * 3 + 10);
    table->horizontalHeader()->hide();
    table->verticalHeader()->hide();
    table->setFixedHeight(4 * table->verticalHeader()->defaultSectionSize() + 2 * table->frameWidth());
    table->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    table->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    ui->slotsLayout->setStretchFactor(ui->detailGroup, 1);
    ui->detailGroupLayout->addStretch();
    table->setIconSize(QSize(22, 22));

    ui->systemTree->setHeaderLabels({S("项目"), S("值")});
    ui->diskTree->setHeaderLabels({S("名称"), S("大小"), S("加密"), S("TRIM"), S("挂载点")});
    ui->diskTree->setColumnCount(5);
    ui->pcrTree->setHeaderLabels({S("PCR"), S("当前值"), S("用途")});
    ui->pcrTree->setRootIsDecorated(false);
    ui->issueTree->setHeaderLabels({S("级别"), S("问题"), S("说明")});
    ui->issueTree->setRootIsDecorated(false);
    ui->issueTree->setWordWrap(true);
    ui->bootTree->setHeaderLabels({S("状态"), S("项目"), S("详情")});
    ui->bootTree->setRootIsDecorated(false);
    ui->bootTree->setWordWrap(true);
    ui->backupTree->setHeaderLabels({S("卷"), S("UUID"), S("最后备份"), S("数量"), S("文件")});
    ui->backupTree->setColumnCount(5);
    ui->backupTree->setRootIsDecorated(false);
    for (QTreeWidget *t : {ui->systemTree, ui->diskTree, ui->pcrTree, ui->issueTree, ui->bootTree, ui->backupTree})
        t->setAlternatingRowColors(true);

    connect(ui->refreshButton, &QPushButton::clicked, this, &MainWindow::refreshAll);
    connect(ui->diskCombo, qOverload<int>(&QComboBox::activated), this, [this](int index) {
        const QString path = ui->diskCombo->itemData(index).toString();
        if (path.isEmpty() || path == m_path)
            return;
        m_path = path;
        m_selected = 0;
        loadDevice();
    });
    connect(table, &QTableWidget::currentCellChanged, this, [this](int row, int col) {
        if (row < 0 || col < 0)
            return;
        m_selected = row * 8 + col;
        fillDetail();
    });
    connect(table, &QTableWidget::cellDoubleClicked, this, [this](int row, int col) {
        const QJsonArray actions = arr(slot(row * 8 + col), "actions");
        if (!actions.isEmpty())
            openForm(actions.first().toObject().value(S("form")));
    });
    connect(table, &QWidget::customContextMenuRequested, this, &MainWindow::slotContextMenu);
    connect(ui->verifyButton, &QPushButton::clicked, this, [this] { openForm(S("Verify")); });
    connect(ui->trimButton, &QPushButton::clicked, this, [this] { openForm(S("Discards")); });
    connect(ui->fixButton, &QPushButton::clicked, this, &MainWindow::fixIssue);
    connect(ui->issueTree, &QTreeWidget::itemDoubleClicked, this, &MainWindow::fixIssue);
    connect(ui->selectAllButton, &QPushButton::clicked, this, [this] {
        auto *t = ui->backupTree;
        bool all = true;
        for (int i = 0; i < t->topLevelItemCount(); ++i)
            all &= t->topLevelItem(i)->checkState(0) == Qt::Checked;
        for (int i = 0; i < t->topLevelItemCount(); ++i)
            t->topLevelItem(i)->setCheckState(0, all ? Qt::Unchecked : Qt::Checked);
    });
    connect(ui->backupButton, &QPushButton::clicked, this, &MainWindow::backupSelected);
    connect(ui->restoreButton, &QPushButton::clicked, this, &MainWindow::restoreSelected);
    connect(ui->saveDirButton, &QPushButton::clicked, this, &MainWindow::saveBackupDir);
    connect(ui->browseButton, &QPushButton::clicked, this, [this] {
        const QString dir = QFileDialog::getExistingDirectory(this, S("备份位置"), ui->backupDirEdit->text());
        if (!dir.isEmpty())
            ui->backupDirEdit->setText(dir);
    });

    connect(m_helper, &HelperClient::ready, this, &MainWindow::refreshAll);
    connect(m_helper, &HelperClient::failed, this, [this](const QString &message) {
        statusBar()->showMessage(S("后端未连接，点击“刷新”重试"));
        showError(S("无法启动后端"), message);
    });
    connect(m_helper, &HelperClient::event, this, [this](const QString &kind, const QString &text) {
        if (m_progress)
            m_progress->append(kind == QLatin1String("progress") ? S("▶ ") + text : text);
    });

    fillDetail();
    startHelper();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::showError(const QString &title, const QString &message)
{
    QMessageBox::warning(this, title, message);
}

void MainWindow::log(const QString &text)
{
    ui->logView->appendPlainText(QStringLiteral("[%1] %2").arg(QDateTime::currentDateTime().toString(Qt::ISODate), text));
}

void MainWindow::startHelper()
{
    statusBar()->showMessage(S("正在请求管理员权限…"));
    m_helper->start();
}

// ---- loading -------------------------------------------------------------

void MainWindow::refreshAll()
{
    if (!m_helper->isRunning())
        return startHelper();
    statusBar()->showMessage(S("正在读取…"));
    QJsonArray extra;
    for (const QString &e : m_extra)
        extra.append(e);
    m_helper->call(S("system_view"), QJsonObject{{S("extra"), extra}}, [this](const QJsonValue &ok, const QString &err) {
        if (!err.isEmpty())
            return showError(S("读取失败"), err);
        m_system = ok.toObject();
        fillSystem();
        fillPicker();
        loadDevice();
    });
}

void MainWindow::loadDevice()
{
    if (m_path.isEmpty()) {
        m_device = {};
        fillSlots();
        fillDetail();
        statusBar()->showMessage(S("没有 LUKS 卷"));
        return;
    }
    m_helper->call(S("device_view"), QJsonObject{{S("path"), m_path}}, [this](const QJsonValue &ok, const QString &err) {
        if (!err.isEmpty()) {
            m_device = {};
            fillSlots();
            fillDetail();
            statusBar()->showMessage(S("读取失败：") + err);
            return;
        }
        const QJsonObject reply = ok.toObject();
        m_device = reply.value(S("device")).toObject();
        m_boot = reply.value(S("boot")).toArray();
        fillSlots();
        fillDetail();
        fillHealth();
        fillBoot();
        fillSystem(); // bound PCRs are highlighted
        statusBar()->showMessage(S("就绪"));
        loadBackups();
    });
}

void MainWindow::loadBackups()
{
    QJsonArray paths;
    for (const QJsonValue &v : arr(m_system, "picker"))
        if (v.toObject().value(S("selectable")).toBool())
            paths.append(v.toObject().value(S("path")));
    m_helper->call(S("backup_rows"), QJsonObject{{S("paths"), paths}}, [this](const QJsonValue &ok, const QString &err) {
        if (err.isEmpty())
            fillBackups(ok.toArray());
    });
}

// ---- filling the pages ----------------------------------------------------------

void MainWindow::fillSystem()
{
    ui->summaryLabel->setText(str(m_system, "summary"));
    ui->volumeCountLabel->setText(S("LUKS 卷 %1/%2")
                                      .arg(m_system.value(S("luks_volumes")).toInt())
                                      .arg(m_system.value(S("total_volumes")).toInt()));
    ui->backupDirEdit->setText(str(m_system, "backup_root"));
    ui->backupDirEdit->setPlaceholderText(str(m_system, "default_backup_root"));

    // Key/value rows share two columns; titles, device names and feature
    // checks span both so long text does not push the values off-screen.
    auto *sys = ui->systemTree;
    sys->clear();
    int keyWidth = 0;
    auto spanned = [sys](QTreeWidgetItem *parent, const QString &text) {
        auto *item = parent ? new QTreeWidgetItem(parent, {text}) : new QTreeWidgetItem(sys, {text});
        item->setFirstColumnSpanned(true);
        return item;
    };
    auto group = [&spanned](const QString &title) {
        auto *g = spanned(nullptr, title);
        QFont f = g->font(0);
        f.setBold(true);
        g->setFont(0, f);
        return g;
    };
    auto rows = [&keyWidth, sys](QTreeWidgetItem *g, const QJsonArray &rs) {
        for (const QJsonValue &r : rs) {
            const QString key = str(r.toObject(), "key");
            new QTreeWidgetItem(g, {key, str(r.toObject(), "value")});
            keyWidth = std::max(keyWidth, sys->fontMetrics().horizontalAdvance(key));
        }
    };
    rows(group(S("系统")), arr(m_system, "system"));
    rows(group(S("TPM")), arr(m_system, "tpm"));
    for (const auto &[title, key] : {std::pair{S("FIDO2 安全密钥"), "fido2"}, std::pair{S("PKCS#11 智能卡"), "pkcs11"}}) {
        auto *g = group(title);
        const QJsonArray list = arr(m_system, key);
        if (list.isEmpty())
            spanned(g, S("未检测到"));
        for (const QJsonValue &d : list)
            spanned(g, d.toString());
    }
    auto *caps = group(S("功能"));
    for (const QJsonValue &c : arr(m_system, "caps")) {
        const QJsonArray pair = c.toArray();
        auto *item = spanned(caps, pair.at(0).toString());
        item->setIcon(0, statusIcon(pair.at(1).toBool() ? S("Ok") : S("Fail"), style()));
    }
    sys->expandAll();
    sys->setColumnWidth(0, keyWidth + 2 * sys->indentation() + 16);

    auto *disks = ui->diskTree;
    disks->clear();
    QVector<QTreeWidgetItem *> parents;
    for (const QJsonValue &v : arr(m_system, "disks")) {
        const QJsonObject d = v.toObject();
        const int depth = d.value(S("depth")).toInt();
        parents.resize(depth);
        const QJsonValue trim = d.value(S("trim"));
        const QStringList cols = {str(d, "name"), str(d, "size"), str(d, "encryption"),
                                  trim.isNull() ? QString() : (trim.toBool() ? S("✓") : S("✗")), str(d, "mount")};
        auto *item = depth == 0 || parents.isEmpty() ? new QTreeWidgetItem(disks, cols)
                                                     : new QTreeWidgetItem(parents.last(), cols);
        item->setToolTip(0, QStringList{str(d, "path"), str(d, "kind"), str(d, "fstype"), str(d, "model")}.join(S("  ")));
        if (d.value(S("luks")).toBool())
            item->setIcon(0, QIcon::fromTheme(S("drive-harddisk-encrypted"), style()->standardIcon(QStyle::SP_DriveHDIcon)));
        parents.append(item);
    }
    disks->expandAll();
    for (int c = 0; c < 4; ++c)
        disks->resizeColumnToContents(c);

    QSet<int> bound;
    for (const QJsonValue &p : arr(m_device, "bound_pcrs"))
        bound.insert(p.toInt());
    auto *pcrs = ui->pcrTree;
    pcrs->clear();
    for (const QJsonValue &v : arr(m_system, "pcrs")) {
        const QJsonObject p = v.toObject();
        const int index = p.value(S("index")).toInt();
        const QString value = str(p, "value");
        auto *item = new QTreeWidgetItem(pcrs, {QString::number(index), value.isEmpty() ? S("—") : value.left(16) + S("…"), str(p, "name")});
        item->setToolTip(2, S("%1\n改变：%2").arg(str(p, "measures"), str(p, "changes")));
        item->setToolTip(1, value);
        if (bound.contains(index)) {
            for (int c = 0; c < 3; ++c) {
                QFont f = item->font(c);
                f.setBold(true);
                item->setFont(c, f);
            }
            item->setIcon(0, kindIcon(S("tpm2"), QString(), style()));
        }
    }
    pcrs->resizeColumnToContents(0);
    pcrs->resizeColumnToContents(1);
    const QString pcrError = str(m_system, "pcr_error");
    ui->pcrGroup->setToolTip(pcrError);
}

void MainWindow::fillPicker()
{
    auto *combo = ui->diskCombo;
    const QSignalBlocker block(combo);
    combo->clear();
    auto *model = qobject_cast<QStandardItemModel *>(combo->model());
    QString first;
    bool keep = false;
    for (const QJsonValue &v : arr(m_system, "picker")) {
        const QJsonObject e = v.toObject();
        const bool selectable = e.value(S("selectable")).toBool();
        const QString path = str(e, "path");
        combo->addItem(QString(e.value(S("depth")).toInt() * 4, QLatin1Char(' ')) + str(e, "text"), selectable ? path : QString());
        auto *item = model->item(combo->count() - 1);
        item->setEnabled(selectable); // unencrypted volumes are shown but cannot be chosen
        if (selectable) {
            item->setIcon(QIcon::fromTheme(S("drive-harddisk-encrypted"), style()->standardIcon(QStyle::SP_DriveHDIcon)));
            if (first.isEmpty())
                first = path;
            keep |= path == m_path;
        }
    }
    if (!keep)
        m_path = first;
    const int index = combo->findData(m_path);
    if (index >= 0)
        combo->setCurrentIndex(index);
}

QJsonObject MainWindow::slot(int id) const
{
    return arr(m_device, "slots").at(id).toObject();
}

void MainWindow::fillSlots()
{
    auto *table = ui->slotTable;
    const QJsonArray slotList = arr(m_device, "slots");
    ui->slotsGroup->setTitle(slotList.isEmpty() ? S("槽位") : str(m_device, "header"));
    const QColor dim = palette().color(QPalette::Disabled, QPalette::Text);
    for (int id = 0; id < 32; ++id) {
        const QJsonObject s = slotList.at(id).toObject();
        const QString kind = str(s, "kind");
        const bool empty = kind.isEmpty() || kind == QLatin1String("empty");
        QString text = QStringLiteral("%1").arg(id, 2, 10, QLatin1Char('0'));
        text += empty ? S("  空闲") : S("  ") + str(s, "kind_label");
        if (!str(s, "subtitle").isEmpty())
            text += QLatin1Char('\n') + str(s, "subtitle");
        auto *item = new QTableWidgetItem(kindIcon(kind, str(s, "state"), style()), text);
        if (empty)
            item->setForeground(dim);
        if (str(s, "state") == QLatin1String("bad"))
            item->setForeground(QColor(0xda, 0x44, 0x53));
        QStringList tip;
        for (const QJsonValue &r : arr(s, "details"))
            tip << S("%1：%2").arg(str(r.toObject(), "key"), str(r.toObject(), "value"));
        item->setToolTip(tip.join(QLatin1Char('\n')));
        table->setItem(id / 8, id % 8, item);
    }
    table->setCurrentCell(m_selected / 8, m_selected % 8);

    const bool loaded = !slotList.isEmpty();
    ui->verifyButton->setEnabled(loaded);
    const QJsonValue trimDevice = m_device.value(S("trim_device"));
    ui->trimLabel->setText(loaded ? S("TRIM：头部 %1 · 设备 %2")
                                        .arg(m_device.value(S("trim_header")).toBool() ? S("开") : S("关"),
                                             trimDevice.isNull() ? S("?") : (trimDevice.toBool() ? S("支持") : S("不支持")))
                                  : QString());
    ui->trimButton->setVisible(loaded && m_device.value(S("unlocked")).toBool());
}

void MainWindow::fillDetail()
{
    clearLayout(ui->detailForm);
    clearLayout(ui->actionsLayout);
    const QJsonObject s = slot(m_selected);
    ui->detailGroup->setTitle(S("槽位 %1").arg(m_selected));
    if (m_device.isEmpty())
        return;
    const QJsonArray details = arr(s, "details");
    if (details.isEmpty())
        ui->detailForm->addRow(new QLabel(S("空闲")));
    for (const QJsonValue &r : details) {
        auto *value = new QLabel(str(r.toObject(), "value"));
        value->setTextInteractionFlags(Qt::TextSelectableByMouse);
        value->setWordWrap(true);
        ui->detailForm->addRow(str(r.toObject(), "key") + S("："), value);
    }
    auto *volume = new QLabel(str(m_device, "volume"));
    volume->setEnabled(false);
    ui->detailForm->addRow(S("卷："), volume);
    const QString readOnly = str(m_device, "read_only");
    if (!readOnly.isEmpty()) {
        ui->detailForm->addRow(new QLabel(S("<b>%1</b>").arg(readOnly.toHtmlEscaped())));
        return;
    }
    for (const QJsonValue &a : arr(s, "actions")) {
        const QJsonObject action = a.toObject();
        auto *b = new QPushButton(str(action, "label"));
        const QJsonValue form = action.value(S("form"));
        connect(b, &QPushButton::clicked, this, [this, form] { openForm(form); });
        ui->actionsLayout->addWidget(b);
    }
    ui->actionsLayout->addStretch();
}

void MainWindow::fillHealth()
{
    auto *t = ui->issueTree;
    t->clear();
    for (const QJsonValue &v : arr(m_device, "issues")) {
        const QJsonObject i = v.toObject();
        auto *item = new QTreeWidgetItem(t, {str(i, "level_label"), str(i, "title"), str(i, "detail")});
        item->setIcon(0, statusIcon(str(i, "level"), style()));
        item->setData(0, Qt::UserRole, i.value(S("fix")));
        if (!i.value(S("fix")).isNull())
            item->setToolTip(1, S("可以自动修复"));
    }
    if (t->topLevelItemCount() == 0) {
        auto *item = new QTreeWidgetItem(t, {QString(), S("没有发现问题")});
        item->setIcon(0, statusIcon(S("Ok"), style()));
    }
    t->resizeColumnToContents(0);
    t->resizeColumnToContents(1);
    const int issues = arr(m_device, "issues").size();
    ui->tabs->setTabText(ui->tabs->indexOf(ui->healthTab), issues ? S("体检 (%1)").arg(issues) : S("体检"));
}

void MainWindow::fillBoot()
{
    auto *t = ui->bootTree;
    t->clear();
    for (const QJsonValue &v : m_boot) {
        const QJsonObject b = v.toObject();
        auto *item = new QTreeWidgetItem(t, {QString(), str(b, "title"), str(b, "detail").replace(QLatin1Char('\n'), QLatin1Char(' '))});
        item->setIcon(0, statusIcon(str(b, "status"), style()));
    }
    t->resizeColumnToContents(0);
    t->resizeColumnToContents(1);
}

void MainWindow::fillBackups(const QJsonArray &rows)
{
    auto *t = ui->backupTree;
    QHash<QString, Qt::CheckState> previous;
    for (int i = 0; i < t->topLevelItemCount(); ++i)
        previous.insert(t->topLevelItem(i)->data(0, Qt::UserRole).toString(), t->topLevelItem(i)->checkState(0));
    t->clear();
    for (const QJsonValue &v : rows) {
        const QJsonObject r = v.toObject();
        const int count = r.value(S("count")).toInt();
        auto *item = new QTreeWidgetItem(t, {str(r, "title"), str(r, "uuid"), count ? str(r, "last") : S("从未备份"),
                                             QString::number(count), str(r, "file")});
        item->setData(0, Qt::UserRole, str(r, "path"));
        item->setCheckState(0, previous.value(str(r, "path"), Qt::Checked));
    }
    for (int c = 0; c < 4; ++c)
        t->resizeColumnToContents(c);
}

// ---- actions ----------------------------------------------------------------

void MainWindow::slotContextMenu(const QPoint &pos)
{
    const QModelIndex index = ui->slotTable->indexAt(pos);
    if (!index.isValid())
        return;
    const QJsonArray actions = arr(slot(index.row() * 8 + index.column()), "actions");
    if (actions.isEmpty())
        return;
    QMenu menu(this);
    for (const QJsonValue &a : actions) {
        const QJsonObject action = a.toObject();
        const QJsonValue form = action.value(S("form"));
        menu.addAction(str(action, "label"), this, [this, form] { openForm(form); });
    }
    menu.exec(ui->slotTable->viewport()->mapToGlobal(pos));
}

void MainWindow::openForm(const QJsonValue &kind, const QString &forPath)
{
    const QString path = forPath.isEmpty() ? m_path : forPath;
    if (path.isEmpty())
        return;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    m_helper->call(S("build_form"), QJsonObject{{S("path"), path}, {S("kind"), kind}},
                   [this, path](const QJsonValue &ok, const QString &err) {
                       QApplication::restoreOverrideCursor();
                       if (!err.isEmpty())
                           return showError(S("无法执行"), err);
                       auto *dialog = new FormDialog(ok.toObject(), this);
                       dialog->setAttribute(Qt::WA_DeleteOnClose);
                       connect(dialog, &FormDialog::submitRequested, this, [this, dialog, path] { submitForm(dialog, path); });
                       auto updateNotes = [this, dialog] {
                           QJsonArray pcrs;
                           for (int p : dialog->selectedPcrs())
                               pcrs.append(p);
                           QPointer<FormDialog> d(dialog);
                           m_helper->call(S("pcr_notes"), QJsonObject{{S("pcrs"), pcrs}}, [d](const QJsonValue &ok, const QString &) {
                               if (!d)
                                   return;
                               QStringList notes;
                               for (const QJsonValue &n : ok.toArray())
                                   notes << n.toString();
                               d->setNotes(notes);
                           });
                       };
                       if (QJsonDocument(ok.toObject()).toJson().contains("\"Pcrs\"")) {
                           connect(dialog, &FormDialog::pcrsChanged, this, updateNotes);
                           updateNotes();
                       }
                       dialog->open();
                   });
}

void MainWindow::submitForm(FormDialog *dialog, const QString &path)
{
    dialog->setError(QString());
    dialog->setBusy(true);
    QPointer<FormDialog> d(dialog);
    m_helper->call(S("submit_form"), QJsonObject{{S("path"), path}, {S("form"), dialog->form()}},
                   [this, d](const QJsonValue &ok, const QString &err) {
                       if (!d)
                           return;
                       d->setBusy(false);
                       if (!err.isEmpty())
                           return d->setError(err);
                       const QJsonObject reply = ok.toObject();
                       const QString kind = str(reply, "kind");
                       d->accept();
                       if (kind == QLatin1String("plan")) {
                           confirm(QJsonArray{reply});
                       } else if (kind == QLatin1String("message")) {
                           const QString text = str(reply, "text");
                           if (reply.value(S("ok")).toBool())
                               QMessageBox::information(this, S("验证"), text);
                           else
                               QMessageBox::warning(this, S("验证"), text);
                           log(S("验证：") + text);
                       } else {
                           statusBar()->showMessage(S("备份位置已保存"));
                           refreshAll();
                       }
                   });
}

void MainWindow::confirm(const QJsonArray &plans)
{
    ConfirmDialog dialog(plans, this);
    if (dialog.exec() != QDialog::Accepted)
        return;
    QJsonArray ids;
    for (const QJsonValue &p : plans)
        ids.append(p.toObject().value(S("id")));
    execute(ids, dialog.confirmText());
}

void MainWindow::execute(const QJsonArray &ids, const QString &confirmText)
{
    m_progress = new ProgressDialog(S("正在执行…（如有需要请触摸安全密钥）"), this);
    m_progress->setAttribute(Qt::WA_DeleteOnClose);
    m_progress->show();
    m_helper->call(S("execute"), QJsonObject{{S("plans"), ids}, {S("confirm"), confirmText}},
                   [this](const QJsonValue &ok, const QString &err) {
                       if (m_progress)
                           m_progress->done(QDialog::Accepted);
                       if (!err.isEmpty())
                           return showError(S("执行失败"), err);
                       const QJsonArray reports = ok.toArray();
                       log(reportsText(reports));
                       QString key;
                       int newSlot = -1;
                       for (const QJsonValue &r : reports) {
                           const QJsonObject o = r.toObject();
                           if (!o.value(S("new_slot")).isNull())
                               newSlot = o.value(S("new_slot")).toInt();
                           if (key.isEmpty())
                               key = str(o, "recovery_key");
                       }
                       if (newSlot >= 0)
                           m_selected = newSlot;
                       if (!key.isEmpty()) {
                           RecoveryKeyDialog(key, newSlot, this).exec();
                       } else {
                           showReports(reports, this);
                       }
                       refreshAll();
                   });
}

void MainWindow::fixIssue()
{
    QTreeWidgetItem *item = ui->issueTree->currentItem();
    if (!item)
        return;
    const QJsonValue fix = item->data(0, Qt::UserRole).toJsonValue();
    if (fix.isNull() || fix.isUndefined()) {
        statusBar()->showMessage(S("这个问题无法自动修复"), 4000);
        return;
    }
    m_helper->call(S("plan"), QJsonObject{{S("path"), m_path}, {S("request"), fix}}, [this](const QJsonValue &ok, const QString &err) {
        if (!err.isEmpty())
            return showError(S("无法执行"), err);
        confirm(QJsonArray{ok});
    });
}

void MainWindow::backupSelected()
{
    QJsonArray paths;
    auto *t = ui->backupTree;
    for (int i = 0; i < t->topLevelItemCount(); ++i)
        if (t->topLevelItem(i)->checkState(0) == Qt::Checked)
            paths.append(t->topLevelItem(i)->data(0, Qt::UserRole).toString());
    if (paths.isEmpty())
        return statusBar()->showMessage(S("未选择任何卷"), 4000);
    m_helper->call(S("plan_backups"), QJsonObject{{S("paths"), paths}}, [this](const QJsonValue &ok, const QString &err) {
        if (!err.isEmpty())
            return showError(S("备份"), err);
        confirm(ok.toArray());
    });
}

void MainWindow::restoreSelected()
{
    QTreeWidgetItem *item = ui->backupTree->currentItem();
    if (!item)
        return statusBar()->showMessage(S("请先选择一个卷"), 4000);
    openForm(S("Restore"), item->data(0, Qt::UserRole).toString());
}

void MainWindow::saveBackupDir()
{
    const QString dir = ui->backupDirEdit->text().trimmed();
    m_helper->call(S("set_backup_dir"), QJsonObject{{S("dir"), dir.isEmpty() ? QJsonValue() : QJsonValue(dir)}},
                   [this](const QJsonValue &, const QString &err) {
                       if (!err.isEmpty())
                           return showError(S("备份位置"), err);
                       statusBar()->showMessage(S("备份位置已保存"), 4000);
                       refreshAll();
                   });
}
