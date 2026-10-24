#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "appsettings.h"
#include "dialogs.h"
#include "formdialog.h"

#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPushButton>
#include <QStandardItemModel>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QSysInfo>
#include <QToolButton>
#include <QTreeWidget>
#include <QUrl>

#include <algorithm>

namespace {

// JSON keys and other untranslated literals.
const auto S = [](const char *s) { return QString::fromUtf8(s); };

const char *const RepoUrl = "https://github.com/Fosvcat/Luks-Assistant";

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

// Hardware tokens use symbolic (monochrome) icons; a slot whose PCRs changed
// says so in its text, the icon stays the same.
QIcon kindIcon(const QString &kind, const QStyle *style)
{
    if (kind == QLatin1String("passphrase") || kind == QLatin1String("secret") || kind == QLatin1String("luks1"))
        return themed({"dialog-password", "password-copy"}, QStyle::SP_DialogYesButton, style);
    if (kind == QLatin1String("keyfile"))
        return themed({"document-encrypted", "application-pgp-keys"}, QStyle::SP_FileIcon, style);
    if (kind == QLatin1String("recovery"))
        return themed({"document-save", "media-floppy"}, QStyle::SP_DialogSaveButton, style);
    if (kind == QLatin1String("tpm2"))
        return themed({"cpu-symbolic", "cpu"}, QStyle::SP_ComputerIcon, style);
    if (kind == QLatin1String("fido2"))
        return themed({"drive-removable-media-usb-pendrive-symbolic", "drive-removable-media-usb"},
                      QStyle::SP_DriveFDIcon, style);
    if (kind == QLatin1String("pkcs11"))
        return themed({"auth-smartcard-symbolic", "auth-sim"}, QStyle::SP_DriveCDIcon, style);
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

/// Icon of an action button: the token kinds have one, the rest none.
QIcon formIcon(const QJsonValue &form, const QStyle *style)
{
    const QString kind = form.isObject() && !form.toObject().isEmpty() ? form.toObject().keys().first() : QString();
    if (kind == QLatin1String("Tpm2"))
        return kindIcon(S("tpm2"), style);
    if (kind == QLatin1String("Fido2"))
        return kindIcon(S("fido2"), style);
    if (kind == QLatin1String("Pkcs11"))
        return kindIcon(S("pkcs11"), style);
    return {};
}

/// A monochrome (symbolic) icon: every visible pixel is grey.
bool isMonochrome(const QImage &image)
{
    const QImage img = image.convertToFormat(QImage::Format_ARGB32);
    for (int y = 0; y < img.height(); ++y) {
        const auto *line = reinterpret_cast<const QRgb *>(img.constScanLine(y));
        for (int x = 0; x < img.width(); ++x) {
            const QRgb c = line[x];
            if (qAlpha(c) < 32)
                continue;
            const int hi = std::max({qRed(c), qGreen(c), qBlue(c)});
            const int lo = std::min({qRed(c), qGreen(c), qBlue(c)});
            if (hi - lo > 40)
                return false;
        }
    }
    return true;
}

/// `pixmap` in a single colour, keeping its shape.
QPixmap tinted(QPixmap pixmap, const QColor &color)
{
    QPainter p(&pixmap);
    p.setCompositionMode(QPainter::CompositionMode_SourceIn);
    p.fillRect(pixmap.rect(), color);
    return pixmap;
}

/// Slot cells with square selection and hover marks whatever the style draws
/// (Breeze rounds them), and no separate focus frame.
class SquareCellDelegate : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        QStyleOptionViewItem opt(option);
        initStyleOption(&opt, index);
        const bool selected = opt.state & QStyle::State_Selected;
        if (selected) {
            const QColor highlight = opt.palette.color(QPalette::Active, QPalette::Highlight);
            p->fillRect(opt.rect, highlight);
            opt.palette.setColor(QPalette::Text, opt.palette.color(QPalette::Active, QPalette::HighlightedText));
            // Symbolic icons are drawn light in dark themes and vanish on a
            // light highlight: draw them dark (or light) against it.
            if (!opt.icon.isNull()) {
                const qreal dpr = opt.widget ? opt.widget->devicePixelRatioF() : 1.0;
                const QPixmap pm = opt.icon.pixmap(opt.decorationSize, dpr);
                if (isMonochrome(pm.toImage())) {
                    const QColor ink = highlight.lightnessF() > 0.45 ? QColor(0x23, 0x26, 0x29) : QColor(Qt::white);
                    opt.icon = QIcon(tinted(pm, ink));
                }
            }
        } else if (opt.state & QStyle::State_MouseOver) {
            QColor hover = opt.palette.color(QPalette::Active, QPalette::Highlight);
            hover.setAlpha(40);
            p->fillRect(opt.rect, hover);
        }
        opt.state &= ~(QStyle::State_Selected | QStyle::State_HasFocus | QStyle::State_MouseOver);
        opt.backgroundBrush = Qt::NoBrush;
        const QWidget *w = opt.widget;
        (w ? w->style() : QApplication::style())->drawControl(QStyle::CE_ItemViewItem, &opt, p, w);
    }
};

QString arch()
{
    const QString a = QSysInfo::buildCpuArchitecture();
    return a == QLatin1String("arm64") ? S("aarch64") : a;
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
    , m_refresh(new QToolButton)
    , m_extra(extraDevices)
{
    ui->setupUi(this);
    {
        // the logo is large; show it at 112 px (sharp on HiDPI screens)
        const qreal dpr = devicePixelRatioF();
        QPixmap logo = QPixmap(S(":/icons/luks-assistant.png"))
                           .scaled(QSize(112, 112) * dpr, Qt::KeepAspectRatio, Qt::SmoothTransformation);
        logo.setDevicePixelRatio(dpr);
        ui->appIcon->setPixmap(logo);
    }
    QFont nameFont = ui->appName->font();
    nameFont.setPointSizeF(nameFont.pointSizeF() * 1.6);
    nameFont.setBold(true);
    ui->appName->setFont(nameFont);

    // Tabs on top, refresh at their right.
    m_refresh->setIcon(QIcon::fromTheme(S("view-refresh")));
    m_refresh->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_refresh->setAutoRaise(true);
    m_refresh->setFocusPolicy(Qt::NoFocus); // no focus mark left behind after a click
    ui->tabs->setCornerWidget(m_refresh, Qt::TopRightCorner);
    ui->tabs->setDocumentMode(true);

    ui->verifyButton->setIcon(QIcon::fromTheme(S("dialog-ok-apply")));
    ui->backupButton->setIcon(QIcon::fromTheme(S("document-save")));
    ui->pruneButton->setIcon(QIcon::fromTheme(S("edit-clear-history"), QIcon::fromTheme(S("edit-delete"))));
    ui->restoreButton->setIcon(QIcon::fromTheme(S("document-revert")));
    ui->browseButton->setIcon(QIcon::fromTheme(S("document-open-folder")));
    ui->openDirButton->setIcon(QIcon::fromTheme(S("folder-open")));
    ui->exportButton->setIcon(QIcon::fromTheme(S("document-export")));

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
    table->setItemDelegate(new SquareCellDelegate(table));
    table->setMouseTracking(true);

    ui->diskTree->setColumnCount(6);
    ui->pcrTree->setRootIsDecorated(false);
    ui->issueTree->setRootIsDecorated(false);
    ui->issueTree->setWordWrap(true);
    ui->bootTree->setRootIsDecorated(false);
    ui->bootTree->setWordWrap(true);
    ui->backupTree->setColumnCount(5);
    ui->backupTree->setRootIsDecorated(false);
    ui->backupTree->setContextMenuPolicy(Qt::CustomContextMenu);
    for (QTreeWidget *t : {ui->systemTree, ui->diskTree, ui->pcrTree, ui->issueTree, ui->bootTree, ui->backupTree})
        t->setAlternatingRowColors(true);

    // Right-click → copy.
    installCopyMenu(ui->systemTree, tr("复制"), [](const QTreeWidgetItem *i) {
        return i->text(1).isEmpty() ? i->text(0) : tr("%1：%2").arg(i->text(0), i->text(1));
    });
    installCopyMenu(ui->diskTree, tr("复制"), [](const QTreeWidgetItem *i) {
        QStringList parts{i->data(0, Qt::UserRole).toString(), i->text(1), i->text(2), i->text(3),
                          i->text(4).isEmpty() ? QString() : S("TRIM ") + i->text(4), i->text(5)};
        parts.removeAll(QString());
        return parts.join(S("  "));
    });
    installCopyMenu(ui->pcrTree, tr("复制 PCR 值"),
                    [](const QTreeWidgetItem *i) { return i->data(1, Qt::UserRole).toString(); });
    installCopyMenu(ui->issueTree, tr("复制"), [](const QTreeWidgetItem *i) {
        return i->text(2).isEmpty() ? i->text(1) : tr("%1：%2").arg(i->text(1), i->text(2));
    });
    installCopyMenu(ui->bootTree, tr("复制"), [](const QTreeWidgetItem *i) {
        return tr("%1：%2").arg(i->text(1), i->data(2, Qt::UserRole).toString());
    });

    connect(m_refresh, &QToolButton::clicked, this, &MainWindow::refreshAll);
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
    connect(ui->lockButton, &QPushButton::clicked, this, &MainWindow::toggleLock);
    ui->showAllPcrs->setChecked(AppSettings::showAllPcrs());
    connect(ui->showAllPcrs, &QCheckBox::toggled, this, [this](bool all) {
        AppSettings::setShowAllPcrs(all);
        fillSystem();
    });

    // Header management
    auto setChecks = [this](const std::function<Qt::CheckState(Qt::CheckState)> &f) {
        auto *t = ui->backupTree;
        for (int i = 0; i < t->topLevelItemCount(); ++i)
            t->topLevelItem(i)->setCheckState(0, f(t->topLevelItem(i)->checkState(0)));
    };
    connect(ui->selectAllButton, &QPushButton::clicked, this, [setChecks] { setChecks([](Qt::CheckState) { return Qt::Checked; }); });
    connect(ui->clearButton, &QPushButton::clicked, this, [setChecks] { setChecks([](Qt::CheckState) { return Qt::Unchecked; }); });
    connect(ui->invertButton, &QPushButton::clicked, this, [setChecks] {
        setChecks([](Qt::CheckState s) { return s == Qt::Checked ? Qt::Unchecked : Qt::Checked; });
    });
    connect(ui->backupTree, &QTreeWidget::itemChanged, this, &MainWindow::updateBackupButtons);
    connect(ui->backupTree, &QWidget::customContextMenuRequested, this, &MainWindow::backupContextMenu);
    connect(ui->backupButton, &QPushButton::clicked, this, [this] { backupVolumes(checkedVolumes()); });
    connect(ui->pruneButton, &QPushButton::clicked, this, [this] { pruneVolumes(checkedVolumes()); });
    connect(ui->restoreButton, &QPushButton::clicked, this, [this] {
        const QStringList v = checkedVolumes();
        if (v.size() == 1)
            restoreVolume(v.first());
    });
    connect(ui->backupDirEdit, &QLineEdit::editingFinished, this, &MainWindow::saveBackupDir);
    connect(ui->openDirButton, &QPushButton::clicked, this, &MainWindow::openBackupDir);
    connect(ui->browseButton, &QPushButton::clicked, this, [this] {
        const QString current = ui->backupDirEdit->text().isEmpty() ? ui->backupDirEdit->placeholderText()
                                                                    : ui->backupDirEdit->text();
        const QString dir = QFileDialog::getExistingDirectory(this, tr("备份位置"), current);
        if (dir.isEmpty())
            return;
        ui->backupDirEdit->setText(dir);
        saveBackupDir();
    });
    connect(ui->exportButton, &QPushButton::clicked, this, &MainWindow::exportLog);

    // About
    ui->languageCombo->setCurrentIndex(static_cast<int>(AppSettings::language()));
    ui->themeCombo->setCurrentIndex(static_cast<int>(AppSettings::theme()));
    connect(ui->languageCombo, qOverload<int>(&QComboBox::activated), this, &MainWindow::changeLanguage);
    connect(ui->themeCombo, qOverload<int>(&QComboBox::activated), this, &MainWindow::changeTheme);

    connect(m_helper, &HelperClient::ready, this, [this] {
        m_helper->call(S("set_language"), QJsonObject{{S("lang"), AppSettings::effectiveLanguage()}},
                       [](const QJsonValue &, const QString &) {});
        refreshAll();
    });
    connect(m_helper, &HelperClient::failed, this, [this](const QString &message) {
        statusBar()->showMessage(tr("后端未连接，点击“刷新”重试"));
        showError(tr("无法启动后端"), message);
    });
    connect(m_helper, &HelperClient::event, this, [this](const QString &kind, const QString &text) {
        if (m_progress)
            m_progress->append(kind == QLatin1String("progress") ? S("▶ ") + text : text);
    });

    retranslate();
    fillDetail();
    updateBackupButtons();
    startHelper();
}

MainWindow::~MainWindow()
{
    disconnect(m_helper, nullptr, this, nullptr);
    delete m_helper; // closes the helper while the window is still whole
    delete ui;
}

void MainWindow::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::LanguageChange) {
        ui->retranslateUi(this);
        retranslate();
    } else if (event->type() == QEvent::PaletteChange && !m_device.isEmpty()) {
        fillSlots(); // colors come from the palette
    }
    QMainWindow::changeEvent(event);
}

/// Texts set in code; the .ui texts are handled by retranslateUi.
void MainWindow::retranslate()
{
    m_refresh->setText(tr("刷新"));
    ui->systemTree->setHeaderLabels({tr("项目"), tr("值")});
    ui->diskTree->setHeaderLabels({tr("名称"), tr("大小"), tr("加密"), tr("类型"), S("TRIM"), tr("挂载点")});
    ui->pcrTree->setHeaderLabels({S("PCR"), tr("当前值"), tr("用途")});
    ui->issueTree->setHeaderLabels({tr("级别"), tr("问题"), tr("说明")});
    ui->bootTree->setHeaderLabels({tr("状态"), tr("项目"), tr("详情")});
    ui->backupTree->setHeaderLabels({tr("卷"), S("UUID"), tr("最后备份"), tr("数量"), tr("文件")});
    ui->appVersion->setText(S("%1 %2").arg(QStringLiteral(LUKS_ASSISTANT_VERSION), arch()));
    updateLockState();
    ui->appLink->setText(S("<a href=\"%1\">%1</a>").arg(QString::fromLatin1(RepoUrl)));
    ui->logView->setPlaceholderText(tr("还没有日志"));
}

void MainWindow::showError(const QString &title, const QString &message)
{
    QMessageBox::warning(this, title, message);
}

void MainWindow::log(const QString &english)
{
    ui->logView->appendPlainText(QStringLiteral("[%1] %2").arg(QDateTime::currentDateTime().toString(Qt::ISODate), english));
}

void MainWindow::startHelper()
{
    statusBar()->showMessage(tr("正在请求管理员权限…"));
    m_helper->start();
}

void MainWindow::installCopyMenu(QTreeWidget *tree, const QString &label,
                                 const std::function<QString(const QTreeWidgetItem *)> &text)
{
    tree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(tree, &QWidget::customContextMenuRequested, this, [tree, label, text](const QPoint &pos) {
        const QTreeWidgetItem *item = tree->itemAt(pos);
        if (!item)
            return;
        const QString t = text(item);
        if (t.isEmpty())
            return;
        QMenu menu(tree);
        menu.addAction(QIcon::fromTheme(S("edit-copy")), label, [t] { QGuiApplication::clipboard()->setText(t); });
        menu.exec(tree->viewport()->mapToGlobal(pos));
    });
}

// ---- loading -------------------------------------------------------------

void MainWindow::refreshAll()
{
    if (!m_helper->isRunning())
        return startHelper();
    statusBar()->showMessage(tr("正在读取…"));
    QJsonArray extra;
    for (const QString &e : m_extra)
        extra.append(e);
    m_helper->call(S("system_view"), QJsonObject{{S("extra"), extra}}, [this](const QJsonValue &ok, const QString &err) {
        if (!err.isEmpty())
            return showError(tr("读取失败"), err);
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
        statusBar()->showMessage(tr("没有 LUKS 卷"));
        return;
    }
    m_helper->call(S("device_view"), QJsonObject{{S("path"), m_path}}, [this](const QJsonValue &ok, const QString &err) {
        if (!err.isEmpty()) {
            m_device = {};
            fillSlots();
            fillDetail();
            statusBar()->showMessage(tr("读取失败：%1").arg(err));
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
        statusBar()->showMessage(tr("就绪"));
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
    rows(group(tr("系统")), arr(m_system, "system"));
    rows(group(S("TPM")), arr(m_system, "tpm"));
    for (const auto &[title, key] : {std::pair{tr("FIDO2 安全密钥"), "fido2"}, std::pair{tr("PKCS#11 智能卡"), "pkcs11"}}) {
        auto *g = group(title);
        const QJsonArray list = arr(m_system, key);
        if (list.isEmpty())
            spanned(g, tr("未检测到"));
        for (const QJsonValue &d : list)
            spanned(g, d.toString());
    }
    auto *caps = group(tr("功能"));
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
        // TRIM: "—" for spinning disks, ✓/✗ otherwise.
        const QJsonValue trim = d.value(S("trim"));
        const QString media = str(d, "media");
        const QString trimText = media == QLatin1String("HDD") ? S("—")
                                 : trim.isNull()               ? QString()
                                 : trim.toBool()               ? S("✓")
                                                               : S("✗");
        const QStringList cols = {str(d, "name"), str(d, "size"), str(d, "encryption"), media, trimText, str(d, "mount")};
        auto *item = depth == 0 || parents.isEmpty() ? new QTreeWidgetItem(disks, cols)
                                                     : new QTreeWidgetItem(parents.last(), cols);
        item->setData(0, Qt::UserRole, str(d, "path"));
        item->setToolTip(0, QStringList{str(d, "path"), str(d, "kind"), str(d, "fstype"), str(d, "model")}.join(S("  ")));
        if (d.value(S("luks")).toBool())
            item->setIcon(0, QIcon::fromTheme(S("drive-harddisk-encrypted"), style()->standardIcon(QStyle::SP_DriveHDIcon)));
        parents.append(item);
    }
    disks->expandAll();
    for (int c = 0; c < 5; ++c)
        disks->resizeColumnToContents(c);

    QSet<int> bound;
    for (const QJsonValue &p : arr(m_device, "bound_pcrs"))
        bound.insert(p.toInt());
    const QList<int> shown = visiblePcrs();
    auto *pcrs = ui->pcrTree;
    pcrs->clear();
    for (const QJsonValue &v : arr(m_system, "pcrs")) {
        const QJsonObject p = v.toObject();
        const int index = p.value(S("index")).toInt();
        if (!shown.contains(index))
            continue;
        const QString value = str(p, "value");
        auto *item = new QTreeWidgetItem(pcrs, {QString::number(index), value.isEmpty() ? S("—") : value.left(16) + S("…"), str(p, "name")});
        item->setData(1, Qt::UserRole, value);
        item->setToolTip(2, tr("%1\n改变：%2").arg(str(p, "measures"), str(p, "changes")));
        item->setToolTip(1, value);
        if (bound.contains(index)) {
            for (int c = 0; c < 3; ++c) {
                QFont f = item->font(c);
                f.setBold(true);
                item->setFont(c, f);
            }
            item->setIcon(0, kindIcon(S("tpm2"), style()));
        }
    }
    pcrs->resizeColumnToContents(0);
    pcrs->resizeColumnToContents(1);
    ui->pcrGroup->setToolTip(str(m_system, "pcr_error"));
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
    ui->slotsGroup->setTitle(slotList.isEmpty() ? tr("槽位") : str(m_device, "header"));
    const QColor dim = palette().color(QPalette::Disabled, QPalette::Text);
    for (int id = 0; id < 32; ++id) {
        const QJsonObject s = slotList.at(id).toObject();
        const QString kind = str(s, "kind");
        const bool empty = kind.isEmpty() || kind == QLatin1String("empty");
        QString text = QStringLiteral("%1").arg(id, 2, 10, QLatin1Char('0'));
        text += S("  ") + (empty ? tr("空闲") : str(s, "kind_label"));
        if (!str(s, "subtitle").isEmpty())
            text += QLatin1Char('\n') + str(s, "subtitle");
        auto *item = new QTableWidgetItem(kindIcon(kind, style()), text);
        if (empty)
            item->setForeground(dim);
        if (str(s, "state") == QLatin1String("bad"))
            item->setForeground(QColor(0xda, 0x44, 0x53));
        QStringList tip;
        for (const QJsonValue &r : arr(s, "details"))
            tip << tr("%1：%2").arg(str(r.toObject(), "key"), str(r.toObject(), "value"));
        item->setToolTip(tip.join(QLatin1Char('\n')));
        table->setItem(id / 8, id % 8, item);
    }
    table->setCurrentCell(m_selected / 8, m_selected % 8);

    ui->verifyButton->setEnabled(!slotList.isEmpty());
    updateLockState();
}

void MainWindow::updateLockState()
{
    const bool loaded = !arr(m_device, "slots").isEmpty();
    const bool unlocked = m_device.value(S("unlocked")).toBool();
    ui->lockStateLabel->setText(!loaded ? QString() : unlocked ? tr("状态：已解锁") : tr("状态：锁定"));
    ui->lockButton->setText(unlocked ? tr("锁定") : tr("解锁"));
    ui->lockButton->setIcon(unlocked ? themed({"object-locked-symbolic", "changes-prevent-symbolic", "object-locked"},
                                              QStyle::SP_DialogCloseButton, style())
                                     : themed({"object-unlocked-symbolic", "changes-allow-symbolic", "object-unlocked"},
                                              QStyle::SP_DialogOpenButton, style()));
    // the running system's own volume cannot be locked
    ui->lockButton->setEnabled(loaded && !(unlocked && m_device.value(S("system_disk")).toBool()));
}

QList<int> MainWindow::visiblePcrs() const
{
    QList<int> list;
    if (AppSettings::showAllPcrs() || arr(m_system, "preferred_pcrs").isEmpty()) {
        for (int i = 0; i < 24; ++i)
            list << i;
    } else {
        for (const QJsonValue &v : arr(m_system, "preferred_pcrs"))
            list << v.toInt();
    }
    return list;
}

void MainWindow::toggleLock()
{
    if (m_path.isEmpty())
        return;
    if (!m_device.value(S("unlocked")).toBool())
        return openForm(S("Unlock"));
    const QString path = m_path;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    m_helper->call(S("lock"), QJsonObject{{S("path"), path}}, [this, path](const QJsonValue &, const QString &err) {
        QApplication::restoreOverrideCursor();
        if (!err.isEmpty()) {
            log(S("Lock failed: ") + path);
            return showError(tr("锁定"), err);
        }
        log(S("Locked ") + path);
        statusBar()->showMessage(tr("已锁定"), 4000);
        refreshAll();
    });
}

void MainWindow::fillDetail()
{
    clearLayout(ui->detailForm);
    clearLayout(ui->actionsLayout);
    const QJsonObject s = slot(m_selected);
    ui->detailGroup->setTitle(tr("槽位 %1").arg(m_selected));
    if (m_device.isEmpty())
        return;
    const QJsonArray details = arr(s, "details");
    if (details.isEmpty())
        ui->detailForm->addRow(new QLabel(tr("空闲")));
    for (const QJsonValue &r : details) {
        auto *value = new QLabel(str(r.toObject(), "value"));
        value->setTextInteractionFlags(Qt::TextSelectableByMouse);
        value->setWordWrap(true);
        ui->detailForm->addRow(tr("%1：").arg(str(r.toObject(), "key")), value);
    }
    auto *volume = new QLabel(str(m_device, "volume"));
    volume->setEnabled(false);
    ui->detailForm->addRow(tr("卷："), volume);
    const QString readOnly = str(m_device, "read_only");
    if (!readOnly.isEmpty()) {
        ui->detailForm->addRow(new QLabel(S("<b>%1</b>").arg(readOnly.toHtmlEscaped())));
        return;
    }
    for (const QJsonValue &a : arr(s, "actions")) {
        const QJsonObject action = a.toObject();
        const QJsonValue form = action.value(S("form"));
        auto *b = new QPushButton(formIcon(form, style()), str(action, "label"));
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
    }
    if (t->topLevelItemCount() == 0) {
        auto *item = new QTreeWidgetItem(t, {QString(), tr("没有发现问题")});
        item->setIcon(0, statusIcon(S("Ok"), style()));
    }
    t->resizeColumnToContents(0);
    t->resizeColumnToContents(1);
}

void MainWindow::fillBoot()
{
    auto *t = ui->bootTree;
    t->clear();
    for (const QJsonValue &v : m_boot) {
        const QJsonObject b = v.toObject();
        const QString detail = str(b, "detail");
        auto *item = new QTreeWidgetItem(t, {QString(), str(b, "title"), QString(detail).replace(QLatin1Char('\n'), QLatin1Char(' '))});
        item->setData(2, Qt::UserRole, detail);
        item->setIcon(0, statusIcon(str(b, "status"), style()));
    }
    t->resizeColumnToContents(0);
    t->resizeColumnToContents(1);
}

void MainWindow::fillBackups(const QJsonArray &rows)
{
    m_backupRows = rows;
    auto *t = ui->backupTree;
    const QSignalBlocker block(t);
    QHash<QString, Qt::CheckState> previous;
    for (int i = 0; i < t->topLevelItemCount(); ++i)
        previous.insert(t->topLevelItem(i)->data(0, Qt::UserRole).toString(), t->topLevelItem(i)->checkState(0));
    t->clear();
    for (const QJsonValue &v : rows) {
        const QJsonObject r = v.toObject();
        const int count = r.value(S("count")).toInt();
        auto *item = new QTreeWidgetItem(t, {str(r, "title"), str(r, "uuid"), count ? str(r, "last") : tr("从未备份"),
                                             QString::number(count), str(r, "file")});
        item->setData(0, Qt::UserRole, str(r, "path"));
        item->setCheckState(0, previous.value(str(r, "path"), Qt::Checked));
    }
    for (int c = 0; c < 4; ++c)
        t->resizeColumnToContents(c);
    updateBackupButtons();
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

void MainWindow::backupContextMenu(const QPoint &pos)
{
    const QTreeWidgetItem *item = ui->backupTree->itemAt(pos);
    if (!item)
        return;
    const QString path = item->data(0, Qt::UserRole).toString();
    QMenu menu(this);
    menu.addAction(QIcon::fromTheme(S("document-save")), tr("备份"), this, [this, path] { backupVolumes({path}); });
    menu.addAction(QIcon::fromTheme(S("edit-clear-history"), QIcon::fromTheme(S("edit-delete"))), tr("清理旧备份"), this,
                   [this, path] { pruneVolumes({path}); });
    menu.addAction(QIcon::fromTheme(S("document-revert")), tr("恢复…"), this, [this, path] { restoreVolume(path); });
    menu.exec(ui->backupTree->viewport()->mapToGlobal(pos));
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
                           return showError(tr("无法执行"), err);
                       auto *dialog = new FormDialog(ok.toObject(), visiblePcrs(), this);
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
                       const bool unlock = d->form().value(S("kind")) == QLatin1String("Unlock");
                       d->accept();
                       if (kind == QLatin1String("plan")) {
                           confirm(QJsonArray{reply});
                       } else if (kind == QLatin1String("message") && unlock) {
                           // success needs no dialog: the state shows it
                           log(str(reply, "log"));
                           if (!reply.value(S("ok")).toBool())
                               QMessageBox::warning(this, tr("解锁"), str(reply, "text"));
                           else
                               statusBar()->showMessage(str(reply, "text"), 4000);
                           refreshAll();
                       } else if (kind == QLatin1String("message")) {
                           const QString text = str(reply, "text");
                           if (reply.value(S("ok")).toBool())
                               QMessageBox::information(this, tr("验证"), text);
                           else
                               QMessageBox::warning(this, tr("验证"), text);
                           log(S("Verify: ") + str(reply, "log"));
                       } else {
                           statusBar()->showMessage(tr("备份位置已保存"), 4000);
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
    m_progress = new ProgressDialog(tr("正在执行…（如有需要请触摸安全密钥）"), this);
    m_progress->setAttribute(Qt::WA_DeleteOnClose);
    m_progress->show();
    m_helper->call(S("execute"), QJsonObject{{S("plans"), ids}, {S("confirm"), confirmText}},
                   [this](const QJsonValue &ok, const QString &err) {
                       if (m_progress)
                           m_progress->done(QDialog::Accepted);
                       if (!err.isEmpty()) {
                           log(S("Execution failed: ") + err);
                           return showError(tr("执行失败"), err);
                       }
                       const QJsonArray reports = ok.toArray();
                       log(reportsLog(reports));
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

QStringList MainWindow::checkedVolumes() const
{
    QStringList paths;
    auto *t = ui->backupTree;
    for (int i = 0; i < t->topLevelItemCount(); ++i)
        if (t->topLevelItem(i)->checkState(0) == Qt::Checked)
            paths << t->topLevelItem(i)->data(0, Qt::UserRole).toString();
    return paths;
}

void MainWindow::updateBackupButtons()
{
    const int checked = checkedVolumes().size();
    ui->backupButton->setEnabled(checked > 0);
    ui->pruneButton->setEnabled(checked > 0);
    ui->restoreButton->setEnabled(checked == 1);
}

/// Keep only the newest header backup of each volume.
void MainWindow::pruneVolumes(const QStringList &volumes)
{
    if (volumes.isEmpty())
        return;
    QJsonArray paths;
    for (const QString &p : volumes)
        paths.append(p);
    m_helper->call(S("plan_prunes"), QJsonObject{{S("paths"), paths}}, [this](const QJsonValue &ok, const QString &err) {
        if (!err.isEmpty())
            return showError(tr("清理"), err);
        confirm(ok.toArray());
    });
}

void MainWindow::backupVolumes(const QStringList &volumes)
{
    if (volumes.isEmpty())
        return;
    QJsonArray paths;
    for (const QString &p : volumes)
        paths.append(p);
    m_helper->call(S("plan_backups"), QJsonObject{{S("paths"), paths}}, [this](const QJsonValue &ok, const QString &err) {
        if (!err.isEmpty())
            return showError(tr("备份"), err);
        confirm(ok.toArray());
    });
}

/// Like a backup: the plan is shown for confirmation, with the backup file
/// to restore chosen above it (this program's latest backup, or any file).
void MainWindow::restoreVolume(const QString &path)
{
    QString latest;
    for (const QJsonValue &v : m_backupRows)
        if (str(v.toObject(), "path") == path)
            latest = str(v.toObject(), "file");

    auto *dialog = new ConfirmDialog({}, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    auto *box = new QWidget;
    auto *column = new QVBoxLayout(box);
    column->setContentsMargins(0, 0, 0, 0);
    auto *source = new QComboBox;
    source->addItem(tr("恢复本程序的备份文件：%1").arg(latest.isEmpty() ? tr("未找到备份") : QFileInfo(latest).fileName()));
    source->addItem(tr("指定要恢复的备份文件"));
    column->addWidget(source);
    auto *fileRow = new QWidget;
    auto *row = new QHBoxLayout(fileRow);
    row->setContentsMargins(0, 0, 0, 0);
    auto *file = new QLineEdit;
    auto *browse = new QPushButton(QIcon::fromTheme(S("document-open")), tr("浏览…"));
    row->addWidget(file, 1);
    row->addWidget(browse);
    fileRow->hide();
    column->addWidget(fileRow);
    dialog->insertWidget(box);

    QPointer<ConfirmDialog> d(dialog);
    auto replan = [this, d, path, latest, source, file] {
        const bool ours = source->currentIndex() == 0;
        const QString f = ours ? latest : file->text().trimmed();
        if (f.isEmpty())
            return d->setMessage(ours ? tr("没有找到本程序为这个卷保存的备份。") : tr("请选择备份文件。"));
        const QJsonObject request{{S("RestoreHeader"), QJsonObject{{S("file"), f}}}};
        m_helper->call(S("plan"), QJsonObject{{S("path"), path}, {S("request"), request}},
                       [d](const QJsonValue &ok, const QString &err) {
                           if (!d)
                               return;
                           if (!err.isEmpty())
                               return d->setMessage(err);
                           d->setPlans(QJsonArray{ok});
                       });
    };
    connect(source, qOverload<int>(&QComboBox::currentIndexChanged), dialog, [fileRow, file, replan](int i) {
        fileRow->setVisible(i == 1);
        if (i == 1)
            file->setFocus();
        replan();
    });
    connect(file, &QLineEdit::editingFinished, dialog, replan);
    connect(browse, &QPushButton::clicked, dialog, [this, dialog, file, latest, replan] {
        const QString start = file->text().isEmpty() ? QFileInfo(latest).path() : file->text();
        const QString f = QFileDialog::getOpenFileName(dialog, tr("备份文件"), start);
        if (f.isEmpty())
            return;
        file->setText(f);
        replan();
    });
    connect(dialog, &QDialog::accepted, this, [this, dialog] {
        QJsonArray ids;
        for (const QJsonValue &p : dialog->plans())
            ids.append(p.toObject().value(S("id")));
        execute(ids, dialog->confirmText());
    });
    replan();
    dialog->open();
}

void MainWindow::saveBackupDir()
{
    const QString dir = ui->backupDirEdit->text().trimmed();
    if (dir == str(m_system, "backup_root"))
        return;
    m_helper->call(S("set_backup_dir"), QJsonObject{{S("dir"), dir.isEmpty() ? QJsonValue() : QJsonValue(dir)}},
                   [this, dir](const QJsonValue &, const QString &err) {
                       if (!err.isEmpty())
                           return showError(tr("备份位置"), err);
                       statusBar()->showMessage(tr("备份位置已保存"), 4000);
                       log(S("Backup location: ") + (dir.isEmpty() ? S("default") : dir));
                       refreshAll();
                   });
}

void MainWindow::openBackupDir()
{
    const QString dir = ui->backupDirEdit->text().trimmed().isEmpty() ? ui->backupDirEdit->placeholderText()
                                                                      : ui->backupDirEdit->text().trimmed();
    if (!QFileInfo(dir).isDir()) {
        statusBar()->showMessage(tr("文件夹不存在：%1").arg(dir), 6000);
        return;
    }
    if (!QDesktopServices::openUrl(QUrl::fromLocalFile(dir)))
        statusBar()->showMessage(tr("无法打开 %1").arg(dir), 6000);
}

void MainWindow::exportLog()
{
    const QString name = QDir::home().filePath(
        S("luks-assistant-%1.txt").arg(QDateTime::currentDateTime().toString(S("yyyyMMdd-HHmmss"))));
    const QString path = QFileDialog::getSaveFileName(this, tr("导出日志"), name, tr("文本文件 (*.txt)"));
    if (path.isEmpty())
        return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        showError(tr("导出日志"), f.errorString());
        return;
    }
    f.write(ui->logView->toPlainText().toUtf8());
    f.write("\n");
    statusBar()->showMessage(tr("已导出到 %1").arg(path), 6000);
}

void MainWindow::changeLanguage(int index)
{
    AppSettings::setLanguage(static_cast<AppSettings::Language>(index));
    AppSettings::applyLanguage(); // → changeEvent(LanguageChange)
    if (m_helper->isRunning()) {
        m_helper->call(S("set_language"), QJsonObject{{S("lang"), AppSettings::effectiveLanguage()}},
                       [](const QJsonValue &, const QString &) {});
        refreshAll(); // texts from the helper
    }
}

void MainWindow::changeTheme(int index)
{
    AppSettings::setTheme(static_cast<AppSettings::Theme>(index));
    AppSettings::applyStyle();
    // the platform theme (colours, fonts, dialogs) is chosen at start-up
    statusBar()->showMessage(tr("重新启动 Luks Assistant 后完全生效"), 8000);
}
