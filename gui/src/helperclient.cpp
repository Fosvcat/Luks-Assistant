#include "helperclient.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QStandardPaths>

#include <unistd.h>

HelperClient::HelperClient(QObject *parent)
    : QObject(parent)
{
}

HelperClient::~HelperClient()
{
    if (m_proc && m_proc->state() != QProcess::NotRunning) {
        // The helper runs as root and cannot be killed from here; closing
        // its stdin ends its request loop.
        m_proc->closeWriteChannel();
        m_proc->waitForFinished(2000);
    }
}

QString HelperClient::findHelper()
{
    const QString env = qEnvironmentVariable("LUKS_ASSISTANT_HELPER");
    if (!env.isEmpty())
        return env;
    const QStringList candidates = {
        QCoreApplication::applicationDirPath() + QStringLiteral("/Luks-Assistant-Helper"),
        QStringLiteral("/usr/libexec/Luks-Assistant-Helper"),
        QStringLiteral("/usr/local/libexec/Luks-Assistant-Helper"),
        QStringLiteral("/usr/lib/luks-assistant/Luks-Assistant-Helper"),
    };
    for (const QString &c : candidates) {
        QFileInfo fi(c);
        if (fi.isFile() && fi.isExecutable())
            return fi.canonicalFilePath();
    }
    return {};
}

bool HelperClient::isRunning() const
{
    return m_proc && m_proc->state() == QProcess::Running && !m_hello.isEmpty();
}

void HelperClient::start()
{
    const QString helper = findHelper();
    if (helper.isEmpty()) {
        emit failed(tr("找不到 Luks-Assistant-Helper"));
        return;
    }
    if (m_proc) {
        m_proc->disconnect(this);
        m_proc->deleteLater();
    }
    m_buffer.clear();
    m_stderr.clear();
    m_hello = {};
    m_proc = new QProcess(this);

    QStringList args;
    // Development overrides travel as arguments: pkexec clears the environment.
    const QList<QPair<const char *, QString>> overrides = {
        {"LUKS_ASSISTANT_TPM2_DEVICE", QStringLiteral("--tpm2-device")},
        {"LUKS_ASSISTANT_ETC_DIR", QStringLiteral("--etc-dir")},
        {"LUKS_ASSISTANT_STATE_DIR", QStringLiteral("--state-dir")},
    };
    for (const auto &o : overrides) {
        const QString v = qEnvironmentVariable(o.first);
        if (!v.isEmpty())
            args << o.second << v;
    }
    if (qEnvironmentVariable("LUKS_ASSISTANT_FAST_KDF") == QLatin1String("1"))
        args << QStringLiteral("--fast-kdf");

    connect(m_proc, &QProcess::readyReadStandardOutput, this, &HelperClient::onReadyRead);
    connect(m_proc, &QProcess::readyReadStandardError, this, [this] {
        m_stderr += QString::fromUtf8(m_proc->readAllStandardError());
    });
    connect(m_proc, &QProcess::finished, this, &HelperClient::onFinished);
    connect(m_proc, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart)
            emit failed(tr("无法启动后端：%1").arg(m_proc->errorString()));
    });

    if (geteuid() == 0) {
        m_proc->start(helper, args);
    } else {
        m_proc->start(QStringLiteral("pkexec"), QStringList{helper} + args);
    }

    call(QStringLiteral("hello"), QJsonValue(), [this](const QJsonValue &ok, const QString &error) {
        if (!error.isEmpty()) {
            emit failed(error);
            return;
        }
        m_hello = ok.toObject();
        emit ready();
    });
}

void HelperClient::call(const QString &method, const QJsonValue &params, Done done)
{
    if (!m_proc || m_proc->state() == QProcess::NotRunning) {
        // Defer, so callers always get their answer asynchronously.
        QMetaObject::invokeMethod(this, [done] { done({}, tr("后端未运行")); }, Qt::QueuedConnection);
        return;
    }
    const quint64 id = ++m_next;
    QJsonObject msg{{QStringLiteral("id"), static_cast<qint64>(id)}, {QStringLiteral("method"), method}};
    if (!params.isNull() && !params.isUndefined())
        msg.insert(QStringLiteral("params"), params);
    m_pending.insert(id, std::move(done));
    m_proc->write(QJsonDocument(msg).toJson(QJsonDocument::Compact) + '\n');
}

void HelperClient::onReadyRead()
{
    m_buffer += m_proc->readAllStandardOutput();
    int nl;
    while ((nl = m_buffer.indexOf('\n')) >= 0) {
        const QByteArray line = m_buffer.left(nl);
        m_buffer.remove(0, nl + 1);
        if (line.trimmed().isEmpty())
            continue;
        const QJsonObject reply = QJsonDocument::fromJson(line).object();
        const quint64 id = static_cast<quint64>(reply.value(QStringLiteral("id")).toInteger());
        if (reply.contains(QStringLiteral("event"))) {
            const QJsonObject e = reply.value(QStringLiteral("event")).toObject();
            emit event(e.value(QStringLiteral("kind")).toString(), e.value(QStringLiteral("text")).toString());
            continue;
        }
        auto it = m_pending.find(id);
        if (it == m_pending.end())
            continue;
        Done done = std::move(it.value());
        m_pending.erase(it);
        if (reply.contains(QStringLiteral("ok")))
            done(reply.value(QStringLiteral("ok")), {});
        else
            done({}, reply.value(QStringLiteral("err")).toString());
    }
}

QString HelperClient::exitMessage(int exitCode) const
{
    switch (exitCode) {
    case 126:
        return tr("已取消管理员认证");
    case 127:
        return tr("认证失败或 pkexec 不可用");
    default:
        return m_stderr.trimmed().isEmpty() ? tr("后端已退出") : tr("后端已退出：%1").arg(m_stderr.trimmed());
    }
}

void HelperClient::onFinished(int exitCode, QProcess::ExitStatus)
{
    const QString message = exitMessage(exitCode);
    m_hello = {};
    const auto pending = std::exchange(m_pending, {});
    for (const Done &done : pending)
        done({}, message);
    if (pending.isEmpty())
        emit failed(message);
}
