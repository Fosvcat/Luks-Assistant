// Talks to Luks-Assistant-Helper (started through pkexec) over its
// stdin/stdout: one JSON request per line, replies matched by id.
#pragma once

#include <QHash>
#include <QJsonObject>
#include <QJsonValue>
#include <QObject>
#include <QProcess>
#include <functional>

class HelperClient : public QObject
{
    Q_OBJECT

public:
    /// Called with the `ok` value, or with an error message.
    using Done = std::function<void(const QJsonValue &ok, const QString &error)>;

    explicit HelperClient(QObject *parent = nullptr);
    ~HelperClient() override;

    /// Start the helper (pkexec unless already root) and send `hello`.
    void start();
    bool isRunning() const;
    void call(const QString &method, const QJsonValue &params, Done done);
    QJsonObject hello() const { return m_hello; }

    static QString findHelper();

signals:
    void ready();
    void failed(const QString &message);
    /// `progress` (a plan step started) or `output` (command output).
    void event(const QString &kind, const QString &text);

private:
    void onReadyRead();
    void onFinished(int exitCode, QProcess::ExitStatus status);
    QString exitMessage(int exitCode) const;

    QProcess *m_proc = nullptr;
    QByteArray m_buffer;
    QString m_stderr;
    quint64 m_next = 0;
    QHash<quint64, Done> m_pending;
    QJsonObject m_hello;
};
