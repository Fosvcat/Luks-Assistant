#include "appsettings.h"

#include <QApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QLibraryInfo>
#include <QLocale>
#include <QSettings>
#include <QStyle>
#include <QStyleFactory>
#include <QTranslator>

namespace {

QSettings settings()
{
    return QSettings(QStringLiteral("Luks-Assistant"), QStringLiteral("Luks-Assistant"));
}

/// One string of a PO file: from `"…"`, with C escapes.
QString poString(const QByteArray &line)
{
    const QByteArray t = line.trimmed();
    if (t.size() < 2 || t.front() != '"' || t.back() != '"')
        return {};
    QByteArray out;
    for (qsizetype i = 1; i < t.size() - 1; ++i) {
        char c = t.at(i);
        if (c == '\\' && i + 1 < t.size() - 1) {
            c = t.at(++i);
            c = c == 'n' ? '\n' : c == 't' ? '\t' : c;
        }
        out += c;
    }
    return QString::fromUtf8(out);
}

// A gettext catalog from po/<code>.po (shared with the Rust crates). The
// English source text is the msgid; a .ui "comment" is the msgctxt.
class PoTranslator : public QTranslator
{
public:
    explicit PoTranslator(const QString &code)
    {
        QFile file(QStringLiteral(":/po/%1.po").arg(code));
        if (!file.open(QIODevice::ReadOnly))
            return;
        // an entry: [#, flags] [msgctxt "…"] msgid "…" msgstr "…", strings
        // continued on following "…" lines
        QString ctxt, id, str;
        bool fuzzy = false, plural = false, haveStr = false;
        QString *target = nullptr;
        auto flush = [&] {
            if (haveStr && !id.isEmpty() && !str.isEmpty() && !fuzzy && !plural)
                m_map.insert(ctxt.isEmpty() ? id : ctxt + QChar(4) + id, str);
            ctxt.clear();
            id.clear();
            str.clear();
            fuzzy = plural = haveStr = false;
            target = nullptr;
        };
        for (const QByteArray &raw : file.readAll().split('\n')) {
            const QByteArray line = raw.trimmed();
            if (line.isEmpty())
                continue;
            if ((line.startsWith("#,") || line.startsWith("msgctxt ") || line.startsWith("msgid ")) && haveStr)
                flush();
            if (line.startsWith("#,")) {
                fuzzy = line.contains("fuzzy");
            } else if (line.startsWith('#')) {
                continue;
            } else if (line.startsWith("msgctxt ")) {
                ctxt = poString(line.mid(8));
                target = &ctxt;
            } else if (line.startsWith("msgid ")) {
                id = poString(line.mid(6));
                target = &id;
            } else if (line.startsWith("msgid_plural ")) {
                plural = true;
                target = nullptr;
            } else if (line.startsWith("msgstr ")) {
                str = poString(line.mid(7));
                haveStr = true;
                target = &str;
            } else if (line.startsWith("msgstr[")) {
                haveStr = true;
                target = nullptr;
            } else if (line.startsWith('"') && target) {
                *target += poString(line);
            }
        }
        flush();
    }

    QString translate(const char *, const char *source, const char *disambiguation, int) const override
    {
        QString key = QString::fromUtf8(source);
        if (disambiguation && *disambiguation)
            key = QString::fromUtf8(disambiguation) + QChar(4) + key;
        return m_map.value(key);
    }

    bool isEmpty() const override { return m_map.isEmpty(); }

private:
    QHash<QString, QString> m_map;
};

/// The catalog (po/<code>.po) closest to `uiLanguages`, or "en".
QString pickCatalog(const QStringList &uiLanguages)
{
    const QStringList codes = QDir(QStringLiteral(":/po")).entryList({QStringLiteral("*.po")}, QDir::Files);
    for (QString want : uiLanguages) {
        want.replace(QLatin1Char('-'), QLatin1Char('_'));
        const QString language = want.section(QLatin1Char('_'), 0, 0);
        if (language.compare(QLatin1String("en"), Qt::CaseInsensitive) == 0)
            return QStringLiteral("en");
        for (const QString &file : codes)
            if (file.chopped(3).compare(want, Qt::CaseInsensitive) == 0)
                return file.chopped(3);
        for (const QString &file : codes)
            if (file.section(QLatin1Char('_'), 0, 0).section(QLatin1Char('.'), 0, 0).compare(language, Qt::CaseInsensitive) == 0)
                return file.chopped(3);
    }
    return QStringLiteral("en");
}

bool hasPlatformTheme(const char *file)
{
    return QFileInfo::exists(QLibraryInfo::path(QLibraryInfo::PluginsPath) + QStringLiteral("/platformthemes/")
                             + QLatin1String(file));
}

/// First installed style of `names`.
QString firstStyle(std::initializer_list<const char *> names)
{
    const QStringList keys = QStyleFactory::keys();
    for (const char *n : names)
        for (const QString &k : keys)
            if (k.compare(QLatin1String(n), Qt::CaseInsensitive) == 0)
                return k;
    return QStringLiteral("Fusion");
}

QTranslator *s_qt = nullptr;
QTranslator *s_catalog = nullptr;
const QString s_chinese = QStringLiteral("zh_CN");
// The style the desktop gave us at startup, to return to "follow the system".
QString s_systemStyle;

} // namespace

namespace AppSettings {

Language language()
{
    const QString v = settings().value(QStringLiteral("language")).toString();
    if (v == QLatin1String("en"))
        return Language::English;
    if (v == s_chinese || v == QLatin1String("zh"))
        return Language::Chinese;
    return Language::System;
}

void setLanguage(Language language)
{
    settings().setValue(QStringLiteral("language"), language == Language::English   ? QStringLiteral("en")
                                                    : language == Language::Chinese ? s_chinese
                                                                                    : QStringLiteral("system"));
}

Theme theme()
{
    const QString v = settings().value(QStringLiteral("theme")).toString();
    return v == QLatin1String("qt") ? Theme::Qt : v == QLatin1String("gtk") ? Theme::Gtk : Theme::System;
}

void setTheme(Theme theme)
{
    settings().setValue(QStringLiteral("theme"), theme == Theme::Qt    ? QStringLiteral("qt")
                                                 : theme == Theme::Gtk ? QStringLiteral("gtk")
                                                                       : QStringLiteral("system"));
}

bool showAllPcrs()
{
    return settings().value(QStringLiteral("showAllPcrs"), false).toBool();
}

void setShowAllPcrs(bool all)
{
    settings().setValue(QStringLiteral("showAllPcrs"), all);
}

QString effectiveLanguage()
{
    switch (language()) {
    case Language::English:
        return QStringLiteral("en");
    case Language::Chinese:
        return s_chinese;
    case Language::System:
        break;
    }
    return pickCatalog(QLocale::system().uiLanguages());
}

void applyLanguage()
{
    for (QTranslator **t : {&s_qt, &s_catalog}) {
        if (*t) {
            QApplication::removeTranslator(*t);
            delete *t;
            *t = nullptr;
        }
    }
    // English is the source language: other languages need our catalog and
    // Qt's own translation (OK, Cancel, …).
    const QString code = effectiveLanguage();
    if (code == QLatin1String("en"))
        return;
    s_catalog = new PoTranslator(code);
    QApplication::installTranslator(s_catalog);
    s_qt = new QTranslator;
    if (s_qt->load(QLocale(code), QStringLiteral("qtbase"), QStringLiteral("_"),
                   QLibraryInfo::path(QLibraryInfo::TranslationsPath)))
        QApplication::installTranslator(s_qt);
}

QByteArray cliTr(const char *english)
{
    // as the TUI decides: LUKS_ASSISTANT_LANG, else the locale
    QStringList want;
    const QByteArray forced = qgetenv("LUKS_ASSISTANT_LANG");
    if (!forced.isEmpty())
        want << QString::fromLocal8Bit(forced);
    want << QLocale::system().uiLanguages();
    const QString code = pickCatalog(want);
    if (code == QLatin1String("en"))
        return english;
    const QString t = PoTranslator(code).translate(nullptr, english, nullptr, -1);
    return t.isEmpty() ? QByteArray(english) : t.toLocal8Bit();
}

void prepareTheme()
{
    switch (theme()) {
    case Theme::System:
        return;
    case Theme::Qt:
        // KDE's platform theme where installed, otherwise Qt's own defaults.
        if (hasPlatformTheme("KDEPlasmaPlatformTheme6.so"))
            qputenv("QT_QPA_PLATFORMTHEME", "kde");
        else
            qunsetenv("QT_QPA_PLATFORMTHEME");
        return;
    case Theme::Gtk:
        if (hasPlatformTheme("libqgtk3.so"))
            qputenv("QT_QPA_PLATFORMTHEME", "gtk3");
        return;
    }
}

void applyStyle()
{
    if (s_systemStyle.isEmpty())
        s_systemStyle = QApplication::style()->name();
    switch (theme()) {
    case Theme::System:
        if (QApplication::style()->name() != s_systemStyle)
            QApplication::setStyle(s_systemStyle);
        return;
    case Theme::Qt:
        QApplication::setStyle(firstStyle({"Breeze"}));
        return;
    case Theme::Gtk:
        QApplication::setStyle(firstStyle({"Adwaita", "adwaita"}));
        return;
    }
}

} // namespace AppSettings
