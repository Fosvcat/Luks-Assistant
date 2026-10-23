#include "appsettings.h"

#include <QApplication>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QLibraryInfo>
#include <QLocale>
#include <QSettings>
#include <QStyleFactory>
#include <QTranslator>

namespace {

QSettings settings()
{
    return QSettings(QStringLiteral("Luks-Assistant"), QStringLiteral("Luks-Assistant"));
}

// English for the Chinese source strings, from i18n/en.tsv (shared with the
// Rust crates): one "中文<TAB>English" pair per line, \n and \t escaped.
class Catalog : public QTranslator
{
public:
    Catalog()
    {
        QFile file(QStringLiteral(":/i18n/en.tsv"));
        if (!file.open(QIODevice::ReadOnly))
            return;
        for (const QByteArray &raw : file.readAll().split('\n')) {
            const QString line = QString::fromUtf8(raw);
            const int tab = line.indexOf(QLatin1Char('\t'));
            if (line.startsWith(QLatin1Char('#')) || tab < 0)
                continue;
            m_map.insert(unescape(line.left(tab)), unescape(line.mid(tab + 1)));
        }
    }

    // A disambiguation (the .ui "comment") selects the entry "source@comment".
    QString translate(const char *, const char *source, const char *disambiguation, int) const override
    {
        const QString key = QString::fromUtf8(source);
        if (disambiguation && *disambiguation) {
            const QString specific = m_map.value(key + QLatin1Char('@') + QString::fromUtf8(disambiguation));
            if (!specific.isEmpty())
                return specific;
        }
        return m_map.value(key);
    }

    bool isEmpty() const override { return m_map.isEmpty(); }

private:
    static QString unescape(const QString &s)
    {
        QString out;
        for (int i = 0; i < s.size(); ++i) {
            if (s.at(i) == QLatin1Char('\\') && i + 1 < s.size()) {
                const QChar c = s.at(++i);
                out += c == QLatin1Char('n') ? QLatin1Char('\n') : c == QLatin1Char('t') ? QLatin1Char('\t') : c;
            } else {
                out += s.at(i);
            }
        }
        return out;
    }

    QHash<QString, QString> m_map;
};

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

} // namespace

namespace AppSettings {

Language language()
{
    const QString v = settings().value(QStringLiteral("language")).toString();
    return v == QLatin1String("en") ? Language::English : v == QLatin1String("zh") ? Language::Chinese : Language::System;
}

void setLanguage(Language language)
{
    settings().setValue(QStringLiteral("language"), language == Language::English   ? QStringLiteral("en")
                                                    : language == Language::Chinese ? QStringLiteral("zh")
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
        return QStringLiteral("zh");
    case Language::System:
        break;
    }
    return QLocale::system().language() == QLocale::Chinese ? QStringLiteral("zh") : QStringLiteral("en");
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
    // The source strings are Chinese: English comes from the catalog, while
    // Qt's own buttons (OK, Cancel, …) need its Chinese translation.
    if (effectiveLanguage() == QLatin1String("en")) {
        s_catalog = new Catalog;
        QApplication::installTranslator(s_catalog);
    } else {
        s_qt = new QTranslator;
        if (s_qt->load(QLocale(QLocale::Chinese, QLocale::China), QStringLiteral("qtbase"), QStringLiteral("_"),
                       QLibraryInfo::path(QLibraryInfo::TranslationsPath)))
            QApplication::installTranslator(s_qt);
    }
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
    switch (theme()) {
    case Theme::System:
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
