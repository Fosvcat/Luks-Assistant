#include "appsettings.h"

#include <QApplication>
#include <QFile>
#include <QHash>
#include <QLibraryInfo>
#include <QLocale>
#include <QPalette>
#include <QSettings>
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

QPalette makePalette(bool dark)
{
    const QColor window = dark ? QColor(0x2a, 0x2e, 0x32) : QColor(0xef, 0xf0, 0xf1);
    const QColor text = dark ? QColor(0xfc, 0xfc, 0xfc) : QColor(0x23, 0x26, 0x27);
    const QColor base = dark ? QColor(0x1b, 0x1e, 0x20) : QColor(0xfc, 0xfc, 0xfc);
    const QColor alternate = dark ? QColor(0x23, 0x26, 0x29) : QColor(0xf3, 0xf4, 0xf5);
    const QColor button = dark ? QColor(0x31, 0x36, 0x3b) : QColor(0xef, 0xf0, 0xf1);
    const QColor disabled = dark ? QColor(0x6e, 0x71, 0x75) : QColor(0xa0, 0xa2, 0xa4);
    const QColor highlight(0x3d, 0xae, 0xe9);

    QPalette p(button, window);
    p.setColor(QPalette::WindowText, text);
    p.setColor(QPalette::Text, text);
    p.setColor(QPalette::ButtonText, text);
    p.setColor(QPalette::Base, base);
    p.setColor(QPalette::AlternateBase, alternate);
    p.setColor(QPalette::ToolTipBase, dark ? button : QColor(0xf7, 0xf7, 0xf7));
    p.setColor(QPalette::ToolTipText, text);
    p.setColor(QPalette::PlaceholderText, disabled);
    p.setColor(QPalette::BrightText, Qt::white);
    p.setColor(QPalette::Highlight, highlight);
    p.setColor(QPalette::HighlightedText, QColor(0xfc, 0xfc, 0xfc));
    p.setColor(QPalette::Link, dark ? QColor(0x1d, 0x99, 0xf3) : QColor(0x29, 0x80, 0xb9));
    for (QPalette::ColorRole role : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText})
        p.setColor(QPalette::Disabled, role, disabled);
    p.setColor(QPalette::Disabled, QPalette::Highlight, dark ? QColor(0x47, 0x4d, 0x54) : QColor(0xc6, 0xc8, 0xca));
    return p;
}

QTranslator *s_qt = nullptr;
QTranslator *s_catalog = nullptr;
bool s_paletteSet = false;

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
    return v == QLatin1String("light") ? Theme::Light : v == QLatin1String("dark") ? Theme::Dark : Theme::System;
}

void setTheme(Theme theme)
{
    settings().setValue(QStringLiteral("theme"), theme == Theme::Light  ? QStringLiteral("light")
                                                 : theme == Theme::Dark ? QStringLiteral("dark")
                                                                        : QStringLiteral("system"));
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

void applyTheme()
{
    const Theme t = theme();
    if (t == Theme::System) {
        // An unresolved palette falls back to the platform's (KDE colour
        // scheme, GTK theme, …).
        if (s_paletteSet)
            QApplication::setPalette(QPalette());
        s_paletteSet = false;
        return;
    }
    QApplication::setPalette(makePalette(t == Theme::Dark));
    s_paletteSet = true;
}

} // namespace AppSettings
