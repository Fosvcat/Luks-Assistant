// Settings from the About and System pages, kept in
// ~/.config/Luks-Assistant/Luks-Assistant.conf.
#pragma once

#include <QByteArray>
#include <QString>

namespace AppSettings {

enum class Language { System, English, Chinese };
/// How widgets are drawn: as the desktop does, as native Qt (Breeze when
/// installed, otherwise Fusion), or through Qt's GTK platform theme.
enum class Theme { System, Qt, Gtk };

Language language();
void setLanguage(Language language);
Theme theme();
void setTheme(Theme theme);

/// The language in use: "en" or the code of a catalog in po/ ("zh_CN").
QString effectiveLanguage();

/// `english` in the locale's language, for terminal messages before Qt starts.
QByteArray cliTr(const char *english);

/// Install the translators for the chosen language; widgets receive
/// QEvent::LanguageChange.
void applyLanguage();
/// Choose the platform theme for the chosen Theme; call before QApplication.
void prepareTheme();
/// Set the widget style for the chosen Theme; call after QApplication.
void applyStyle();

/// Show all 24 PCRs instead of the preferred ones.
bool showAllPcrs();
void setShowAllPcrs(bool all);

} // namespace AppSettings
