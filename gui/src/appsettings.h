// Language and theme chosen on the About page, kept in
// ~/.config/Luks-Assistant/Luks-Assistant.conf.
#pragma once

#include <QString>

namespace AppSettings {

enum class Language { System, English, Chinese };
enum class Theme { System, Light, Dark };

Language language();
void setLanguage(Language language);
Theme theme();
void setTheme(Theme theme);

/// The language in use: "en" or "zh".
QString effectiveLanguage();

/// Install the translators for the chosen language; widgets receive
/// QEvent::LanguageChange.
void applyLanguage();
/// Apply the chosen palette (the platform's own for Theme::System).
void applyTheme();

} // namespace AppSettings
