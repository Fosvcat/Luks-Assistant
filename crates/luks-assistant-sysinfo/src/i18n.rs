//! Interface language. Source strings are English; translations are GNU
//! gettext catalogs in `po/` (`po/<lang>.po`, template `po/luks-assistant.pot`),
//! embedded at build time and shared with the Qt GUI.
//!
//! * `t!("…")` is a `&'static str` and `t!("… {} …", a)` a `String`, both in
//!   the current language.
//! * `tx!(…)` is a [`Text`], translated only when shown, so one message can
//!   be displayed in the interface language and logged in English.
//!
//! * `n!("…")` marks a literal in a `const` table; it is translated with
//!   [`tr`] where it is shown.
//!
//! Placeholders are plain `{}`, filled in order.
//!
//! Adding a language: add `po/<code>.po` (start from the template) and a line
//! to [`CATALOGS`]; `tests/catalog.rs` checks it is complete.

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

/// Shipped translations: gettext language code and catalog.
pub const CATALOGS: &[(&str, &str)] = &[("zh_CN", include_str!("../../../po/zh_CN.po"))];

/// English (the source language) or one of [`CATALOGS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lang(u8);

static LANG: AtomicU8 = AtomicU8::new(0);

pub fn set_lang(lang: Lang) {
    LANG.store(lang.0, Ordering::Relaxed);
}

pub fn lang() -> Lang {
    Lang(LANG.load(Ordering::Relaxed))
}

impl Lang {
    pub const EN: Lang = Lang(0);

    /// A locale or language code (`zh_CN.UTF-8`, `zh`, `en_US`, `de-AT`):
    /// English, a catalog for the same language and region, or else for the
    /// same language. `None` when nothing matches.
    pub fn from_code(code: &str) -> Option<Lang> {
        let c = code.trim().to_ascii_lowercase().replace('-', "_");
        let c = c.split(['.', '@']).next().unwrap_or("");
        let language = c.split('_').next().unwrap_or("");
        if language == "en" {
            return Some(Lang::EN);
        }
        let find = |f: &dyn Fn(&str) -> bool| {
            CATALOGS
                .iter()
                .position(|(k, _)| f(&k.to_ascii_lowercase()))
                .map(|i| Lang(i as u8 + 1))
        };
        find(&|k| k == c)
            .or_else(|| find(&|k| !language.is_empty() && k.split('_').next() == Some(language)))
    }

    /// `LUKS_ASSISTANT_LANG`, else the locale as gettext reads it
    /// (`LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, `LANG`); English by default.
    pub fn from_env() -> Lang {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        if let Some(l) = var("LUKS_ASSISTANT_LANG").and_then(|v| Lang::from_code(&v)) {
            return l;
        }
        let locale = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|k| var(k));
        // LANGUAGE is a list of preferences, ignored for the C locale
        if locale.as_deref().is_some_and(|l| l != "C" && l != "POSIX") {
            for code in var("LANGUAGE").unwrap_or_default().split(':') {
                if let Some(l) = Lang::from_code(code) {
                    return l;
                }
            }
        }
        locale.and_then(|v| Lang::from_code(&v)).unwrap_or(Lang::EN)
    }

    /// `en` or the catalog's code (`zh_CN`).
    pub fn code(self) -> &'static str {
        match self.0 {
            0 => "en",
            i => CATALOGS.get(i as usize - 1).map(|c| c.0).unwrap_or("en"),
        }
    }
}

/// The strings of a PO file: (msgctxt, msgid, msgstr), without the header,
/// untranslated and fuzzy entries.
pub fn parse_po(src: &str) -> Vec<(Option<String>, String, String)> {
    #[derive(Default)]
    struct Entry {
        ctxt: Option<String>,
        id: Option<String>,
        plural: bool,
        str: Option<String>,
        fuzzy: bool,
    }
    fn quoted(s: &str) -> String {
        let inner = s
            .trim()
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or("");
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(o) => out.push(o),
                None => {}
            }
        }
        out
    }
    // an entry: [#, flags] [msgctxt "…"] msgid "…" msgstr "…", strings
    // continued on following "…" lines
    let mut out = Vec::new();
    let mut e = Entry::default();
    // which string a continuation line extends: 0 ctxt, 1 id, 2 str, 3 none
    let mut target = 3;
    let mut flush = |e: &mut Entry| {
        let e = std::mem::take(e);
        if let (Some(id), Some(s)) = (e.id, e.str) {
            if !id.is_empty() && !s.is_empty() && !e.fuzzy && !e.plural {
                out.push((e.ctxt, id, s));
            }
        }
    };
    for line in src.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let starts_entry = ["#,", "msgctxt ", "msgid "]
            .iter()
            .any(|p| line.starts_with(p));
        if starts_entry && e.str.is_some() {
            flush(&mut e);
            target = 3;
        }
        if let Some(flags) = line.strip_prefix("#,") {
            e.fuzzy = flags.split(',').any(|f| f.trim() == "fuzzy");
        } else if line.starts_with('#') {
            continue;
        } else if let Some(rest) = line.strip_prefix("msgctxt ") {
            e.ctxt = Some(quoted(rest));
            target = 0;
        } else if let Some(rest) = line.strip_prefix("msgid ") {
            e.id = Some(quoted(rest));
            target = 1;
        } else if line.starts_with("msgid_plural ") {
            e.plural = true;
            target = 3;
        } else if let Some(rest) = line.strip_prefix("msgstr ") {
            e.str = Some(quoted(rest));
            target = 2;
        } else if line.starts_with("msgstr[") {
            e.str.get_or_insert_with(String::new);
            target = 3;
        } else if line.starts_with('"') {
            let more = quoted(line);
            match target {
                0 => e.ctxt.get_or_insert_with(String::new).push_str(&more),
                1 => e.id.get_or_insert_with(String::new).push_str(&more),
                2 => e.str.get_or_insert_with(String::new).push_str(&more),
                _ => {}
            }
        }
    }
    flush(&mut e);
    out
}

/// Lookup key of a string with a context, as gettext forms it.
pub fn context_key(ctxt: &str, id: &str) -> String {
    format!("{ctxt}\u{4}{id}")
}

type Catalog = HashMap<&'static str, &'static str>;

fn catalog(i: usize) -> Option<&'static Catalog> {
    static MAPS: OnceLock<Vec<Catalog>> = OnceLock::new();
    MAPS.get_or_init(|| {
        CATALOGS
            .iter()
            .map(|(_, src)| {
                parse_po(src)
                    .into_iter()
                    .map(|(ctxt, id, s)| {
                        let key = match ctxt {
                            Some(c) => context_key(&c, &id),
                            None => id,
                        };
                        (
                            &*Box::leak(key.into_boxed_str()),
                            &*Box::leak(s.into_boxed_str()),
                        )
                    })
                    .collect()
            })
            .collect()
    })
    .get(i)
}

/// `source` in `lang` (the English source when the catalog has no entry).
pub fn tr_in(source: &'static str, lang: Lang) -> &'static str {
    match lang.0 {
        0 => source,
        i => catalog(i as usize - 1)
            .and_then(|c| c.get(source).copied())
            .unwrap_or(source),
    }
}

pub fn tr(source: &'static str) -> &'static str {
    tr_in(source, lang())
}

/// Replace each `{}` of `template` with the next argument (`{{`/`}}` escape braces).
pub fn fill(template: &str, args: &[String]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut args = args.iter();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('{', Some('}')) => {
                chars.next();
                out.push_str(args.next().map(String::as_str).unwrap_or(""));
            }
            ('{', Some('{')) | ('}', Some('}')) => {
                chars.next();
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// A message translated when shown.
#[derive(Debug, Clone, PartialEq)]
pub struct Text(Repr);

#[derive(Debug, Clone, PartialEq)]
enum Repr {
    Tr(&'static str, Vec<Text>),
    Plain(String),
    Join(Vec<Text>, Box<Text>),
}

impl Text {
    pub fn tr(source: &'static str, args: Vec<Text>) -> Text {
        Text(Repr::Tr(source, args))
    }

    /// Text that is not translated (tool output, paths, user input).
    pub fn plain(s: impl Into<String>) -> Text {
        Text(Repr::Plain(s.into()))
    }

    /// `items` separated by `sep`.
    pub fn join(items: Vec<Text>, sep: Text) -> Text {
        Text(Repr::Join(items, Box::new(sep)))
    }

    pub fn render(&self, lang: Lang) -> String {
        match &self.0 {
            Repr::Join(items, sep) => items
                .iter()
                .map(|t| t.render(lang))
                .collect::<Vec<_>>()
                .join(&sep.render(lang)),
            Repr::Tr(source, args) => fill(
                tr_in(source, lang),
                &args.iter().map(|a| a.render(lang)).collect::<Vec<_>>(),
            ),
            Repr::Plain(s) => s.clone(),
        }
    }

    /// For logs, which are always English.
    pub fn en(&self) -> String {
        self.render(Lang::EN)
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render(lang()))
    }
}

impl From<String> for Text {
    fn from(s: String) -> Text {
        Text::plain(s)
    }
}

impl From<&str> for Text {
    fn from(s: &str) -> Text {
        Text::plain(s)
    }
}

impl From<Text> for String {
    fn from(t: Text) -> String {
        t.to_string()
    }
}

impl serde::Serialize for Text {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

/// Deserialized text is never translated again.
impl<'de> serde::Deserialize<'de> for Text {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Text, D::Error> {
        String::deserialize(d).map(Text::plain)
    }
}

/// Arguments of `tx!` are borrowed: a [`Text`] stays translatable, anything
/// else that is `Display` becomes plain text. (Method resolution picks the
/// `Wrap<Text>` impl before the autoref'd generic one.)
pub struct Wrap<'a, T: ?Sized>(pub &'a T);

pub trait ViaText {
    fn to_text(&self) -> Text;
}

impl ViaText for Wrap<'_, Text> {
    fn to_text(&self) -> Text {
        self.0.clone()
    }
}

impl ViaText for Wrap<'_, &Text> {
    fn to_text(&self) -> Text {
        (*self.0).clone()
    }
}

pub trait ViaDisplay {
    fn to_text(&self) -> Text;
}

impl<T: fmt::Display + ?Sized> ViaDisplay for &Wrap<'_, T> {
    fn to_text(&self) -> Text {
        Text::plain(self.0.to_string())
    }
}

#[macro_export]
macro_rules! t {
    ($s:literal) => {
        $crate::i18n::tr($s)
    };
    ($s:literal, $($a:expr),+ $(,)?) => {
        $crate::i18n::fill($crate::i18n::tr($s), &[$(::std::string::ToString::to_string(&$a)),+])
    };
}

/// Marks a literal for the catalog without translating it (for `const`
/// tables); translate it where it is shown with [`tr`].
#[macro_export]
macro_rules! n {
    ($s:literal) => {
        $s
    };
}

#[macro_export]
macro_rules! tx {
    ($s:literal) => {
        $crate::i18n::Text::tr($s, ::std::vec::Vec::new())
    };
    ($s:literal, $($a:expr),+ $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::i18n::{ViaDisplay as _, ViaText as _};
        $crate::i18n::Text::tr($s, ::std::vec![$((&$crate::i18n::Wrap(&$a)).to_text()),+])
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_placeholders_in_order() {
        assert_eq!(fill("{} / {}", &["a".into(), "b".into()]), "a / b");
        assert_eq!(fill("{{x}} {}", &["1".into()]), "{x} 1");
        assert_eq!(fill("{} {}", &["1".into()]), "1 ");
    }

    #[test]
    fn text_renders_per_language() {
        let zh = Lang::from_code("zh").unwrap();
        let inner = Text::tr("Slot", vec![]);
        let t = crate::tx!("Slot {} ({})", inner, "x");
        assert_eq!(
            t,
            Text::tr("Slot {} ({})", vec![inner.clone(), Text::plain("x")])
        );
        assert_eq!(t.en(), "Slot Slot (x)");
        assert_ne!(t.render(zh), t.en());
        // not in the catalog: the source is used
        assert_eq!(
            Text::tr("no such string", vec![]).render(zh),
            "no such string"
        );
    }

    #[test]
    fn language_codes() {
        let zh = Lang::from_code("zh").unwrap();
        assert_eq!(zh.code(), "zh_CN");
        assert_eq!(Lang::from_code("zh_CN.UTF-8"), Some(zh));
        assert_eq!(Lang::from_code("zh-TW"), Some(zh));
        assert_eq!(Lang::from_code("en_US"), Some(Lang::EN));
        assert_eq!(Lang::from_code("C"), None);
        assert_eq!(Lang::from_code("xx_YY"), None);
    }

    #[test]
    fn po_entries() {
        let po = r#"
msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\n"

#: a.rs:1
msgid "One"
msgstr "一"

msgctxt "tab"
msgid "Slots"
msgstr "槽"
"位"

#, fuzzy
msgid "Fuzzy"
msgstr "模糊"

msgid "Line\nbreak \"q\""
msgstr "换行\n\"引号\""

msgid "Untranslated"
msgstr ""
"#;
        assert_eq!(
            parse_po(po),
            vec![
                (None, "One".into(), "一".into()),
                (Some("tab".into()), "Slots".into(), "槽位".into()),
                (None, "Line\nbreak \"q\"".into(), "换行\n\"引号\"".into()),
            ]
        );
    }
}
