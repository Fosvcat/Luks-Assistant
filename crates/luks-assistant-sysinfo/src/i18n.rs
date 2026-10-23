//! Interface language. Source strings are Chinese; English comes from the
//! catalog `i18n/en.tsv`, which the Qt GUI uses too.
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

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Zh,
    En,
}

static LANG: AtomicU8 = AtomicU8::new(0);

pub fn set_lang(lang: Lang) {
    LANG.store(lang as u8, Ordering::Relaxed);
}

pub fn lang() -> Lang {
    if LANG.load(Ordering::Relaxed) == Lang::En as u8 {
        Lang::En
    } else {
        Lang::Zh
    }
}

impl Lang {
    /// `zh…` → Chinese, `en…` → English.
    pub fn from_code(code: &str) -> Option<Lang> {
        let c = code.trim().to_ascii_lowercase();
        if c.starts_with("zh") {
            Some(Lang::Zh)
        } else if c.starts_with("en") {
            Some(Lang::En)
        } else {
            None
        }
    }

    /// `LUKS_ASSISTANT_LANG`, else the locale (`LC_ALL`, `LC_MESSAGES`,
    /// `LANG`): Chinese for `zh_*`, English otherwise.
    pub fn from_env() -> Lang {
        if let Some(l) = std::env::var("LUKS_ASSISTANT_LANG")
            .ok()
            .and_then(|v| Lang::from_code(&v))
        {
            return l;
        }
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|k| std::env::var(k).ok())
            .find(|v| !v.is_empty())
            .and_then(|v| Lang::from_code(&v))
            .unwrap_or(Lang::En)
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::Zh => "zh",
            Lang::En => "en",
        }
    }
}

const CATALOG: &str = include_str!("../../../i18n/en.tsv");

fn unescape(s: &'static str) -> &'static str {
    if !s.contains('\\') {
        return s;
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    Box::leak(out.into_boxed_str())
}

/// Chinese → English pairs of the catalog.
pub fn catalog() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        CATALOG
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('\t'))
            .map(|(zh, en)| (unescape(zh), unescape(en)))
            .collect()
    })
}

/// `zh` in `lang` (the Chinese source when the catalog has no entry).
pub fn tr_in(zh: &'static str, lang: Lang) -> &'static str {
    match lang {
        Lang::Zh => zh,
        Lang::En => catalog().get(zh).copied().unwrap_or(zh),
    }
}

pub fn tr(zh: &'static str) -> &'static str {
    tr_in(zh, lang())
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
    pub fn tr(zh: &'static str, args: Vec<Text>) -> Text {
        Text(Repr::Tr(zh, args))
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
            Repr::Tr(zh, args) => fill(
                tr_in(zh, lang),
                &args.iter().map(|a| a.render(lang)).collect::<Vec<_>>(),
            ),
            Repr::Plain(s) => s.clone(),
        }
    }

    /// For logs, which are always English.
    pub fn en(&self) -> String {
        self.render(Lang::En)
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
        let inner = Text::tr("测试内层", vec![]);
        let t = crate::tx!("外层 {} {}", inner, "x");
        assert_eq!(
            t,
            Text::tr("外层 {} {}", vec![inner.clone(), Text::plain("x")])
        );
        assert_eq!(t.render(Lang::Zh), "外层 测试内层 x");
        // not in the catalog: the source is used
        assert_eq!(t.en(), "外层 测试内层 x");
    }

    #[test]
    fn language_codes() {
        assert_eq!(Lang::from_code("zh_CN.UTF-8"), Some(Lang::Zh));
        assert_eq!(Lang::from_code("en_US"), Some(Lang::En));
        assert_eq!(Lang::from_code("C"), None);
    }
}
