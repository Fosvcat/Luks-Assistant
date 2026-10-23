//! The English catalog `i18n/en.tsv` must cover every Chinese string of the
//! Rust crates (inside `t!`/`tx!`/`n!`) and of the Qt GUI (inside `tr()`),
//! with the same placeholders, and hold nothing else.
//!
//! On failure the missing entries are printed as TSV lines to fill in.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn is_cjk(c: char) -> bool {
    ('\u{3000}'..='\u{9fff}').contains(&c) || ('\u{ff00}'..='\u{ffef}').contains(&c)
}

fn files(dir: &Path, ext: &[&str], out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            files(&p, ext, out);
        } else if p
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| ext.contains(&x))
        {
            out.push(p);
        }
    }
}

/// A string literal: its value and the code just before it.
struct Lit {
    value: String,
    /// Chinese written as such in the source (`\u{..}` escapes opt out).
    cjk: bool,
    before: String,
    line: usize,
}

/// Decode the escapes shared by Rust and C++ (plus Rust's `\u{..}` and
/// line continuation).
fn unescape(raw: &str) -> String {
    let mut out = String::new();
    let mut it = raw.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('0') => out.push('\0'),
            Some('\n') => {
                while it.peek().is_some_and(|c| c.is_whitespace()) {
                    it.next();
                }
            }
            Some('u') if it.peek() == Some(&'{') => {
                let hex: String = it.by_ref().skip(1).take_while(|c| *c != '}').collect();
                out.extend(u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32));
            }
            Some(o) => out.push(o),
            None => {}
        }
    }
    out
}

/// String literals outside comments; adjacent literals (C++) are joined.
fn literals(src: &str, rust: bool) -> Vec<Lit> {
    let b: Vec<char> = src.chars().collect();
    let mut out: Vec<Lit> = Vec::new();
    let mut code_since_last = String::new();
    let (mut i, mut line) = (0, 1);
    while i < b.len() {
        let c = b[i];
        if c == '\n' {
            line += 1;
        }
        if c == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && b.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                line += usize::from(b[i] == '\n');
                i += 1;
            }
            i += 2;
            continue;
        }
        let ident_before = i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_');
        if rust && c == 'r' && matches!(b.get(i + 1), Some('"' | '#')) && !ident_before {
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&'"') {
                j += 1;
                let close: String = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                let rest: String = b[j..].iter().collect();
                let end = rest.find(&close).unwrap();
                line += rest[..end].matches('\n').count();
                i = j + rest[..end].chars().count() + close.chars().count();
                code_since_last.push('x');
                continue;
            }
        }
        if c == '\'' {
            // a char literal; Rust lifetimes have no closing quote right after
            let s: String = b[i..(i + 12).min(b.len())].iter().collect();
            let len = if let Some(esc) = s.strip_prefix("'\\") {
                esc.find('\'').map(|e| e + 3)
            } else {
                s.char_indices()
                    .nth(2)
                    .filter(|(_, ch)| *ch == '\'')
                    .map(|(e, _)| e + 1)
            };
            if let Some(len) = len {
                i += s[..len].chars().count();
                code_since_last.push('x');
                continue;
            }
        }
        if c == '"' {
            let start_line = line;
            let mut j = i + 1;
            let mut raw = String::new();
            while b[j] != '"' {
                if b[j] == '\\' {
                    raw.push(b[j]);
                    j += 1;
                }
                line += usize::from(b[j] == '\n');
                raw.push(b[j]);
                j += 1;
            }
            let value = unescape(&raw);
            match out.last_mut() {
                Some(last) if !rust && code_since_last.trim().is_empty() => {
                    last.value.push_str(&value);
                    last.cjk |= raw.chars().any(is_cjk);
                }
                _ => out.push(Lit {
                    value,
                    cjk: raw.chars().any(is_cjk),
                    before: code_since_last.clone(),
                    line: start_line,
                }),
            }
            code_since_last.clear();
            i = j + 1;
            continue;
        }
        code_since_last.push(c);
        if code_since_last.len() > 200 {
            let cut = code_since_last.char_indices().nth(100).unwrap().0;
            code_since_last.drain(..cut);
        }
        i += 1;
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

fn ends_with_call(before: &str, names: &[&str]) -> bool {
    let b = before.trim_end();
    names.iter().any(|n| {
        b.strip_suffix(n)
            .is_some_and(|rest| !rest.ends_with(|c: char| c.is_alphanumeric() || c == '_'))
    })
}

/// `{}` count and `%N` markers.
fn placeholders(s: &str) -> (usize, Vec<String>) {
    let chars: Vec<char> = s.chars().collect();
    let mut pct: Vec<String> = chars
        .windows(2)
        .filter(|w| w[0] == '%' && w[1].is_ascii_digit())
        .map(|w| format!("%{}", w[1]))
        .collect();
    pct.sort();
    (s.matches("{}").count(), pct)
}

#[test]
fn catalog_matches_sources() {
    let root = root();
    let mut used: BTreeMap<String, String> = BTreeMap::new(); // key → where
    let mut errors = Vec::new();
    let rel = |p: &Path| p.strip_prefix(&root).unwrap().display().to_string();

    let mut rs = Vec::new();
    files(&root.join("crates"), &["rs"], &mut rs);
    for p in rs
        .iter()
        .filter(|p| p.components().any(|c| c.as_os_str() == "src"))
    {
        let src = std::fs::read_to_string(p).unwrap();
        let code = src.split("#[cfg(test)]").next().unwrap();
        for l in literals(code, true) {
            if !l.cjk {
                continue;
            }
            let at = format!("{}:{}", rel(p), l.line);
            if ends_with_call(&l.before, &["t!(", "tx!(", "n!("]) {
                used.entry(escape(&l.value)).or_insert(at);
            } else {
                errors.push(format!(
                    "{at}: Chinese text outside t!/tx!/n!: {:?}",
                    l.value
                ));
            }
        }
    }

    let mut cpp = Vec::new();
    files(&root.join("gui/src"), &["cpp", "h"], &mut cpp);
    for p in &cpp {
        let src = std::fs::read_to_string(p).unwrap();
        for l in literals(&src, false) {
            if !l.cjk {
                continue;
            }
            let at = format!("{}:{}", rel(p), l.line);
            if ends_with_call(&l.before, &["tr("]) {
                used.entry(escape(&l.value)).or_insert(at);
            } else if !ends_with_call(&l.before, &["bilingual("]) {
                errors.push(format!("{at}: Chinese text outside tr(): {:?}", l.value));
            }
        }
    }

    let mut ui = Vec::new();
    files(&root.join("gui/src"), &["ui"], &mut ui);
    for p in &ui {
        let src = std::fs::read_to_string(p).unwrap();
        // <string>…</string> and <string comment="c">…</string> (key "…@c");
        // notr="true" strings are not translated.
        for part in src.split("<string").skip(1) {
            let Some((attrs, rest)) = part.split_once('>') else {
                continue;
            };
            if attrs.contains("notr=\"true\"") || attrs.ends_with('/') {
                continue;
            }
            let comment = attrs
                .split("comment=\"")
                .nth(1)
                .and_then(|c| c.split('"').next());
            let v = rest.split("</string>").next().unwrap();
            let v = v
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&amp;", "&");
            if v.chars().any(is_cjk) {
                let key = match comment {
                    Some(c) => format!("{}@{c}", escape(&v)),
                    None => escape(&v),
                };
                used.entry(key).or_insert_with(|| rel(p));
            }
        }
    }

    let tsv = std::fs::read_to_string(root.join("i18n/en.tsv")).unwrap();
    let mut catalog: BTreeMap<String, String> = BTreeMap::new();
    for (n, line) in tsv.lines().enumerate() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let Some((zh, en)) = line.split_once('\t') else {
            errors.push(format!("en.tsv:{}: no tab", n + 1));
            continue;
        };
        if en.trim().is_empty() || en.chars().any(is_cjk) {
            errors.push(format!("en.tsv:{}: no English for {zh:?}", n + 1));
        }
        if placeholders(zh) != placeholders(en) {
            errors.push(format!(
                "en.tsv:{}: placeholders differ: {zh:?} / {en:?}",
                n + 1
            ));
        }
        if catalog.insert(zh.to_owned(), en.to_owned()).is_some() {
            errors.push(format!("en.tsv:{}: duplicate {zh:?}", n + 1));
        }
    }

    let stale: BTreeSet<_> = catalog.keys().filter(|k| !used.contains_key(*k)).collect();
    for k in &stale {
        errors.push(format!("en.tsv: unused entry {k:?}"));
    }
    let missing: Vec<_> = used.keys().filter(|k| !catalog.contains_key(*k)).collect();
    if !missing.is_empty() {
        eprintln!("---- missing catalog entries ----");
        for k in &missing {
            eprintln!("{k}\t\t# {}", used[*k]);
        }
        errors.push(format!(
            "{} strings missing from i18n/en.tsv",
            missing.len()
        ));
    }
    assert!(errors.is_empty(), "\n{}", errors.join("\n"));
}
