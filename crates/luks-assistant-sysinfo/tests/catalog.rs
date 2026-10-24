//! Translations are GNU gettext catalogs. This test extracts the English
//! source strings of the Rust crates (`t!`/`tx!`/`n!`) and of the Qt GUI
//! (`tr()`, `cliTr()` and `.ui` files), and checks that
//!
//! * the sources hold no non-English text outside those strings,
//! * `po/luks-assistant.pot` is the extracted template,
//! * every `po/<lang>.po` translates all of it with the same placeholders.
//!
//! `UPDATE_PO=1 cargo test -p luks-assistant-sysinfo --test catalog` rewrites
//! the template and merges it into the `.po` files: new strings get an empty
//! translation to fill in, strings no longer used are dropped.

use luks_assistant_sysinfo::i18n::parse_po;
use std::collections::BTreeMap;
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

fn ends_with_call(before: &str, names: &[&str]) -> bool {
    let b = before.trim_end();
    names.iter().any(|n| {
        b.strip_suffix(n)
            .is_some_and(|rest| !rest.ends_with(|c: char| c.is_alphanumeric() || c == '_'))
    })
}

/// (msgctxt, msgid)
type Key = (Option<String>, String);

fn po_quote(s: &str) -> String {
    let esc = |s: &str| {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\t', "\\t")
            .replace('\n', "\\n")
    };
    if s.contains('\n') && s.trim_end_matches('\n').contains('\n') {
        let mut out = String::from("\"\"");
        for part in s.split_inclusive('\n') {
            out.push_str(&format!("\n\"{}\"", esc(part)));
        }
        out
    } else {
        format!("\"{}\"", esc(s))
    }
}

fn entry(out: &mut String, key: &Key, refs: &[String], msgstr: &str) {
    out.push('\n');
    for r in refs {
        out.push_str(&format!("#: {r}\n"));
    }
    if let Some(c) = &key.0 {
        out.push_str(&format!("msgctxt {}\n", po_quote(c)));
    }
    out.push_str(&format!("msgid {}\n", po_quote(&key.1)));
    out.push_str(&format!("msgstr {}\n", po_quote(msgstr)));
}

/// The header entry of a .po file (everything before the first `#:`).
fn po_header(src: &str) -> String {
    let head = src.find("\n#: ").map(|i| &src[..i]).unwrap_or(src);
    format!("{}\n", head.trim_end())
}

const POT_HEADER: &str = r#"# Luks Assistant: translatable strings (generated, do not edit).
# Update with: UPDATE_PO=1 cargo test -p luks-assistant-sysinfo --test catalog
msgid ""
msgstr ""
"Project-Id-Version: Luks Assistant\n"
"Language-Team: LANGUAGE <LL@li.org>\n"
"Language: \n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=UTF-8\n"
"Content-Transfer-Encoding: 8bit\n"
"#;

#[test]
fn catalog_matches_sources() {
    let root = root();
    // key → locations, in order of first appearance
    let mut used: Vec<(Key, Vec<String>)> = Vec::new();
    let mut add = |key: Key, at: String| match used.iter_mut().find(|(k, _)| *k == key) {
        Some((_, refs)) => refs.push(at),
        None => used.push((key, vec![at])),
    };
    let mut errors = Vec::new();
    let rel = |p: &Path| p.strip_prefix(&root).unwrap().display().to_string();

    let mut rs = Vec::new();
    files(&root.join("crates"), &["rs"], &mut rs);
    rs.sort();
    for p in rs
        .iter()
        .filter(|p| p.components().any(|c| c.as_os_str() == "src"))
    {
        let src = std::fs::read_to_string(p).unwrap();
        let code = src.split("#[cfg(test)]").next().unwrap();
        for l in literals(code, true) {
            let at = format!("{}:{}", rel(p), l.line);
            if ends_with_call(&l.before, &["t!(", "tx!(", "n!("]) {
                add((None, l.value), at);
            } else if l.cjk {
                errors.push(format!("{at}: not English: {:?}", l.value));
            }
        }
    }

    let mut cpp = Vec::new();
    files(&root.join("gui/src"), &["cpp", "h"], &mut cpp);
    cpp.sort();
    for p in &cpp {
        let src = std::fs::read_to_string(p).unwrap();
        for l in literals(&src, false) {
            let at = format!("{}:{}", rel(p), l.line);
            if ends_with_call(&l.before, &["tr(", "cliTr("]) {
                add((None, l.value), at);
            } else if l.cjk {
                errors.push(format!("{at}: not English: {:?}", l.value));
            }
        }
    }

    let mut ui = Vec::new();
    files(&root.join("gui/src"), &["ui"], &mut ui);
    ui.sort();
    for p in &ui {
        let src = std::fs::read_to_string(p).unwrap();
        // <string>…</string> and <string comment="c">…</string> (msgctxt c);
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
                .and_then(|c| c.split('"').next())
                .map(str::to_owned);
            let v = rest.split("</string>").next().unwrap();
            let v = v
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&amp;", "&");
            if v.chars().any(is_cjk) {
                errors.push(format!("{}: not English: {v:?}", rel(p)));
            } else if v.chars().any(char::is_alphabetic) {
                add((comment, v), rel(p));
            }
        }
    }

    let mut pot = String::from(POT_HEADER);
    for (key, refs) in &used {
        entry(&mut pot, key, refs, "");
    }
    let update = std::env::var("UPDATE_PO").is_ok_and(|v| v == "1");
    let pot_path = root.join("po/luks-assistant.pot");
    if update {
        std::fs::write(&pot_path, &pot).unwrap();
    } else if std::fs::read_to_string(&pot_path).ok().as_deref() != Some(pot.as_str()) {
        errors.push("po/luks-assistant.pot is out of date: run UPDATE_PO=1 cargo test -p luks-assistant-sysinfo --test catalog".into());
    }

    let mut pos = Vec::new();
    files(&root.join("po"), &["po"], &mut pos);
    pos.sort();
    for p in &pos {
        let name = rel(p);
        let src = std::fs::read_to_string(p).unwrap();
        let mut have: BTreeMap<Key, String> = BTreeMap::new();
        for (ctxt, id, s) in parse_po(&src) {
            if have.insert((ctxt.clone(), id.clone()), s).is_some() {
                errors.push(format!("{name}: duplicate {id:?}"));
            }
        }
        if update {
            let mut out = po_header(&src);
            for (key, refs) in &used {
                entry(
                    &mut out,
                    key,
                    refs,
                    have.get(key).map(String::as_str).unwrap_or(""),
                );
            }
            std::fs::write(p, &out).unwrap();
            continue;
        }
        let mut missing = 0;
        for (key, refs) in &used {
            match have.get(key) {
                None => {
                    missing += 1;
                    eprintln!("{name}: untranslated {:?} ({})", key.1, refs[0]);
                }
                Some(s) if placeholders(s) != placeholders(&key.1) => {
                    errors.push(format!("{name}: placeholders differ: {:?} / {s:?}", key.1))
                }
                Some(_) => {}
            }
        }
        if missing > 0 {
            errors.push(format!("{name}: {missing} strings untranslated"));
        }
        for key in have.keys() {
            if !used.iter().any(|(k, _)| k == key) {
                errors.push(format!("{name}: unused entry {:?}", key.1));
            }
        }
    }
    assert!(errors.is_empty(), "\n{}", errors.join("\n"));
}
