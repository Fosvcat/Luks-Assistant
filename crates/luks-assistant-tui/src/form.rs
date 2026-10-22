//! A small modal form: text, secret, toggle, choice and PCR-picker fields.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone)]
pub enum Value {
    Text(String),
    Secret(String),
    Toggle(bool),
    Choice(Vec<String>, usize),
    /// 24 PCR checkboxes and the cursor position.
    Pcrs([bool; 24], usize),
    /// Read-only line of information.
    Label,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub key: &'static str,
    pub label: String,
    pub value: Value,
    pub hint: Option<String>,
}

impl Field {
    pub fn text(key: &'static str, label: &str, init: &str) -> Self {
        Field {
            key,
            label: label.into(),
            value: Value::Text(init.into()),
            hint: None,
        }
    }
    pub fn secret(key: &'static str, label: &str) -> Self {
        Field {
            key,
            label: label.into(),
            value: Value::Secret(String::new()),
            hint: None,
        }
    }
    pub fn toggle(key: &'static str, label: &str, init: bool) -> Self {
        Field {
            key,
            label: label.into(),
            value: Value::Toggle(init),
            hint: None,
        }
    }
    pub fn choice(key: &'static str, label: &str, options: &[&str], init: usize) -> Self {
        Field {
            key,
            label: label.into(),
            value: Value::Choice(options.iter().map(|s| s.to_string()).collect(), init),
            hint: None,
        }
    }
    pub fn pcrs(key: &'static str, label: &str, selected: &[u8]) -> Self {
        let mut set = [false; 24];
        for &p in selected {
            if (p as usize) < 24 {
                set[p as usize] = true;
            }
        }
        Field {
            key,
            label: label.into(),
            value: Value::Pcrs(set, 7),
            hint: None,
        }
    }
    pub fn label(text: &str) -> Self {
        Field {
            key: "",
            label: text.into(),
            value: Value::Label,
            hint: None,
        }
    }
    pub fn hint(mut self, h: &str) -> Self {
        self.hint = Some(h.into());
        self
    }

    fn focusable(&self) -> bool {
        !matches!(self.value, Value::Label)
    }
}

#[derive(Debug, Clone)]
pub struct Form<K> {
    pub title: String,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub kind: K,
    pub error: Option<String>,
}

pub enum FormEvent {
    None,
    Submit,
    Cancel,
}

impl<K> Form<K> {
    pub fn new(title: impl Into<String>, kind: K, fields: Vec<Field>) -> Self {
        let mut f = Form {
            title: title.into(),
            fields,
            focus: 0,
            kind,
            error: None,
        };
        if !f.fields.first().is_some_and(Field::focusable) {
            f.move_focus(1);
        }
        f
    }

    fn move_focus(&mut self, dir: isize) {
        let n = self.fields.len() as isize;
        if n == 0 {
            return;
        }
        let mut i = self.focus as isize;
        for _ in 0..n {
            i = (i + dir).rem_euclid(n);
            if self.fields[i as usize].focusable() {
                self.focus = i as usize;
                return;
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.iter().find(|f| f.key == key).map(|f| &f.value)
    }

    pub fn text(&self, key: &str) -> String {
        match self.get(key) {
            Some(Value::Text(s)) | Some(Value::Secret(s)) => s.clone(),
            _ => String::new(),
        }
    }

    pub fn toggle(&self, key: &str) -> bool {
        matches!(self.get(key), Some(Value::Toggle(true)))
    }

    pub fn choice(&self, key: &str) -> usize {
        match self.get(key) {
            Some(Value::Choice(_, i)) => *i,
            _ => 0,
        }
    }

    pub fn pcrs(&self, key: &str) -> Vec<u8> {
        match self.get(key) {
            Some(Value::Pcrs(set, _)) => (0..24u8).filter(|i| set[*i as usize]).collect(),
            _ => Vec::new(),
        }
    }

    pub fn on_paste(&mut self, s: &str) {
        if let Some(f) = self.fields.get_mut(self.focus) {
            if let Value::Text(t) | Value::Secret(t) = &mut f.value {
                t.push_str(s.trim_end_matches(['\n', '\r']));
            }
        }
    }

    pub fn on_key(&mut self, k: KeyEvent) -> FormEvent {
        self.error = None;
        match k.code {
            KeyCode::Esc => return FormEvent::Cancel,
            KeyCode::Enter => return FormEvent::Submit,
            KeyCode::Tab | KeyCode::Down => {
                self.move_focus(1);
                return FormEvent::None;
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.move_focus(-1);
                return FormEvent::None;
            }
            _ => {}
        }
        let Some(field) = self.fields.get_mut(self.focus) else {
            return FormEvent::None;
        };
        match &mut field.value {
            Value::Text(s) | Value::Secret(s) => match k.code {
                KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => s.clear(),
                KeyCode::Char(c) => s.push(c),
                KeyCode::Backspace => {
                    s.pop();
                }
                _ => {}
            },
            Value::Toggle(b) => {
                if matches!(k.code, KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right) {
                    *b = !*b;
                }
            }
            Value::Choice(opts, i) => match k.code {
                KeyCode::Left => *i = (*i + opts.len() - 1) % opts.len(),
                KeyCode::Right | KeyCode::Char(' ') => *i = (*i + 1) % opts.len(),
                _ => {}
            },
            Value::Pcrs(set, cur) => match k.code {
                KeyCode::Left => *cur = (*cur + 23) % 24,
                KeyCode::Right => *cur = (*cur + 1) % 24,
                KeyCode::Char(' ') => set[*cur] = !set[*cur],
                _ => {}
            },
            Value::Label => {}
        }
        FormEvent::None
    }
}
