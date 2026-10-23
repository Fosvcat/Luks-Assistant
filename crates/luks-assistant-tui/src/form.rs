//! Keyboard editing of a core [`Form`].

use luks_assistant_core::forms::{Form, Value};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub struct FormState {
    pub form: Form,
    pub focus: usize,
    /// Cursor inside a PCR picker.
    pub pcr_cursor: usize,
    pub error: Option<String>,
}

pub enum FormEvent {
    None,
    Submit,
    Cancel,
}

impl FormState {
    pub fn new(form: Form) -> Self {
        let mut f = FormState {
            form,
            focus: 0,
            pcr_cursor: 7,
            error: None,
        };
        if !f.focusable(0) {
            f.move_focus(1);
        }
        f
    }

    fn focusable(&self, i: usize) -> bool {
        self.form.fields.get(i).is_some_and(|x| x.is_input())
            && self.form.visible(i)
            && self.form.enabled(i)
    }

    fn move_focus(&mut self, dir: isize) {
        let n = self.form.fields.len() as isize;
        let mut i = self.focus as isize;
        for _ in 0..n {
            i = (i + dir).rem_euclid(n);
            if self.focusable(i as usize) {
                self.focus = i as usize;
                return;
            }
        }
    }

    pub fn on_paste(&mut self, s: &str) {
        if let Some(f) = self.form.fields.get_mut(self.focus) {
            if let Value::Text(t) | Value::Secret(t) | Value::File(t) | Value::SaveFile(t) =
                &mut f.value
            {
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
        let cur = &mut self.pcr_cursor;
        let Some(field) = self.form.fields.get_mut(self.focus) else {
            return FormEvent::None;
        };
        match &mut field.value {
            Value::Text(s) | Value::Secret(s) | Value::File(s) | Value::SaveFile(s) => match k.code
            {
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
            Value::Choice { options, index } => match k.code {
                KeyCode::Left => *index = (*index + options.len() - 1) % options.len(),
                KeyCode::Right | KeyCode::Char(' ') => *index = (*index + 1) % options.len(),
                _ => {}
            },
            Value::Pcrs(set) => match k.code {
                KeyCode::Left => *cur = (*cur + 23) % 24,
                KeyCode::Right => *cur = (*cur + 1) % 24,
                KeyCode::Char(' ') => set[*cur] = !set[*cur],
                _ => {}
            },
            Value::Label | Value::Separator => {}
        }
        FormEvent::None
    }
}
