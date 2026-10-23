//! Keyboard editing of a core [`Form`].

use luks_assistant_core::forms::{Form, Value};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub struct FormState {
    pub form: Form,
    pub focus: usize,
    /// Cursor inside a PCR picker (a PCR number).
    pub pcr_cursor: usize,
    /// The PCRs the picker shows, in order.
    pub pcrs: Vec<usize>,
    /// Scroll of the message box under a PCR picker.
    pub msg_scroll: u16,
    pub error: Option<String>,
}

pub enum FormEvent {
    None,
    Submit,
    Cancel,
}

impl FormState {
    /// `pcrs`: the PCRs a picker shows (empty = all 24). Hidden PCRs are
    /// unchecked, so what is submitted is what was shown.
    pub fn new(mut form: Form, pcrs: Vec<usize>) -> Self {
        let pcrs = if pcrs.is_empty() {
            (0..24).collect()
        } else {
            pcrs
        };
        for field in &mut form.fields {
            if let Value::Pcrs(set) = &mut field.value {
                for (i, on) in set.iter_mut().enumerate() {
                    *on &= pcrs.contains(&i);
                }
            }
        }
        let mut f = FormState {
            form,
            focus: 0,
            pcr_cursor: if pcrs.contains(&7) { 7 } else { pcrs[0] },
            pcrs,
            msg_scroll: 0,
            error: None,
        };
        // like the GUI: start in the first text field, so typing goes there
        let text = (0..f.form.fields.len()).find(|&i| {
            f.focusable(i)
                && matches!(
                    f.form.fields[i].value,
                    Value::Text(_) | Value::Secret(_) | Value::File(_) | Value::SaveFile(_)
                )
        });
        match text {
            Some(i) => f.focus = i,
            None if !f.focusable(0) => f.move_focus(1),
            None => {}
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
            KeyCode::PageUp => {
                self.msg_scroll = self.msg_scroll.saturating_sub(3);
                return FormEvent::None;
            }
            KeyCode::PageDown => {
                self.msg_scroll = self.msg_scroll.saturating_add(3).min(50);
                return FormEvent::None;
            }
            _ => {}
        }
        let cur = &mut self.pcr_cursor;
        let shown = &self.pcrs;
        let pos = shown.iter().position(|p| p == cur).unwrap_or(0);
        let n = shown.len();
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
                KeyCode::Left => *cur = shown[(pos + n - 1) % n],
                KeyCode::Right => *cur = shown[(pos + 1) % n],
                KeyCode::Char(' ') => set[*cur] = !set[*cur],
                _ => {}
            },
            Value::Label | Value::Separator => {}
        }
        FormEvent::None
    }
}
