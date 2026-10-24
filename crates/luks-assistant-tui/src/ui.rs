//! Rendering.

use crate::app::{App, HeaderButton, Modal, REPO_URL, TABS, Tab};
use crate::form::FormState;
use luks_assistant_core::forms::Value;
use luks_assistant_core::health::Severity;
use luks_assistant_core::notes::Location;
use luks_assistant_core::ops::Danger;
use luks_assistant_core::pcr::{self, TpmStatus};
use luks_assistant_core::slots::{Slot, SlotKind};
use luks_assistant_core::t;
use luks_assistant_core::util::format_time;
use luks_assistant_sysinfo::bootcheck::Status;
use luks_assistant_sysinfo::tpm::encode_hex;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use unicode_width::UnicodeWidthStr;

fn trunc(s: &str, width: usize) -> String {
    if s.width() <= width {
        return s.to_owned();
    }
    let mut out = String::new();
    for c in s.chars() {
        if out.width() + c.to_string().width() + 1 > width {
            break;
        }
        out.push(c);
    }
    out.push('…');
    out
}

fn pad(s: &str, w: usize) -> String {
    let cur = s.width();
    if cur >= w {
        s.to_owned()
    } else {
        format!("{s}{}", " ".repeat(w - cur))
    }
}

fn pcr_list(p: &[u8]) -> String {
    if p.is_empty() {
        t!("none").into()
    } else {
        pcr::format_list(p)
    }
}

fn kind_color(s: &Slot) -> Color {
    match &s.kind {
        SlotKind::Empty => Color::DarkGray,
        SlotKind::Passphrase | SlotKind::Keyfile | SlotKind::Secret | SlotKind::Luks1 => {
            Color::Green
        }
        SlotKind::Recovery => Color::Cyan,
        SlotKind::Tpm2 => match s.tpm2_status {
            Some(TpmStatus::Mismatch { .. }) => Color::Red,
            _ => Color::Magenta,
        },
        SlotKind::Fido2 => Color::Yellow,
        SlotKind::Pkcs11 => Color::Blue,
        SlotKind::OtherToken(_) | SlotKind::Reencrypt => Color::Gray,
    }
}

fn kind_icon(k: &SlotKind) -> &'static str {
    match k {
        SlotKind::Empty => "·",
        SlotKind::Passphrase | SlotKind::Secret | SlotKind::Luks1 => "🔑",
        SlotKind::Keyfile => "📄",
        SlotKind::Recovery => "🛟",
        SlotKind::Tpm2 => "🔒",
        SlotKind::Fido2 => "🗝",
        SlotKind::Pkcs11 => "💳",
        SlotKind::OtherToken(_) => "◆",
        SlotKind::Reencrypt => "↻",
    }
}

fn kv(k: &str, v: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(pad(k, 11), Style::new().dark_gray()),
        Span::raw(v.into()),
    ])
}

fn button(label: &str) -> Span<'static> {
    Span::styled(
        format!("[ {label} ]"),
        Style::new().black().on_cyan().bold(),
    )
}

fn button_off(label: &str) -> Span<'static> {
    Span::styled(format!("[ {label} ]"), Style::new().dark_gray())
}

/// Lays out spans left to right and records where the clickable ones are.
struct Row {
    x: u16,
    y: u16,
    spans: Vec<Span<'static>>,
}

impl Row {
    fn new(area: Rect) -> Self {
        Row {
            x: area.x,
            y: area.y,
            spans: Vec::new(),
        }
    }

    fn push(&mut self, s: impl Into<Span<'static>>) -> Rect {
        let s = s.into();
        let w = s.content.width() as u16;
        let r = Rect::new(self.x, self.y, w, 1);
        self.x += w;
        self.spans.push(s);
        r
    }

    fn line(self) -> Line<'static> {
        Line::from(self.spans)
    }
}

pub fn draw(f: &mut Frame, app: &mut App) {
    app.rects = Default::default();
    let [tabs, body, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(f.area());
    draw_tabs(f, app, tabs);
    match app.tab {
        Tab::Slots => draw_slots(f, app, body),
        Tab::System => draw_system(f, app, body),
        Tab::Check => draw_check(f, app, body),
        Tab::Headers => draw_headers(f, app, body),
        Tab::Log => draw_log(f, app, body),
        Tab::About => draw_about(f, body),
    }
    draw_bottom(f, app, bottom);
    draw_modal(f, app);
    if let Some(msg) = &app.busy {
        let area = centered(f.area(), (msg.width() as u16 + 6).min(f.area().width), 3);
        clear(f, area);
        f.render_widget(
            Paragraph::new(msg.as_str()).block(Block::bordered().border_style(Color::Yellow)),
            area,
        );
    }
}

fn draw_tabs(f: &mut Frame, app: &mut App, area: Rect) {
    let mut x = area.x;
    let mut spans = Vec::new();
    for (t, name) in TABS {
        let label = format!(" {} ", luks_assistant_core::i18n::tr(name));
        let w = label.width() as u16;
        app.rects.tabs.push((Rect::new(x, area.y, w, 1), t));
        x += w + 1;
        let st = if t == app.tab {
            Style::new().black().on_white().bold()
        } else {
            Style::new().gray()
        };
        spans.push(Span::styled(label, st));
        spans.push(" ".into());
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
    // the refresh button sits at the right end, as in the GUI
    let label = format!("[ ⟳ {} ]", t!("Refresh"));
    let w = label.width() as u16;
    if area.width > w {
        let r = Rect::new(area.x + area.width - w, area.y, w, 1);
        app.rects.refresh = Some(r);
        f.render_widget(Paragraph::new(label).style(Style::new().cyan()), r);
    }
}

fn draw_bottom(f: &mut Frame, app: &App, area: Rect) {
    let hints = match app.tab {
        Tab::Slots => {
            t!(
                "←↑↓→ select  Enter actions  a add  d delete  n note  e edit  v verify  u unlock/lock  D disk  ? help  q quit"
            )
        }
        Tab::System => t!("p show all PCR measurements  Tab/1-6 switch  F5 refresh  q quit"),
        Tab::Check => t!("↑↓ select  Tab/1-6 switch  F5 refresh  q quit"),
        Tab::Headers => t!(
            "↑↓ select  Space check  Enter menu  a all  i invert  x clear  r restore  p clean up  b back up checked  c backup location"
        ),
        Tab::Log => t!("↑↓ scroll  x export  Tab/1-6 switch  q quit"),
        Tab::About => t!("Tab/1-6 pages  F5 refresh  q quit"),
    };
    let line = Line::from(vec![
        Span::styled(format!(" {} ", app.status), Style::new().yellow()),
        Span::styled(hints, Style::new().dark_gray()),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_device_bar(f: &mut Frame, app: &mut App, area: Rect) {
    let dev = app.device().map(|d| {
        let size = d.size.clone().unwrap_or_default();
        format!("{} {size}", d.display_name())
    });
    let disk = format!(
        " ▼ {} ",
        trunc(&dev.unwrap_or_else(|| t!("none").into()), 60)
    );
    let mut row = Row::new(area);
    row.push(t!("Disk "));
    app.rects.disk = Some(row.push(Span::styled(disk, Style::new().black().on_white())));
    if let Some(ov) = &app.ov {
        let unlocked = ov.device.mapping.is_some();
        row.push("   ");
        row.push(if unlocked {
            t!("Status: unlocked").green()
        } else {
            t!("Status: locked").yellow()
        });
        row.push("  ");
        // the running system's own volume cannot be locked
        let lock = if unlocked {
            format!("🔒 {}", t!("Lock"))
        } else {
            format!("🔓 {}", t!("Unlock"))
        };
        if unlocked && ov.device.holds_root() {
            row.push(button_off(&lock));
        } else {
            app.rects.lock = Some(row.push(button(&lock)));
        }
        row.push(" ");
        app.rects.verify = Some(row.push(button(t!("Verify"))));
    }
    f.render_widget(Paragraph::new(row.line()), area);
}

fn draw_slots(f: &mut Frame, app: &mut App, area: Rect) {
    let [bar, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(4)]).areas(area);
    draw_device_bar(f, app, bar);
    let Some(ov) = &app.ov else {
        let msg = app.load_error.clone().unwrap_or_default();
        f.render_widget(
            Paragraph::new(msg).block(Block::bordered().title(t!(" Slots "))),
            rest,
        );
        return;
    };
    let cols: u16 = if rest.width >= 8 * 12 + 2 { 8 } else { 4 };
    let rows = 32 / cols;
    let [grid_area, detail_area] =
        Layout::vertical([Constraint::Length(rows * 3 + 2), Constraint::Min(4)]).areas(rest);
    let title = format!(
        " LUKS{} · {} · {}/32 ",
        ov.header.version,
        ov.header.uuid,
        ov.used().count()
    );
    let block = Block::bordered().title(title);
    let inner = block.inner(grid_area);
    f.render_widget(block, grid_area);
    let cw = inner.width / cols;
    for s in &ov.slots {
        let (r, c) = ((s.id as u16) / cols, (s.id as u16) % cols);
        let rect = Rect::new(inner.x + c * cw, inner.y + r * 3, cw.saturating_sub(1), 2);
        app.rects.slots.push((rect, s.id));
        let color = kind_color(s);
        let style = if s.id == app.selected {
            Style::new()
                .fg(Color::Black)
                .bg(color)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(color)
        };
        let w = rect.width as usize;
        let l1 = if s.is_empty() {
            format!("{:02} ·", s.id)
        } else {
            format!("{:02} {} {}", s.id, kind_icon(&s.kind), s.kind.label())
        };
        let l2 = match (&s.note, &s.tpm2_status) {
            (_, Some(TpmStatus::Mismatch { .. })) => t!("PCRs changed").to_owned(),
            (Some(n), _) if !n.note.text.is_empty() => n.note.text.clone(),
            (_, Some(TpmStatus::Match)) => {
                format!("✓ PCR {}", pcr_list(&s.tpm2.as_ref().unwrap().pcrs))
            }
            _ if s.is_empty() => String::new(),
            _ => s.summary(),
        };
        f.render_widget(
            Paragraph::new(Text::from(vec![
                Line::from(trunc(&l1, w)),
                Line::from(trunc(&l2, w)),
            ]))
            .style(style),
            rect,
        );
    }
    draw_slot_detail(f, app, detail_area);
}

fn draw_slot_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(ov) = &app.ov else { return };
    let Some(s) = app.selected_slot() else { return };
    let mut lines: Vec<Line> = Vec::new();
    if s.is_empty() {
        lines.push(Line::from(t!("Empty").dark_gray()));
    } else {
        lines.push(kv(t!("Type"), s.kind.label()));
        if let Some(ks) = &s.keyslot {
            lines.push(kv("KDF", ks.kdf.summary()));
            lines.push(kv(t!("Priority"), ks.priority.label()));
            if let Some(e) = &ks.area_encryption {
                lines.push(kv(
                    t!("Slot encryption"),
                    t!("{}  {} bits", e, ks.key_size * 8),
                ));
            }
        }
        if !s.tokens.is_empty() {
            lines.push(kv(t!("Token"), format!("{:?}", s.tokens)));
        }
        // Both stores, so it is clear where a note lives.
        for (label, loc) in [
            (t!("Header note"), Location::Header),
            (t!("Local note"), Location::Local),
        ] {
            let text = ov
                .notes
                .at(&ov.header, s.id, loc)
                .map(|n| n.text.as_str())
                .filter(|t| !t.is_empty())
                .unwrap_or("—");
            lines.push(kv(label, text));
        }
        if let Some(t) = &s.tpm2 {
            lines.push(kv("TPM2", t.describe()));
            if let Some(st) = &s.tpm2_status {
                let color = match st {
                    TpmStatus::Match => Color::Green,
                    TpmStatus::Mismatch { .. } => Color::Red,
                    TpmStatus::Unknown(_) => Color::Yellow,
                };
                lines.push(Line::from(vec![
                    Span::styled(pad(t!("Status"), 11), Style::new().dark_gray()),
                    Span::styled(st.label(), Style::new().fg(color).bold()),
                    if matches!(st, TpmStatus::Mismatch { .. }) {
                        t!("  press e to re-enroll").yellow()
                    } else {
                        "".into()
                    },
                ]));
            }
            if let Some(h) = &t.policy_hash {
                lines.push(kv(t!("Policy hash"), h.clone()));
            }
        }
        if let Some(fd) = &s.fido2 {
            lines.push(kv(
                "FIDO2",
                format!(
                    "{}  RP: {}",
                    fd.describe(),
                    fd.rp.clone().unwrap_or_default()
                ),
            ));
        }
        if let Some(u) = &s.pkcs11_uri {
            lines.push(kv("PKCS#11", u.clone()));
        }
    }
    lines.push(Line::from(""));
    let seg = ov.header.segments.first();
    lines.push(kv(
        t!("Volume"),
        t!(
            "{} · sector {} · JSON {}/{} bytes",
            seg.and_then(|s| s.encryption.clone()).unwrap_or_default(),
            seg.and_then(|s| s.sector_size).unwrap_or(0),
            ov.header.json_used,
            ov.header.config.json_size
        ),
    ));
    if let Some(r) = ov.read_only_reason() {
        lines.push(Line::from(r.yellow()));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(t!(" Slot {} ", s.id))),
        area,
    );
}

fn draw_system(f: &mut Frame, app: &mut App, area: Rect) {
    let [left, mid, right] = Layout::horizontal([
        Constraint::Ratio(3, 10),
        Constraint::Ratio(4, 10),
        Constraint::Ratio(3, 10),
    ])
    .areas(area);
    let s = &app.sys;
    let ver = |v: Option<luks_assistant_sysinfo::tools::Version>| {
        v.map(|v| v.to_string())
            .unwrap_or_else(|| t!("not installed").into())
    };
    let mut lines = vec![
        kv(t!("Distribution"), s.os.pretty_name.clone()),
        kv(t!("Family"), s.os.family.label()),
        kv(t!("Kernel"), s.os.kernel.clone()),
        kv(t!("Host name"), s.os.hostname.clone()),
        kv("cryptsetup", ver(s.tools.cryptsetup)),
        kv("systemd", ver(s.tools.systemd)),
        kv(
            t!("Firmware"),
            if s.firmware.uefi { "UEFI" } else { "BIOS" },
        ),
        kv(t!("Secure Boot"), s.firmware.secure_boot_label()),
        Line::from(""),
        Line::from("TPM".bold()),
    ];
    if s.tpm.present {
        lines.push(kv(
            t!("Version"),
            format!("TPM {}.0", s.tpm.version_major.unwrap_or(0)),
        ));
        lines.push(kv(
            t!("Device"),
            s.tpm
                .dev_node
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        ));
        lines.push(kv(t!("Driver"), s.tpm.driver.clone().unwrap_or_default()));
        lines.push(kv(
            t!("Description"),
            s.tpm.description.clone().unwrap_or_default(),
        ));
        lines.push(kv("PCR bank", s.tpm.banks.join(", ")));
    } else {
        lines.push(Line::from(t!("  Not detected").dark_gray()));
    }
    if app.ctx.tpm2_device != "auto" {
        lines.push(kv(t!("Override"), app.ctx.tpm2_device.clone()));
    }
    for (title, list) in [
        (t!("FIDO2 security keys"), &app.fido2_devices),
        (t!("PKCS#11 smart cards"), &app.pkcs11_tokens),
    ] {
        lines.push(Line::from(""));
        lines.push(Line::from(title.bold()));
        match list {
            Some(d) if !d.is_empty() => {
                lines.extend(d.iter().map(|x| Line::from(format!("  {x}"))))
            }
            _ => lines.push(Line::from(t!("  Not detected").dark_gray())),
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(t!("Features").bold()));
    for (name, ok) in s.caps.describe() {
        lines.push(Line::from(vec![
            if ok { "  ✓ ".green() } else { "  ✗ ".red() },
            name.into(),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(t!(" System "))),
        left,
    );

    // block devices
    let (luks, total) = app.tree.volume_counts();
    let mut dl: Vec<Line> = vec![Line::from(
        format!(
            "{} {} {} {} {} {}",
            pad(t!("Name"), 16),
            pad(t!("Size"), 6),
            pad(t!("Encryption"), 12),
            pad(t!("Type"), 4),
            pad("TRIM", 4),
            t!("Mount point")
        )
        .dark_gray(),
    )];
    for (depth, n) in app.tree.flatten() {
        let name = format!(
            "{}{}",
            "  ".repeat(depth),
            n.path.rsplit('/').next().unwrap_or(&n.path)
        );
        // TRIM: "—" for spinning disks, ✓/✗ otherwise
        let media = match n.rota {
            Some(true) => "HDD",
            Some(false) => "SSD",
            None => "",
        };
        let trim = match (n.rota, n.trim()) {
            (Some(true), _) => "—",
            (_, Some(true)) => "✓",
            (_, Some(false)) => "✗",
            (_, None) => "",
        };
        let style = if n.is_luks() {
            Style::new().green()
        } else if n.kind == "crypt" {
            Style::new().cyan()
        } else {
            Style::new()
        };
        dl.push(Line::from(vec![
            Span::styled(format!("{} ", pad(&trunc(&name, 16), 16)), style),
            Span::raw(format!("{} ", pad(&n.size.clone().unwrap_or_default(), 6))),
            Span::styled(format!("{} ", pad(&trunc(&n.encryption(), 12), 12)), style),
            Span::raw(format!("{} ", pad(media, 4))),
            Span::raw(format!("{} ", pad(trim, 4))),
            Span::raw(n.mountpoints.join(" ")),
        ]));
    }
    f.render_widget(
        Paragraph::new(dl).block(Block::bordered().title(t!(" Disks · LUKS {}/{} ", luks, total))),
        mid,
    );

    let shown = app.visible_pcrs();
    let toggle = format!(
        "{} {}",
        if app.show_all_pcrs { "[x]" } else { "[ ]" },
        t!("Show all PCR measurements")
    );
    app.rects.all_pcrs = Some(Rect::new(
        right.x + 1,
        right.y + 1,
        toggle.width() as u16,
        1,
    ));
    let mut pl: Vec<Line> = vec![Line::from(toggle.cyan()), Line::from("")];
    let vals = app.pcr_table.as_ref();
    if let Some(Err(e)) = vals {
        pl.push(Line::from(e.clone().yellow()));
    }
    let bound: Vec<u8> = app
        .ov
        .as_ref()
        .map(|o| {
            o.slots
                .iter()
                .filter_map(|s| s.tpm2.as_ref())
                .flat_map(|t| t.pcrs.clone())
                .collect()
        })
        .unwrap_or_default();
    for info in pcr::PCRS.iter().filter(|p| shown.contains(&p.index)) {
        let v = vals
            .and_then(|r| r.as_ref().ok())
            .and_then(|m| m.get(&info.index))
            .map(|b| encode_hex(b))
            .unwrap_or_default();
        let short = if v.is_empty() {
            "—".to_owned()
        } else {
            format!("{}…", &v[..12.min(v.len())])
        };
        let used = bound.contains(&info.index);
        let style = if used {
            Style::new().magenta().bold()
        } else {
            Style::new()
        };
        pl.push(Line::from(vec![
            Span::styled(
                format!("{:>2}{} ", info.index, if used { "*" } else { " " }),
                style,
            ),
            Span::styled(format!("{short:<14}"), Style::new().dark_gray()),
            Span::styled(info.name(), style),
        ]));
    }
    pl.push(Line::from(t!("* used by a TPM2 slot").dark_gray()));
    f.render_widget(
        Paragraph::new(pl).block(Block::bordered().title(" PCR (sha256) ")),
        right,
    );
}

fn sev_style(s: Severity) -> Style {
    match s {
        Severity::Critical => Style::new().red().bold(),
        Severity::Warning => Style::new().yellow(),
        Severity::Info => Style::new().cyan(),
    }
}

/// Problems and warnings on the left, hardware unlock availability on the right.
fn draw_check(f: &mut Frame, app: &mut App, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]).areas(area);
    draw_issues(f, app, left);
    draw_boot(f, app, right);
}

fn draw_issues(f: &mut Frame, app: &mut App, area: Rect) {
    let [list, detail] = Layout::vertical([Constraint::Min(5), Constraint::Length(6)]).areas(area);
    let block = Block::bordered().title(t!(" Problems and warnings "));
    let inner = block.inner(list);
    f.render_widget(block, list);
    if app.issues.is_empty() {
        f.render_widget(Paragraph::new(t!("✓ No problems").green()), inner);
        return;
    }
    let start = app
        .issue_sel
        .saturating_sub(inner.height.saturating_sub(1) as usize);
    for (row, (i, issue)) in app
        .issues
        .iter()
        .enumerate()
        .skip(start)
        .take(inner.height as usize)
        .enumerate()
    {
        let rect = Rect::new(inner.x, inner.y + row as u16, inner.width, 1);
        app.rects.issues.push((rect, i));
        let mut line = Line::from(vec![
            Span::styled(
                format!("[{}] ", issue.severity.label()),
                sev_style(issue.severity),
            ),
            Span::raw(issue.title.clone()),
        ]);
        if i == app.issue_sel {
            line = line.patch_style(Style::new().add_modifier(Modifier::REVERSED));
        }
        f.render_widget(Paragraph::new(line), rect);
    }
    if let Some(issue) = app.issues.get(app.issue_sel) {
        f.render_widget(
            Paragraph::new(issue.detail.clone())
                .wrap(Wrap { trim: false })
                .block(Block::bordered()),
            detail,
        );
    }
}

fn draw_boot(f: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    for item in app.boot.iter().flatten() {
        let st = match item.status {
            Status::Ok => Style::new().green(),
            Status::Info => Style::new().cyan(),
            Status::Warn => Style::new().yellow(),
            Status::Fail => Style::new().red().bold(),
            Status::Unknown => Style::new().gray(),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", item.status.symbol()), st),
            Span::styled(item.title.clone(), Style::new().bold()),
        ]));
        for l in item.detail.lines() {
            lines.push(Line::from(format!("  {l}").dark_gray()));
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(t!(" Hardware unlock availability "))),
        area,
    );
}

fn draw_headers(f: &mut Frame, app: &mut App, area: Rect) {
    let [head, list, buttons] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);
    let line = Line::from(vec![
        Span::raw(t!(" Backup location: ")),
        Span::styled(
            app.ctx.paths.backup_root.display().to_string(),
            Style::new().bold(),
        ),
        Span::styled(t!("  (c to change)"), Style::new().dark_gray()),
    ]);
    f.render_widget(Paragraph::new(line).block(Block::bordered()), head);

    let checked = app.checked_volumes().len();
    let mut row = Row::new(buttons);
    for (b, label, on) in [
        (HeaderButton::All, t!("Select all").to_owned(), true),
        (HeaderButton::Invert, t!("Invert").into(), true),
        (HeaderButton::Clear, t!("Clear").into(), true),
        (HeaderButton::Restore, t!("Restore…").into(), checked == 1),
        (HeaderButton::Prune, t!("Clean up").into(), checked > 0),
        (
            HeaderButton::Backup,
            t!("Back up selected ({})", checked),
            checked > 0,
        ),
    ] {
        if on {
            let r = row.push(button(&label));
            app.rects.header_buttons.push((r, b));
        } else {
            row.push(button_off(&label));
        }
        row.push(" ");
    }
    f.render_widget(Paragraph::new(row.line()), buttons);

    let block = Block::bordered().title(t!(" LUKS volumes "));
    let inner = block.inner(list);
    f.render_widget(block, list);
    let rows_per = 2u16;
    let visible = (inner.height / rows_per).max(1) as usize;
    let start = app.backup_cursor.saturating_sub(visible - 1);
    for (row, (i, d)) in app
        .devices
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .enumerate()
    {
        let rect = Rect::new(
            inner.x,
            inner.y + row as u16 * rows_per,
            inner.width,
            rows_per,
        );
        app.rects.backups.push((rect, i));
        let check = if app.backup_sel.get(i).copied().unwrap_or(false) {
            "[x]"
        } else {
            "[ ]"
        };
        let uuid = d.uuid.clone().unwrap_or_default();
        let files = if uuid.is_empty() {
            Vec::new()
        } else {
            luks_assistant_core::backup::list(&app.ctx.paths, &uuid)
        };
        let last = match files.first() {
            Some(b) => t!(
                "Last backup {} · {} · {} in total",
                format_time(b.modified),
                b.path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                files.len()
            ),
            None => t!("Never backed up").into(),
        };
        let mut l1 = Line::from(vec![
            Span::styled(format!("{check} "), Style::new().cyan().bold()),
            Span::styled(d.display_name(), Style::new().bold()),
            Span::raw(format!("  {}  {uuid}", d.size.clone().unwrap_or_default())),
        ]);
        let mut l2 = Line::from(Span::styled(
            format!("    {last}"),
            Style::new().dark_gray(),
        ));
        if i == app.backup_cursor {
            l1 = l1.patch_style(Style::new().add_modifier(Modifier::REVERSED));
            l2 = l2.patch_style(Style::new().add_modifier(Modifier::REVERSED));
        }
        f.render_widget(Paragraph::new(vec![l1, l2]), rect);
    }
    if app.devices.is_empty() {
        f.render_widget(Paragraph::new(t!("No LUKS volumes").dark_gray()), inner);
    }
}

fn draw_log(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = vec![
        Line::from(
            app.ctx
                .paths
                .history_log()
                .display()
                .to_string()
                .dark_gray(),
        ),
        Line::from(""),
    ];
    if app.log.is_empty() {
        lines.push(Line::from(t!("No logs yet").dark_gray()));
    }
    lines.extend(app.log.iter().map(|l| Line::from(l.clone())));
    f.render_widget(
        Paragraph::new(lines)
            .scroll((app.log_scroll, 0))
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(t!(" Logs"))),
        area,
    );
}

fn draw_about(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("Luks Assistant".bold().cyan()),
        Line::from(format!(
            "{} {}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::ARCH
        )),
        Line::from(REPO_URL.underlined()),
    ];
    let h = lines.len() as u16;
    let r = Rect::new(
        area.x,
        area.y + area.height.saturating_sub(h) / 2,
        area.width,
        h.min(area.height),
    );
    f.render_widget(
        Paragraph::new(lines).alignment(ratatui::layout::Alignment::Center),
        r,
    );
}

/// Clear a popup area plus one column on each side, so that no
/// double-width character straddles the popup border.
fn clear(f: &mut Frame, r: Rect) {
    let full = f.area();
    let x = r.x.saturating_sub(1);
    let right = (r.x + r.width + 1).min(full.x + full.width);
    f.render_widget(Clear, Rect::new(x, r.y, right - x, r.height));
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

fn draw_modal(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let Some(modal) = &app.modal else { return };
    match modal {
        Modal::Menu { title, items, sel } => {
            let w = items
                .iter()
                .map(|(s, _)| s.width())
                .max()
                .unwrap_or(10)
                .max(title.width()) as u16
                + 8;
            let r = centered(area, w, items.len() as u16 + 2);
            clear(f, r);
            let block = Block::bordered()
                .title(format!(" {title} "))
                .border_style(Color::Cyan);
            let inner = block.inner(r);
            f.render_widget(block, r);
            for (i, (label, _)) in items.iter().enumerate() {
                let rr = Rect::new(inner.x, inner.y + i as u16, inner.width, 1);
                app.rects.menu.push((rr, i));
                let st = if i == *sel {
                    Style::new().black().on_cyan()
                } else {
                    Style::new()
                };
                f.render_widget(Paragraph::new(format!(" {label}")).style(st), rr);
            }
        }
        Modal::Picker { rows, sel } => {
            let w = rows
                .iter()
                .map(|r| r.text.width() + r.depth * 2)
                .max()
                .unwrap_or(20) as u16
                + 6;
            let h = (rows.len() as u16 + 2).min(area.height.saturating_sub(2));
            let r = centered(area, w.min(area.width), h);
            clear(f, r);
            let block = Block::bordered()
                .title(t!(" Disks "))
                .border_style(Color::Cyan);
            let inner = block.inner(r);
            f.render_widget(block, r);
            let visible = inner.height as usize;
            let start = sel.saturating_sub(visible.saturating_sub(1));
            for (row, (i, pr)) in rows
                .iter()
                .enumerate()
                .skip(start)
                .take(visible)
                .enumerate()
            {
                let rr = Rect::new(inner.x, inner.y + row as u16, inner.width, 1);
                app.rects.menu.push((rr, i));
                let st = match (pr.device.is_some(), i == *sel) {
                    (true, true) => Style::new().black().on_cyan(),
                    (true, false) => Style::new().green(),
                    (false, _) => Style::new().dark_gray(),
                };
                f.render_widget(
                    Paragraph::new(format!(" {}{}", "  ".repeat(pr.depth), pr.text)).style(st),
                    rr,
                );
            }
        }
        Modal::Form(state, _) => draw_form(f, app, state, area),
        Modal::Confirm {
            plans,
            typed,
            scroll,
        } => {
            let r = centered(
                area,
                area.width.saturating_sub(6).min(120),
                area.height.saturating_sub(4).min(32),
            );
            clear(f, r);
            let danger = plans
                .iter()
                .map(|p| p.danger)
                .max()
                .unwrap_or(Danger::Normal);
            let color = match danger {
                Danger::Normal => Color::Cyan,
                Danger::High => Color::Yellow,
                Danger::Critical => Color::Red,
            };
            let mut lines: Vec<Line> = Vec::new();
            for plan in plans {
                lines.push(Line::from(
                    format!("{} — {}", plan.title, plan.device.display()).bold(),
                ));
                for w in &plan.warnings {
                    lines.push(Line::from(format!("  ! {w}").yellow()));
                }
                for (i, s) in plan.steps.iter().enumerate() {
                    lines.push(Line::from(format!("{:>2}. {}", i + 1, s.desc())));
                    if let Some(c) = s.command() {
                        lines.push(Line::from(format!("      $ {c}").dark_gray()));
                    }
                }
                lines.push(Line::from(""));
            }
            match plans.iter().find_map(|p| p.confirm_word.as_ref()) {
                Some(w) => {
                    lines.push(Line::from(
                        t!("Type {} and press Enter to confirm", w).red().bold(),
                    ));
                    lines.push(Line::from(vec![
                        "> ".into(),
                        typed.clone().bold(),
                        "▏".into(),
                    ]));
                }
                None => lines.push(Line::from(t!("Enter run · Esc cancel").cyan())),
            }
            f.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .scroll((*scroll, 0))
                    .block(Block::bordered().title(t!(" Confirm ")).border_style(color)),
                r,
            );
        }
        Modal::Report {
            title,
            lines,
            ok,
            scroll,
        } => {
            let r = centered(
                area,
                area.width.saturating_sub(6).min(120),
                area.height.saturating_sub(4).min(32),
            );
            clear(f, r);
            let text: Vec<Line> = lines.iter().map(|l| Line::from(l.clone())).collect();
            f.render_widget(
                Paragraph::new(text)
                    .wrap(Wrap { trim: false })
                    .scroll((*scroll, 0))
                    .block(
                        Block::bordered()
                            .title(format!(" {title} "))
                            .border_style(if *ok { Color::Green } else { Color::Red }),
                    ),
                r,
            );
        }
        Modal::Recovery { key, slot } => {
            let r = centered(area, 90, 9);
            clear(f, r);
            let lines = vec![
                Line::from(
                    t!(
                        "Recovery key · slot {}",
                        slot.map(|s| s.to_string()).unwrap_or("?".into())
                    )
                    .green()
                    .bold(),
                ),
                Line::from(""),
                Line::from(key.clone().bold().yellow()),
                Line::from(""),
                Line::from(t!("Shown only once; store it offline")),
                Line::from(""),
                Line::from(t!("press y to close").cyan()),
            ];
            f.render_widget(
                Paragraph::new(lines).block(Block::bordered().border_style(Color::Yellow)),
                r,
            );
        }
        Modal::Message { title, text } => {
            let w = text.lines().map(|l| l.width()).max().unwrap_or(10) as u16 + 4;
            let r = centered(
                area,
                w.clamp(30, area.width.saturating_sub(4)),
                text.lines().count() as u16 + 2,
            );
            clear(f, r);
            f.render_widget(
                Paragraph::new(text.clone())
                    .wrap(Wrap { trim: false })
                    .block(Block::bordered().title(format!(" {title} "))),
                r,
            );
        }
        Modal::Help => {
            let text = t!("\
Slots
  ←↑↓→ hjkl / click   select; double click, right click or Enter opens the menu
  a add   e edit/re-enroll   d delete   n note
  v verify   u unlock/lock   D choose disk
System
  p show all PCR measurements
Headers
  Space check   a all   i invert   x clear
  r restore   p clean up (keep the newest backup)   b back up checked
  Enter/right click back up, restore or clean up one volume   c backup location
Logs
  x export as txt
Global
  Tab / 1-6 switch page   F5 refresh   q quit");
            let w = text.lines().map(|l| l.width()).max().unwrap_or(40) as u16 + 3;
            let r = centered(area, w, text.lines().count() as u16 + 2);
            clear(f, r);
            f.render_widget(
                Paragraph::new(text).block(Block::bordered().title(t!(" Help "))),
                r,
            );
        }
    }
}

/// Rows `lines` take when wrapped to `width` (a close estimate).
fn wrapped_rows(lines: &[Line], width: u16) -> u16 {
    lines
        .iter()
        .map(|l| (l.width() as u16).div_ceil(width).max(1))
        .sum()
}

fn draw_form(f: &mut Frame, app: &App, state: &FormState, area: Rect) {
    let form = &state.form;
    let has_pcrs = form
        .fields
        .iter()
        .any(|x| matches!(x.value, Value::Pcrs(..)));
    let w = area.width.saturating_sub(4).min(100);
    // inside the border and the margin
    let text_w = w.saturating_sub(4).max(1);
    let mut lines: Vec<Line> = Vec::new();
    let label_w = 16;
    for (i, field) in form.fields.iter().enumerate() {
        if !form.visible(i) {
            continue;
        }
        let focused = i == state.focus;
        let disabled = !form.enabled(i);
        let lab = Span::styled(
            format!(
                "{}{}",
                if focused { "▶ " } else { "  " },
                pad(&field.label, label_w)
            ),
            if focused {
                Style::new().cyan().bold()
            } else if disabled {
                Style::new().dark_gray()
            } else {
                Style::new()
            },
        );
        let cursor: Span = if focused { "▏".into() } else { "".into() };
        let val: Vec<Span> = match &field.value {
            Value::Text(s) | Value::File(s) | Value::SaveFile(s) => {
                vec![Span::raw(s.clone()), cursor]
            }
            Value::Secret(s) => vec![Span::raw("•".repeat(s.chars().count())), cursor],
            Value::Toggle(b) => vec![Span::raw(if *b { "[x]" } else { "[ ]" })],
            Value::Choice { options, index } => vec![Span::raw(format!("◀ {} ▶", options[*index]))],
            Value::Pcrs(set) => state
                .pcrs
                .iter()
                .map(|&p| {
                    let mut st = if set[p] {
                        Style::new().black().on_magenta()
                    } else {
                        Style::new().dark_gray()
                    };
                    if focused && p == state.pcr_cursor {
                        st = st
                            .add_modifier(Modifier::UNDERLINED | Modifier::BOLD)
                            .fg(Color::White);
                    }
                    Span::styled(format!("{p:>2}"), st)
                })
                .flat_map(|s| [s, Span::raw(" ")])
                .collect(),
            Value::Label => {
                lines.push(Line::from(format!("  {}", field.label).dark_gray()));
                continue;
            }
            Value::Separator => {
                lines.push(Line::from(""));
                continue;
            }
        };
        let mut spans = vec![lab];
        spans.extend(val);
        lines.push(Line::from(spans));
        if focused {
            if let Some(h) = &field.hint {
                lines.push(Line::from(
                    format!("  {}{h}", " ".repeat(label_w)).dark_gray(),
                ));
            }
        }
    }
    let block = Block::bordered()
        .title(format!(" {} ", form.title))
        .title_bottom(t!(" Tab/↑↓ move  Space/←→ choose  Enter OK  Esc cancel "))
        .border_style(Color::Cyan);
    if !has_pcrs {
        if let Some(e) = &state.error {
            lines.push(Line::from(""));
            lines.push(Line::from(format!("✗ {e}").red().bold()));
        }
        let h = wrapped_rows(&lines, text_w) + 3;
        let r = centered(area, w, h.min(area.height));
        clear(f, r);
        let inner = block.inner(r).inner(Margin::new(1, 0));
        f.render_widget(block, r);
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        return;
    }

    // Like the GUI: notes and warnings go to a box of fixed height at the
    // bottom (scrolled with PgUp/PgDn), so the popup never changes size.
    let msg_w = text_w.saturating_sub(2).max(1);
    let mut msgs: Vec<Line> = Vec::new();
    if let Some(e) = &state.error {
        msgs.push(Line::from(format!("✗ {e}").red().bold()));
    }
    let sel = form.pcrs("pcrs");
    for w in pcr::selection_warnings(&sel, app.sys.firmware.secure_boot) {
        msgs.push(Line::from(format!("! {w}").yellow()));
    }
    let c = state.pcr_cursor;
    let info = &pcr::PCRS[c];
    let val = app
        .pcr_table
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .and_then(|m| m.get(&(c as u8)))
        .map(|b| encode_hex(b))
        .unwrap_or_else(|| "—".into());
    msgs.push(Line::from(
        t!("PCR {} {}: {}", c, info.name(), info.measures()).bold(),
    ));
    msgs.push(Line::from(t!("  Changes: {}", info.changes()).dark_gray()));
    msgs.push(Line::from(
        t!(
            "  Current: {}",
            trunc(&val, (msg_w as usize).saturating_sub(10))
        )
        .dark_gray(),
    ));
    msgs.push(Line::from(t!("Selected PCRs {}", pcr_list(&sel))));
    let box_h = 9;
    // Room for every field whatever is shown, plus a hint and a wrapped
    // PCR row: the height only depends on the form.
    let pcr_rows = (18 + state.pcrs.len() as u16 * 3).div_ceil(text_w);
    let fields_h = form.fields.len() as u16 + 1 + pcr_rows;
    let h = fields_h + box_h + 2;
    let r = centered(area, w, h.min(area.height));
    clear(f, r);
    let inner = block.inner(r).inner(Margin::new(1, 0));
    f.render_widget(block, r);
    let [top, bottom] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(box_h)]).areas(inner);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), top);
    let max_scroll = wrapped_rows(&msgs, msg_w).saturating_sub(box_h - 2);
    f.render_widget(
        Paragraph::new(msgs)
            .wrap(Wrap { trim: false })
            .scroll((state.msg_scroll.min(max_scroll), 0))
            .block(
                Block::bordered()
                    .title_bottom(" PgUp/PgDn ")
                    .border_style(Color::DarkGray),
            ),
        bottom,
    );
}
