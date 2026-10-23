//! Rendering.

use crate::app::{App, Modal, TABS, Tab};
use crate::form::FormState;
use luks_assistant_core::forms::Value;
use luks_assistant_core::health::Severity;
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
        t!("无").into()
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

pub fn draw(f: &mut Frame, app: &mut App) {
    app.rects = Default::default();
    let [top, tabs, body, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(f.area());
    draw_top(f, app, top);
    draw_tabs(f, app, tabs);
    match app.tab {
        Tab::Slots => draw_slots(f, app, body),
        Tab::System => draw_system(f, app, body),
        Tab::Health => draw_health(f, app, body),
        Tab::Boot => draw_boot(f, app, body),
        Tab::Backup => draw_backup(f, app, body),
        Tab::Log => draw_log(f, app, body),
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

fn draw_top(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.sys;
    let tpm = if app.ctx.tpm2_device != "auto" {
        format!("TPM2 → {}", app.ctx.tpm2_device)
    } else if s.tpm.is_tpm2() {
        format!("TPM2 ✓ {}", s.tpm.banks.join("/"))
    } else if s.tpm.present {
        "TPM 1.2".into()
    } else {
        t!("无 TPM").into()
    };
    let ver = |v: Option<luks_assistant_sysinfo::tools::Version>| {
        v.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
    };
    let line = Line::from(vec![
        " Luks Assistant ".black().on_cyan().bold(),
        t!(
            " {} · 内核 {} · systemd {} · cryptsetup {} · {} · 安全启动 {} ",
            s.os.pretty_name,
            s.os.kernel,
            ver(s.tools.systemd),
            ver(s.tools.cryptsetup),
            tpm,
            s.firmware.secure_boot_label()
        )
        .into(),
        if s.is_root {
            " root ".black().on_green()
        } else {
            t!(" 只读 ").black().on_yellow()
        },
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_tabs(f: &mut Frame, app: &mut App, area: Rect) {
    let mut x = area.x;
    let mut spans = Vec::new();
    for (t, name) in TABS {
        let name = luks_assistant_core::i18n::tr(name);
        let label = if t == Tab::Health && !app.issues.is_empty() {
            format!(" {name}({}) ", app.issues.len())
        } else {
            format!(" {name} ")
        };
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
}

fn draw_bottom(f: &mut Frame, app: &App, area: Rect) {
    let hints = match app.tab {
        Tab::Slots => {
            t!(
                "←↑↓→ 选择  Enter 操作  a 添加  d 删除  n 备注  e 修改  v 验证  D 磁盘  T TRIM  ? 帮助  q 退出"
            )
        }
        Tab::Health => t!("↑↓ 选择  Enter 修复"),
        Tab::Backup => t!("↑↓ 选择  空格 勾选  a 全选  Enter 备份所选  r 恢复  c 备份位置"),
        _ => t!("Tab/1-6 切换  F5 刷新  q 退出"),
    };
    let line = Line::from(vec![
        Span::styled(format!(" {} ", app.status), Style::new().yellow()),
        Span::styled(hints, Style::new().dark_gray()),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_device_bar(f: &mut Frame, app: &mut App, area: Rect) {
    let (luks, total) = app.tree.volume_counts();
    let luks = luks + app.extra.len();
    let total = total + app.extra.len();
    let dev = app.device().map(|d| {
        let size = d.size.clone().unwrap_or_default();
        format!("{} {size}", d.display_name())
    });
    let disk = format!(" ▼ {} ", trunc(&dev.unwrap_or_else(|| t!("无").into()), 60));
    let mut x = area.x;
    let mut spans: Vec<Span> = Vec::new();
    let mut push =
        |spans: &mut Vec<Span<'static>>, s: Span<'static>, rect: Option<&mut Option<Rect>>| {
            let w = s.content.width() as u16;
            if let Some(r) = rect {
                *r = Some(Rect::new(x, area.y, w, 1));
            }
            x += w;
            spans.push(s);
        };
    push(&mut spans, t!("磁盘 ").into(), None);
    push(
        &mut spans,
        Span::styled(disk, Style::new().black().on_white()),
        Some(&mut app.rects.disk),
    );
    push(
        &mut spans,
        t!("  LUKS 卷 {}/{}   ", luks, total).into(),
        None,
    );
    push(&mut spans, button(t!("验证")), Some(&mut app.rects.verify));
    let unlocked = app.ov.as_ref().is_some_and(|o| o.device.mapping.is_some());
    if let Some((flag, dev)) = app.trim_state() {
        let d = match dev {
            Some(true) => t!("支持"),
            Some(false) => t!("不支持"),
            None => "?",
        };
        push(
            &mut spans,
            t!(
                "   TRIM 头部:{} 设备:{} ",
                if flag { t!("开") } else { t!("关") },
                d
            )
            .into(),
            None,
        );
        if unlocked {
            push(&mut spans, button("TRIM"), Some(&mut app.rects.trim));
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_slots(f: &mut Frame, app: &mut App, area: Rect) {
    let [bar, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(4)]).areas(area);
    draw_device_bar(f, app, bar);
    let Some(ov) = &app.ov else {
        let msg = app.load_error.clone().unwrap_or_default();
        f.render_widget(
            Paragraph::new(msg).block(Block::bordered().title(t!(" 槽位 "))),
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
            (_, Some(TpmStatus::Mismatch { .. })) => t!("⚠ PCR 已变化").to_owned(),
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
        lines.push(Line::from(t!("空闲").dark_gray()));
    } else {
        lines.push(kv(t!("类型"), s.kind.label()));
        if let Some(ks) = &s.keyslot {
            lines.push(kv("KDF", ks.kdf.summary()));
            lines.push(kv(t!("优先级"), ks.priority.label()));
            if let Some(e) = &ks.area_encryption {
                lines.push(kv(t!("槽位加密"), t!("{}  {} 位", e, ks.key_size * 8)));
            }
        }
        if !s.tokens.is_empty() {
            lines.push(kv(t!("令牌"), format!("{:?}", s.tokens)));
        }
        lines.push(kv(
            t!("备注"),
            match &s.note {
                Some(n) => format!(
                    "{}  [{}{}]",
                    if n.note.text.is_empty() {
                        "—"
                    } else {
                        &n.note.text
                    },
                    n.location.label(),
                    n.note
                        .kind
                        .map(|k| t!("，{}", k.label()))
                        .unwrap_or_default()
                ),
                None => "—".into(),
            },
        ));
        if let Some(t) = &s.tpm2 {
            lines.push(kv("TPM2", t.describe()));
            if let Some(st) = &s.tpm2_status {
                let color = match st {
                    TpmStatus::Match => Color::Green,
                    TpmStatus::Mismatch { .. } => Color::Red,
                    TpmStatus::Unknown(_) => Color::Yellow,
                };
                lines.push(Line::from(vec![
                    Span::styled(pad(t!("状态"), 11), Style::new().dark_gray()),
                    Span::styled(st.label(), Style::new().fg(color).bold()),
                    if matches!(st, TpmStatus::Mismatch { .. }) {
                        t!("  按 e 重新录入").yellow()
                    } else {
                        "".into()
                    },
                ]));
            }
            if let Some(h) = &t.policy_hash {
                lines.push(kv(t!("策略哈希"), h.clone()));
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
        t!("卷"),
        t!(
            "{} · 扇区 {} · JSON {}/{} 字节",
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
            .block(Block::bordered().title(t!(" 槽位 {} ", s.id))),
        area,
    );
}

fn draw_system(f: &mut Frame, app: &mut App, area: Rect) {
    let [left, mid, right] = Layout::horizontal([
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
    ])
    .areas(area);
    let s = &app.sys;
    let ver = |v: Option<luks_assistant_sysinfo::tools::Version>| {
        v.map(|v| v.to_string())
            .unwrap_or_else(|| t!("未安装").into())
    };
    let mut lines = vec![
        kv(t!("发行版"), s.os.pretty_name.clone()),
        kv(t!("系列"), s.os.family.label()),
        kv(t!("内核"), s.os.kernel.clone()),
        kv(t!("主机名"), s.os.hostname.clone()),
        kv("cryptsetup", ver(s.tools.cryptsetup)),
        kv("systemd", ver(s.tools.systemd)),
        kv(t!("固件"), if s.firmware.uefi { "UEFI" } else { "BIOS" }),
        kv(t!("安全启动"), s.firmware.secure_boot_label()),
        Line::from(""),
        Line::from("TPM".bold()),
    ];
    if s.tpm.present {
        lines.push(kv(
            t!("版本"),
            format!("TPM {}.0", s.tpm.version_major.unwrap_or(0)),
        ));
        lines.push(kv(
            t!("设备"),
            s.tpm
                .dev_node
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        ));
        lines.push(kv(t!("驱动"), s.tpm.driver.clone().unwrap_or_default()));
        lines.push(kv(
            t!("描述"),
            s.tpm.description.clone().unwrap_or_default(),
        ));
        lines.push(kv("PCR bank", s.tpm.banks.join(", ")));
    } else {
        lines.push(Line::from(t!("  未检测到").dark_gray()));
    }
    if app.ctx.tpm2_device != "auto" {
        lines.push(kv(t!("覆盖"), app.ctx.tpm2_device.clone()));
    }
    for (title, list) in [
        (t!("FIDO2 安全密钥"), &app.fido2_devices),
        (t!("PKCS#11 智能卡"), &app.pkcs11_tokens),
    ] {
        lines.push(Line::from(""));
        lines.push(Line::from(title.bold()));
        match list {
            Some(d) if !d.is_empty() => {
                lines.extend(d.iter().map(|x| Line::from(format!("  {x}"))))
            }
            _ => lines.push(Line::from(t!("  未检测到").dark_gray())),
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(t!("功能").bold()));
    for (name, ok) in s.caps.describe() {
        lines.push(Line::from(vec![
            if ok { "  ✓ ".green() } else { "  ✗ ".red() },
            name.into(),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(t!(" 系统 "))),
        left,
    );

    // block devices
    let (luks, total) = app.tree.volume_counts();
    let mut dl: Vec<Line> = vec![Line::from(
        t!(
            "{} {} {} 加密",
            format!("{:<16}", t!("名称")),
            format!("{:>6}", t!("大小")),
            format!("{:<5}", "TRIM")
        )
        .dark_gray(),
    )];
    for (depth, n) in app.tree.flatten() {
        let name = format!(
            "{}{}",
            "  ".repeat(depth),
            n.path.rsplit('/').next().unwrap_or(&n.path)
        );
        let trim = match n.trim() {
            Some(true) => "✓",
            Some(false) => "✗",
            None => "-",
        };
        let style = if n.is_luks() {
            Style::new().green()
        } else if n.kind == "crypt" {
            Style::new().cyan()
        } else {
            Style::new()
        };
        let mut extra = n.encryption();
        if let Some(mp) = n.mountpoints.first() {
            extra = format!("{extra} {mp}");
        }
        dl.push(Line::from(vec![
            Span::styled(format!("{} ", pad(&trunc(&name, 16), 16)), style),
            Span::raw(format!("{:>6} ", n.size.clone().unwrap_or_default())),
            Span::raw(format!("{:<5} ", trim)),
            Span::styled(extra, style),
        ]));
    }
    f.render_widget(
        Paragraph::new(dl).block(Block::bordered().title(t!(" 磁盘 · LUKS {}/{} ", luks, total))),
        mid,
    );

    let mut pl: Vec<Line> = Vec::new();
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
    for info in pcr::PCRS.iter() {
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
    pl.push(Line::from(t!("* 已被 TPM2 槽位使用").dark_gray()));
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

fn draw_health(f: &mut Frame, app: &mut App, area: Rect) {
    let [list, detail] = Layout::vertical([Constraint::Min(5), Constraint::Length(5)]).areas(area);
    let block = Block::bordered().title(t!(" 元数据体检 "));
    let inner = block.inner(list);
    f.render_widget(block, list);
    if app.issues.is_empty() {
        f.render_widget(Paragraph::new(t!("✓ 没有问题").green()), inner);
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
            if issue.fix.is_some() {
                t!("  (Enter 修复)").green()
            } else {
                "".into()
            },
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
            Span::styled(format!(" {} ", item.status.symbol()), st),
            Span::styled(pad(&item.title, 22), Style::new().bold()),
            Span::raw(item.detail.replace('\n', " ")),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(t!(" 检查开机时 TPM2/FIDO2 自动解锁是否可用 "))),
        area,
    );
}

fn draw_backup(f: &mut Frame, app: &mut App, area: Rect) {
    let [head, list] = Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).areas(area);
    let selected = app.backup_sel.iter().filter(|b| **b).count();
    let mut spans = vec![
        Span::raw(t!(" 备份位置: ")),
        Span::styled(
            app.ctx.paths.backup_root.display().to_string(),
            Style::new().bold(),
        ),
        Span::raw(t!("  (c 修改)    ")),
    ];
    let label = t!("备份所选 ({})", selected);
    let x = head.x + 1 + spans.iter().map(|s| s.content.width() as u16).sum::<u16>();
    app.rects.backup_button = Some(Rect::new(x, head.y + 1, label.width() as u16 + 4, 1));
    spans.push(button(&label));
    f.render_widget(
        Paragraph::new(Line::from(spans)).block(Block::bordered()),
        head,
    );

    let block = Block::bordered().title(t!(" LUKS 卷 "));
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
                "最后备份 {} · {} · 共 {} 个",
                format_time(b.modified),
                b.path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                files.len()
            ),
            None => t!("从未备份").into(),
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
        f.render_widget(Paragraph::new(t!("没有 LUKS 卷").dark_gray()), inner);
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
    lines.extend(app.log.iter().map(|l| Line::from(l.clone())));
    f.render_widget(
        Paragraph::new(lines)
            .scroll((app.log_scroll, 0))
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(t!(" 日志 "))),
        area,
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
                .title(t!(" 磁盘 "))
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
        Modal::Form(state) => draw_form(f, app, state, area),
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
                    lines.push(Line::from(t!("输入 {} 后按 Enter 确认", w).red().bold()));
                    lines.push(Line::from(vec![
                        "> ".into(),
                        typed.clone().bold(),
                        "▏".into(),
                    ]));
                }
                None => lines.push(Line::from(t!("Enter 执行 · Esc 取消").cyan())),
            }
            f.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .scroll((*scroll, 0))
                    .block(Block::bordered().title(t!(" 确认 ")).border_style(color)),
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
                        "恢复密钥 · 槽位 {}",
                        slot.map(|s| s.to_string()).unwrap_or("?".into())
                    )
                    .green()
                    .bold(),
                ),
                Line::from(""),
                Line::from(key.clone().bold().yellow()),
                Line::from(""),
                Line::from(t!("只显示这一次，请离线保存")),
                Line::from(""),
                Line::from(t!("按 y 关闭").cyan()),
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
槽位
  ←↑↓→ hjkl / 点击   选择；双击或 Enter 打开菜单
  a 添加   e 修改/重新录入   d 删除   n 备注
  v 验证   D 选择磁盘   T TRIM 穿透
备份
  空格 勾选   a 全选   Enter 备份所选   r 恢复   c 备份位置
全局
  Tab / 1-6 切换页面   F5 刷新   q 退出");
            let r = centered(area, 60, 12);
            clear(f, r);
            f.render_widget(
                Paragraph::new(text).block(Block::bordered().title(t!(" 帮助 "))),
                r,
            );
        }
    }
}

fn draw_form(f: &mut Frame, app: &App, state: &FormState, area: Rect) {
    let form = &state.form;
    let has_pcrs = form
        .fields
        .iter()
        .any(|x| matches!(x.value, Value::Pcrs(..)));
    let shown = (0..form.fields.len()).filter(|i| form.visible(*i)).count();
    let h = shown as u16 + if has_pcrs { 11 } else { 4 };
    let r = centered(
        area,
        area.width.saturating_sub(4).min(100),
        h.min(area.height),
    );
    clear(f, r);
    let block = Block::bordered()
        .title(format!(" {} ", form.title))
        .title_bottom(t!(" Tab/↑↓ 切换  空格/←→ 选择  Enter 确定  Esc 取消 "))
        .border_style(Color::Cyan);
    let inner = block.inner(r).inner(Margin::new(1, 0));
    f.render_widget(block, r);
    let mut lines: Vec<Line> = Vec::new();
    let label_w = 16;
    for (i, field) in form.fields.iter().enumerate() {
        if !form.visible(i) {
            continue;
        }
        let focused = i == state.focus;
        let lab = Span::styled(
            format!(
                "{}{}",
                if focused { "▶ " } else { "  " },
                pad(&field.label, label_w)
            ),
            if focused {
                Style::new().cyan().bold()
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
            Value::Pcrs(set) => (0..24)
                .map(|p| {
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
    if has_pcrs {
        let sel = form.pcrs("pcrs");
        let c = state.pcr_cursor;
        let info = &pcr::PCRS[c];
        let val = app
            .pcr_table
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .and_then(|m| m.get(&(c as u8)))
            .map(|b| encode_hex(b))
            .unwrap_or_else(|| "—".into());
        lines.push(Line::from(""));
        lines.push(Line::from(t!("已选 PCR {}", pcr_list(&sel)).bold()));
        lines.push(Line::from(t!(
            "PCR {} {}：{}",
            c,
            info.name(),
            info.measures()
        )));
        lines.push(Line::from(t!("  改变：{}", info.changes()).dark_gray()));
        lines.push(Line::from(
            t!("  当前：{}", trunc(&val, inner.width as usize - 10)).dark_gray(),
        ));
        for w in pcr::selection_warnings(&sel, app.sys.firmware.secure_boot) {
            lines.push(Line::from(format!("! {w}").yellow()));
        }
    }
    if let Some(e) = &state.error {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("✗ {e}").red().bold()));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}
