//! Rendering.

use crate::app::{App, Modal, TABS, Tab, pcr_label};
use crate::form::{Form, Value};
use luks_assistant_core::health::Severity;
use luks_assistant_core::ops::Danger;
use luks_assistant_core::pcr::{self, TpmStatus};
use luks_assistant_core::slots::{Slot, SlotKind};
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
        SlotKind::Passphrase => "🔑",
        SlotKind::Keyfile => "📄",
        SlotKind::Secret => "🔑",
        SlotKind::Recovery => "🛟",
        SlotKind::Tpm2 => "🔒",
        SlotKind::Fido2 => "🗝",
        SlotKind::Pkcs11 => "💳",
        SlotKind::OtherToken(_) => "◆",
        SlotKind::Reencrypt => "↻",
        SlotKind::Luks1 => "🔑",
    }
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
        "无 TPM".into()
    };
    let ver = |v: Option<luks_assistant_sysinfo::tools::Version>| {
        v.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
    };
    let line = Line::from(vec![
        " luks-assistant ".black().on_cyan().bold(),
        format!(
            " {} · {} · 内核 {} · systemd {} · cryptsetup {} · {} · 安全启动 {} ",
            s.os.pretty_name,
            s.os.family.label(),
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
            " 非 root（只读）".black().on_yellow()
        },
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_tabs(f: &mut Frame, app: &mut App, area: Rect) {
    let mut x = area.x;
    let mut spans = Vec::new();
    for (t, name) in TABS {
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
    if let Some(d) = app.device() {
        spans.push(format!("   设备: {}", d.display_name()).bold());
        if app.devices.len() > 1 {
            spans.push(format!("  [D 切换，共 {} 个]", app.devices.len()).dark_gray());
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_bottom(f: &mut Frame, app: &App, area: Rect) {
    let hints = match app.tab {
        Tab::Slots => {
            "←↑↓→ 选择  Enter 操作  a 添加  d 删除  n 备注  e 修改/重新录入  t 测试密码  b 备份  R 恢复  F5 刷新  ? 帮助  q 退出"
        }
        Tab::Health => "↑↓ 选择  Enter 修复（如可）  F5 刷新  q 退出",
        _ => "Tab/1-5 切换页面  F5 刷新  ? 帮助  q 退出",
    };
    let line = Line::from(vec![
        Span::styled(format!(" {} ", app.status), Style::new().yellow()),
        Span::styled(hints, Style::new().dark_gray()),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_slots(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(ov) = &app.ov else {
        let msg = app.load_error.clone().unwrap_or_default();
        f.render_widget(
            Paragraph::new(msg)
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title(" 槽位 ")),
            area,
        );
        return;
    };
    let cols: u16 = if area.width >= 8 * 12 + 2 { 8 } else { 4 };
    let rows = 32 / cols;
    let grid_h = rows * 3 + 2;
    let [grid_area, detail_area] =
        Layout::vertical([Constraint::Length(grid_h), Constraint::Min(4)]).areas(area);

    let used = ov.used().count();
    let title = format!(
        " LUKS{} · UUID {} · 已用 {used}/32 槽位 · {} 个令牌 ",
        ov.header.version,
        ov.header.uuid,
        ov.header.tokens.len()
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
        let selected = s.id == app.selected;
        let mut style = Style::new().fg(color);
        if selected {
            style = Style::new()
                .fg(Color::Black)
                .bg(color)
                .add_modifier(Modifier::BOLD);
        }
        let w = rect.width as usize;
        let l1 = if s.is_empty() {
            format!("{:02} ·", s.id)
        } else {
            format!("{:02} {} {}", s.id, kind_icon(&s.kind), s.kind.label())
        };
        let l2 = match (&s.note, &s.tpm2_status) {
            (_, Some(TpmStatus::Mismatch { .. })) => "⚠ PCR 已变化".to_owned(),
            (Some(n), _) if !n.note.text.is_empty() => n.note.text.clone(),
            (_, Some(TpmStatus::Match)) => {
                format!("✓ PCR {}", pcr_label(&s.tpm2.as_ref().unwrap().pcrs))
            }
            _ if s.is_empty() => String::new(),
            _ => s.summary(),
        };
        let text = Text::from(vec![Line::from(trunc(&l1, w)), Line::from(trunc(&l2, w))]);
        let para = Paragraph::new(text).style(style);
        f.render_widget(para, rect);
    }

    draw_slot_detail(f, app, detail_area);
}

fn kv(k: &str, v: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(pad(k, 11), Style::new().dark_gray()),
        Span::raw(v.into()),
    ])
}

fn draw_slot_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(ov) = &app.ov else { return };
    let Some(s) = app.selected_slot() else { return };
    let mut lines: Vec<Line> = Vec::new();
    if s.is_empty() {
        lines.push(Line::from(
            "空闲槽位。按 Enter 或 a 添加密码、密钥文件、恢复密钥或令牌。".dark_gray(),
        ));
    } else {
        lines.push(kv("类型", s.kind.label()));
        if let Some(ks) = &s.keyslot {
            lines.push(kv("KDF", ks.kdf.summary()));
            lines.push(kv("优先级", ks.priority.label()));
            if let Some(e) = &ks.area_encryption {
                lines.push(kv("槽位加密", format!("{e}  密钥 {} 位", ks.key_size * 8)));
            }
        }
        if !s.tokens.is_empty() {
            lines.push(kv("令牌", format!("{:?}", s.tokens)));
        }
        match &s.note {
            Some(n) => lines.push(kv(
                "备注",
                format!(
                    "{}  [{}{}]",
                    if n.note.text.is_empty() {
                        "（无文字）"
                    } else {
                        &n.note.text
                    },
                    n.location.label(),
                    n.note
                        .kind
                        .map(|k| format!("，类型: {}", k.label()))
                        .unwrap_or_default()
                ),
            )),
            None => lines.push(kv("备注", "（无）  按 n 添加")),
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
                    Span::styled(pad("状态", 11), Style::new().dark_gray()),
                    Span::styled(st.label(), Style::new().fg(color).bold()),
                ]));
                if matches!(st, TpmStatus::Mismatch { .. }) {
                    lines.push(Line::from(
                        "           按 e 重新录入（需要现有密码），可同时修改 PCR 选择".yellow(),
                    ));
                }
            }
            if let Some(h) = &t.policy_hash {
                lines.push(kv("策略哈希", h.clone()));
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
        "设备",
        format!(
            "{} · {} · 扇区 {} · TRIM 穿透(头部) {} · JSON 区 {}/{} 字节",
            seg.and_then(|s| s.encryption.clone()).unwrap_or_default(),
            ov.device.size.clone().unwrap_or_default(),
            seg.and_then(|s| s.sector_size).unwrap_or(0),
            if ov.header.allows_discards() {
                "开"
            } else {
                "关"
            },
            ov.header.json_used,
            ov.header.config.json_size
        ),
    ));
    if let Some(r) = ov.read_only_reason() {
        lines.push(Line::from(r.yellow()));
    }
    let title = if s.is_empty() {
        format!(" 槽位 {} ", s.id)
    } else {
        format!(" 槽位 {} 详情 ", s.id)
    };
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(title)),
        area,
    );
}

fn draw_system(f: &mut Frame, app: &mut App, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).areas(area);
    let s = &app.sys;
    let ver = |v: Option<luks_assistant_sysinfo::tools::Version>| {
        v.map(|v| v.to_string()).unwrap_or_else(|| "未安装".into())
    };
    let mut lines = vec![
        kv(
            "发行版",
            format!("{} ({})", s.os.pretty_name, s.os.family.label()),
        ),
        kv("内核", s.os.kernel.clone()),
        kv("主机名", s.os.hostname.clone()),
        kv("cryptsetup", ver(s.tools.cryptsetup)),
        kv("systemd", ver(s.tools.systemd)),
        kv(
            "tpm2-tools",
            if s.tools.has_tpm2_tools {
                "已安装"
            } else {
                "未安装（非必需）"
            },
        ),
        kv("固件", if s.firmware.uefi { "UEFI" } else { "BIOS" }),
        kv("安全启动", s.firmware.secure_boot_label()),
        Line::from(""),
        Line::from("TPM".bold()),
    ];
    if s.tpm.present {
        lines.push(kv(
            "版本",
            format!("TPM {}.0", s.tpm.version_major.unwrap_or(0)),
        ));
        lines.push(kv(
            "设备",
            s.tpm
                .dev_node
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        ));
        lines.push(kv("驱动", s.tpm.driver.clone().unwrap_or_default()));
        lines.push(kv("描述", s.tpm.description.clone().unwrap_or_default()));
        lines.push(kv("PCR bank", s.tpm.banks.join(", ")));
    } else {
        lines.push(Line::from("未检测到 TPM".dark_gray()));
    }
    if app.ctx.tpm2_device != "auto" {
        lines.push(kv("TPM 覆盖", app.ctx.tpm2_device.clone()));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("FIDO2 安全密钥".bold()));
    match &app.fido2_devices {
        Some(d) if !d.is_empty() => lines.extend(d.iter().map(|x| Line::from(format!("  {x}")))),
        _ => lines.push(Line::from("  未检测到".dark_gray())),
    }
    lines.push(Line::from(""));
    lines.push(Line::from("功能支持".bold()));
    for (name, ok) in s.caps.describe() {
        lines.push(Line::from(vec![
            if ok { "  ✓ ".green() } else { "  ✗ ".red() },
            name.into(),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" 系统 ")),
        left,
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
            Span::styled(format!("{:<14}", short), Style::new().dark_gray()),
            Span::styled(trunc(info.name, 16), style),
            Span::raw("  "),
            Span::styled(info.changes, Style::new().dark_gray()),
        ]));
    }
    pl.push(Line::from(""));
    pl.push(Line::from("* = 被当前设备的 TPM2 槽位使用".dark_gray()));
    f.render_widget(
        Paragraph::new(pl)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" PCR (sha256) · 编号 · 当前值 · 用途 · 何时改变 ")),
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
    let [list, detail] = Layout::vertical([Constraint::Min(5), Constraint::Length(7)]).areas(area);
    let block = Block::bordered().title(" 元数据体检 ");
    let inner = block.inner(list);
    f.render_widget(block, list);
    if app.issues.is_empty() {
        f.render_widget(Paragraph::new("✓ 没有发现问题".green()), inner);
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
                "  (Enter 修复)".green()
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
                .block(Block::bordered().title(" 说明 ")),
            detail,
        );
    }
}

fn draw_boot(f: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![
        Line::from("检查开机时 TPM2/FIDO2 自动解锁是否可用。只做检查，不修改任何配置；不同发行版差异很大，结果仅供参考。".dark_gray()),
        Line::from(""),
    ];
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
            Span::styled(item.title.clone(), Style::new().bold()),
        ]));
        for l in item.detail.lines() {
            lines.push(Line::from(format!("     {l}")));
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" 开机检查 ")),
        area,
    );
}

fn draw_log(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = vec![
        Line::from(
            format!(
                "完整历史（已脱敏）: {}",
                app.ctx.paths.history_log().display()
            )
            .dark_gray(),
        ),
        Line::from(
            format!(
                "头部备份目录: {}/backups/",
                app.ctx.paths.state_dir.display()
            )
            .dark_gray(),
        ),
        Line::from(""),
    ];
    if app.log.is_empty() {
        lines.push(Line::from("本次会话还没有执行操作".dark_gray()));
    }
    lines.extend(app.log.iter().map(|l| Line::from(l.clone())));
    f.render_widget(
        Paragraph::new(lines)
            .scroll((app.log_scroll, 0))
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" 日志 ")),
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
        Modal::Form(form) => draw_form(f, app, form, area),
        Modal::Confirm {
            plan,
            typed,
            scroll,
        } => {
            let r = centered(
                area,
                area.width.saturating_sub(6).min(120),
                area.height.saturating_sub(4).min(30),
            );
            clear(f, r);
            let color = match plan.danger {
                Danger::Normal => Color::Cyan,
                Danger::High => Color::Yellow,
                Danger::Critical => Color::Red,
            };
            let mut lines: Vec<Line> = vec![Line::from(plan.title.clone().bold()), Line::from("")];
            if !plan.warnings.is_empty() {
                lines.push(Line::from("注意：".yellow().bold()));
                for w in &plan.warnings {
                    lines.push(Line::from(format!("  ! {w}").yellow()));
                }
                lines.push(Line::from(""));
            }
            lines.push(Line::from(
                "将执行以下步骤（等效命令，秘密已隐藏）：".bold(),
            ));
            for (i, s) in plan.steps.iter().enumerate() {
                lines.push(Line::from(format!("{:>2}. {}", i + 1, s.desc())));
                if let Some(c) = s.command() {
                    lines.push(Line::from(format!("      $ {c}").dark_gray()));
                }
            }
            lines.push(Line::from(""));
            match &plan.confirm_word {
                Some(w) => {
                    lines.push(Line::from(
                        format!("高危操作：输入 {w} 后按 Enter 确认，Esc 取消")
                            .red()
                            .bold(),
                    ));
                    lines.push(Line::from(vec![
                        "> ".into(),
                        typed.clone().bold(),
                        "▏".into(),
                    ]));
                }
                None => lines.push(Line::from("Enter 执行 · Esc 取消 · ↑↓ 滚动".cyan())),
            }
            f.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .scroll((*scroll, 0))
                    .block(Block::bordered().title(" 确认 ").border_style(color)),
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
                area.height.saturating_sub(4).min(30),
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
                            .title_bottom(" 任意键关闭 · ↑↓ 滚动 ")
                            .border_style(if *ok { Color::Green } else { Color::Red }),
                    ),
                r,
            );
        }
        Modal::Recovery { key, slot } => {
            let r = centered(area, 90, 12);
            clear(f, r);
            let lines = vec![
                Line::from(
                    format!(
                        "恢复密钥已写入槽位 {}",
                        slot.map(|s| s.to_string()).unwrap_or("?".into())
                    )
                    .green()
                    .bold(),
                ),
                Line::from(""),
                Line::from(key.clone().bold().yellow()),
                Line::from(""),
                Line::from(
                    "它只会显示这一次。请抄写/打印并离线保存，可在任何要求输入密码的地方使用。",
                ),
                Line::from("不要截图上传到云端。"),
                Line::from(""),
                Line::from("已妥善保存后，按 y 关闭".cyan()),
            ];
            f.render_widget(
                Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                    Block::bordered()
                        .title(" 恢复密钥 ")
                        .border_style(Color::Yellow),
                ),
                r,
            );
        }
        Modal::Message { title, text } => {
            let w = text.lines().map(|l| l.width()).max().unwrap_or(10) as u16 + 4;
            let r = centered(
                area,
                w.clamp(30, area.width.saturating_sub(4)),
                text.lines().count() as u16 + 4,
            );
            clear(f, r);
            f.render_widget(
                Paragraph::new(text.clone())
                    .wrap(Wrap { trim: false })
                    .block(
                        Block::bordered()
                            .title(format!(" {title} "))
                            .title_bottom(" 任意键关闭 "),
                    ),
                r,
            );
        }
        Modal::Help => {
            let text = "\
槽位页
  ←↑↓→ / hjkl  选择槽位（也可以用鼠标点击，双击打开操作菜单）
  Enter / 空格  打开该槽位的操作菜单
  a  添加（密码 / 密钥文件 / 恢复密钥 / TPM2 / FIDO2 / PKCS#11）
  e  修改密码，或重新录入 TPM2/FIDO2/恢复密钥
  d  删除槽位（需要另一个槽位的凭据，并输入槽位号确认）
  n  编辑备注（存入头部 或 存在本机 /etc/）
全局
  t  测试密码对应哪个槽位      b  备份头部      R  从备份恢复头部
  D  切换设备                  F5 刷新          Tab / 1-5 切换页面
  q / Ctrl-C 退出

所有写操作都会先显示等效命令并自动备份头部。
最后一个密码/恢复密钥槽位永远不能删除。";
            let r = centered(area, 76, 20);
            clear(f, r);
            f.render_widget(
                Paragraph::new(text).block(
                    Block::bordered()
                        .title(" 帮助 ")
                        .title_bottom(" 任意键关闭 "),
                ),
                r,
            );
        }
    }
}

fn draw_form(f: &mut Frame, app: &App, form: &Form<crate::app::FormKind>, area: Rect) {
    let has_pcrs = form
        .fields
        .iter()
        .any(|x| matches!(x.value, Value::Pcrs(..)));
    let h = form.fields.len() as u16 + if has_pcrs { 12 } else { 5 };
    let r = centered(
        area,
        area.width.saturating_sub(4).min(100),
        h.min(area.height),
    );
    clear(f, r);
    let block = Block::bordered()
        .title(format!(" {} ", form.title))
        .title_bottom(" Tab/↑↓ 切换  空格/←→ 选择  Enter 下一步  Esc 取消 ")
        .border_style(Color::Cyan);
    let inner = block.inner(r).inner(Margin::new(1, 0));
    f.render_widget(block, r);
    let mut lines: Vec<Line> = Vec::new();
    let label_w = 18;
    for (i, field) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
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
        let val: Vec<Span> = match &field.value {
            Value::Text(s) => vec![
                Span::raw(s.clone()),
                if focused { "▏".into() } else { "".into() },
            ],
            Value::Secret(s) => vec![
                Span::raw("•".repeat(s.chars().count())),
                if focused { "▏".into() } else { "".into() },
            ],
            Value::Toggle(b) => vec![Span::raw(if *b { "[x] 是" } else { "[ ] 否" })],
            Value::Choice(opts, idx) => vec![Span::raw(format!("◀ {} ▶", opts[*idx]))],
            Value::Pcrs(set, cur) => (0..24)
                .map(|p| {
                    let mut st = if set[p] {
                        Style::new().black().on_magenta()
                    } else {
                        Style::new().dark_gray()
                    };
                    if focused && p == *cur {
                        st = st
                            .add_modifier(Modifier::UNDERLINED | Modifier::BOLD)
                            .fg(Color::White);
                    }
                    Span::styled(format!("{p:>2}"), st)
                })
                .flat_map(|s| [s, Span::raw(" ")])
                .collect(),
            Value::Label => {
                lines.push(Line::from(field.label.clone().dark_gray()));
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
        let cur = form.fields.iter().find_map(|x| match x.value {
            Value::Pcrs(_, c) => Some(c),
            _ => None,
        });
        lines.push(Line::from(""));
        lines.push(Line::from(format!("已选 PCR: {}", pcr_label(&sel)).bold()));
        if let Some(c) = cur {
            let info = &pcr::PCRS[c];
            let val = app
                .pcr_table
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .and_then(|m| m.get(&(c as u8)))
                .map(|b| encode_hex(b))
                .unwrap_or_else(|| "—".into());
            lines.push(Line::from(format!(
                "PCR {c} {}：{}",
                info.name, info.measures
            )));
            lines.push(Line::from(
                format!("  何时改变：{}", info.changes).dark_gray(),
            ));
            lines.push(Line::from(
                format!("  当前值：{}", trunc(&val, inner.width as usize - 10)).dark_gray(),
            ));
        }
        for w in pcr::selection_warnings(&sel, app.sys.firmware.secure_boot) {
            lines.push(Line::from(format!("! {w}").yellow()));
        }
    }
    if let Some(e) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(format!("✗ {e}").red().bold()));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn pad(s: &str, w: usize) -> String {
    let cur = s.width();
    if cur >= w {
        s.to_owned()
    } else {
        format!("{s}{}", " ".repeat(w - cur))
    }
}
