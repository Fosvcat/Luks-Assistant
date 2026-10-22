//! "Will TPM2 / FIDO2 unlocking work at boot?" — a quick, best-effort check.
//!
//! Boot setups differ wildly between distributions, so this only inspects
//! the obvious places (initramfs generator configuration, crypttab, kernel
//! command line, token plugins) and explains what it finds. It never
//! changes anything.

use crate::cmd;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Status {
    Ok,
    Info,
    Warn,
    Fail,
    Unknown,
}

impl Status {
    pub fn symbol(self) -> &'static str {
        match self {
            Status::Ok => "✓",
            Status::Info => "i",
            Status::Warn => "!",
            Status::Fail => "✗",
            Status::Unknown => "?",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub title: String,
    pub status: Status,
    pub detail: String,
}

fn item(title: &str, status: Status, detail: impl Into<String>) -> Item {
    Item {
        title: title.to_owned(),
        status,
        detail: detail.into(),
    }
}

/// The encrypted device we are asking about.
#[derive(Debug, Clone, Default)]
pub struct Target {
    pub uuid: String,
    pub path: String,
    pub mapping: Option<String>,
}

const PLUGIN_DIRS: &[&str] = &[
    "/usr/lib/cryptsetup",
    "/usr/lib64/cryptsetup",
    "/usr/lib/x86_64-linux-gnu/cryptsetup",
    "/usr/lib/aarch64-linux-gnu/cryptsetup",
    "/lib/x86_64-linux-gnu/cryptsetup",
];

/// Run every check against the live system.
pub fn check(target: &Target) -> Vec<Item> {
    let mut items = Vec::new();

    let tpm = crate::tpm::TpmInfo::detect();
    items.push(if tpm.is_tpm2() {
        item(
            "TPM 2.0 设备",
            Status::Ok,
            format!(
                "{} 可用",
                tpm.dev_node
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "tpm0".into())
            ),
        )
    } else if tpm.present {
        item("TPM 2.0 设备", Status::Fail, "检测到 TPM，但不是 2.0 版本")
    } else {
        item(
            "TPM 2.0 设备",
            Status::Warn,
            "未检测到 TPM（如只用 FIDO2 可忽略）",
        )
    });

    items.push(check_plugins());

    let fw = crate::firmware::Firmware::detect();
    items.push(match fw.secure_boot {
        _ if !fw.uefi => item(
            "安全启动",
            Status::Warn,
            "传统 BIOS 启动，没有安全启动；PCR 7 无实际意义",
        ),
        Some(true) => item("安全启动", Status::Ok, "已开启，绑定 PCR 7 有意义"),
        Some(false) => item(
            "安全启动",
            Status::Warn,
            "未开启：PCR 7 只能证明“安全启动是关闭的”，TPM 自动解锁的保护力有限",
        ),
        None => item("安全启动", Status::Unknown, "无法读取 SecureBoot 变量"),
    });

    let mut found_generator = false;
    if Path::new("/etc/mkinitcpio.conf").exists() && cmd::which("mkinitcpio").is_some() {
        found_generator = true;
        items.push(analyze_mkinitcpio(&read_mkinitcpio_config()));
    }
    if cmd::which("dracut").is_some() {
        found_generator = true;
        items.push(analyze_dracut(&read_dir_concat(
            "/etc/dracut.conf",
            "/etc/dracut.conf.d",
        )));
    }
    if Path::new("/etc/initramfs-tools").is_dir() && cmd::which("update-initramfs").is_some() {
        found_generator = true;
        items.push(item(
            "initramfs-tools",
            Status::Warn,
            "Debian/Ubuntu 的 initramfs-tools (cryptsetup-initramfs) 一般不支持 systemd-cryptenroll 令牌，开机时通常仍会要求输入密码。可考虑改用 dracut 或 clevis（以实测为准）。",
        ));
    }
    if Path::new("/etc/booster.yaml").exists() {
        found_generator = true;
        items.push(item(
            "booster",
            Status::Info,
            "booster 支持 systemd-tpm2 / systemd-fido2 令牌，请确认已启用相应模块。",
        ));
    }
    if !found_generator {
        items.push(item(
            "initramfs 生成器",
            Status::Unknown,
            "没有识别出 mkinitcpio / dracut / initramfs-tools / booster",
        ));
    }

    let crypttab = std::fs::read_to_string("/etc/crypttab").unwrap_or_default();
    items.push(analyze_crypttab(&crypttab, target));

    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    items.push(analyze_cmdline(&cmdline, target));

    items
}

fn check_plugins() -> Item {
    let mut found = Vec::new();
    for dir in PLUGIN_DIRS {
        for name in ["tpm2", "fido2", "pkcs11"] {
            let p = Path::new(dir).join(format!("libcryptsetup-token-systemd-{name}.so"));
            if p.exists() && !found.contains(&name) {
                found.push(name);
            }
        }
    }
    if found.is_empty() {
        item(
            "cryptsetup 令牌插件",
            Status::Warn,
            "未找到 libcryptsetup-token-systemd-*.so：`cryptsetup open` 无法直接使用 TPM2/FIDO2 令牌（systemd-cryptsetup 不受影响）",
        )
    } else {
        item(
            "cryptsetup 令牌插件",
            Status::Ok,
            format!("已安装: {}", found.join(", ")),
        )
    }
}

fn read_mkinitcpio_config() -> String {
    read_dir_concat("/etc/mkinitcpio.conf", "/etc/mkinitcpio.conf.d")
}

/// Main file followed by the drop-ins of `dir` in lexical order, so that
/// later assignments override earlier ones as the tools do.
fn read_dir_concat(main: &str, dir: &str) -> String {
    let mut text = std::fs::read_to_string(main).unwrap_or_default();
    if let Ok(rd) = std::fs::read_dir(dir) {
        let mut files: Vec<_> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "conf"))
            .collect();
        files.sort();
        for f in files {
            text.push('\n');
            text.push_str(&std::fs::read_to_string(f).unwrap_or_default());
        }
    }
    text
}

/// Value of the last active `HOOKS=(...)` assignment.
pub fn mkinitcpio_hooks(conf: &str) -> Option<Vec<String>> {
    let mut hooks = None;
    for line in conf.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("HOOKS=") {
            let inner = rest
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim_matches('"');
            hooks = Some(inner.split_whitespace().map(str::to_owned).collect());
        }
    }
    hooks
}

pub fn analyze_mkinitcpio(conf: &str) -> Item {
    let Some(hooks) = mkinitcpio_hooks(conf) else {
        return item("mkinitcpio", Status::Unknown, "没有找到 HOOKS= 配置");
    };
    let has = |h: &str| hooks.iter().any(|x| x == h);
    let list = hooks.join(" ");
    if has("sd-encrypt") {
        if has("systemd") {
            item(
                "mkinitcpio",
                Status::Ok,
                format!("使用 systemd + sd-encrypt 钩子，支持 TPM2/FIDO2 令牌。HOOKS=({list})"),
            )
        } else {
            item(
                "mkinitcpio",
                Status::Warn,
                format!(
                    "有 sd-encrypt 但缺少 systemd 钩子，sd-encrypt 需要基于 systemd 的 initramfs。HOOKS=({list})"
                ),
            )
        }
    } else if has("encrypt") {
        item(
            "mkinitcpio",
            Status::Fail,
            format!(
                "使用 busybox 的 encrypt 钩子（cryptdevice=），它不读取 LUKS2 令牌，开机时不会用 TPM2/FIDO2 解锁。需改用 systemd + sd-encrypt 钩子。HOOKS=({list})"
            ),
        )
    } else {
        item(
            "mkinitcpio",
            Status::Info,
            format!("HOOKS 中没有加密钩子，适用于非根分区的数据盘。HOOKS=({list})"),
        )
    }
}

pub fn analyze_dracut(conf: &str) -> Item {
    let mut modules = Vec::new();
    for line in conf.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((key, val)) = line.split_once("+=").or_else(|| line.split_once('=')) {
            let key = key.trim();
            if key == "add_dracutmodules" || key == "dracutmodules" {
                modules.extend(
                    val.trim()
                        .trim_matches('"')
                        .split_whitespace()
                        .map(str::to_owned),
                );
            }
        }
    }
    let has_tpm = modules.iter().any(|m| m == "tpm2-tss");
    let has_fido = modules.iter().any(|m| m == "fido2");
    let available = Path::new("/usr/lib/dracut/modules.d")
        .read_dir()
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().ends_with("tpm2-tss"))
        })
        .unwrap_or(false);
    match (has_tpm, has_fido) {
        (true, _) => item(
            "dracut",
            Status::Ok,
            format!(
                "已添加 tpm2-tss 模块{}",
                if has_fido { "和 fido2 模块" } else { "" }
            ),
        ),
        (false, true) => item("dracut", Status::Ok, "已添加 fido2 模块（未添加 tpm2-tss）"),
        (false, false) => item(
            "dracut",
            if available {
                Status::Warn
            } else {
                Status::Fail
            },
            if available {
                "配置中未显式添加 tpm2-tss / fido2 模块。hostonly 模式可能会自动包含；如开机不能自动解锁，可在 /etc/dracut.conf.d/ 中写入 add_dracutmodules+=\" tpm2-tss \" 后执行 dracut -f"
            } else {
                "未找到 dracut 的 tpm2-tss 模块，可能需要安装 tpm2-tss 相关软件包"
            },
        ),
    }
}

/// Does a crypttab source field refer to `target`?
fn crypttab_matches(name: &str, source: &str, target: &Target) -> bool {
    let uuid = target.uuid.to_ascii_lowercase();
    let src = source.to_ascii_lowercase();
    (!uuid.is_empty()
        && (src == format!("uuid={uuid}") || src.ends_with(&format!("/by-uuid/{uuid}"))))
        || (!target.path.is_empty() && source == target.path)
        || target.mapping.as_deref() == Some(name)
}

pub fn analyze_crypttab(text: &str, target: &Target) -> Item {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 || !crypttab_matches(fields[0], fields[1], target) {
            continue;
        }
        let opts = fields.get(3).copied().unwrap_or("");
        let mut found = Vec::new();
        for o in opts.split(',') {
            if o.starts_with("tpm2-device=")
                || o.starts_with("fido2-device=")
                || o.starts_with("pkcs11-uri=")
            {
                found.push(o.to_owned());
            }
        }
        return if found.is_empty() {
            item(
                "/etc/crypttab",
                Status::Info,
                format!(
                    "条目 {} 没有 tpm2-device= / fido2-device= 选项；systemd-cryptsetup 通常会通过令牌插件自动尝试头部中的令牌，若不生效可显式添加",
                    fields[0]
                ),
            )
        } else {
            item(
                "/etc/crypttab",
                Status::Ok,
                format!("条目 {} 已配置: {}", fields[0], found.join(", ")),
            )
        };
    }
    item(
        "/etc/crypttab",
        Status::Info,
        "没有该设备的条目（根分区通常由内核参数/initramfs 处理）",
    )
}

pub fn analyze_cmdline(cmdline: &str, target: &Target) -> Item {
    let args: Vec<&str> = cmdline.split_whitespace().collect();
    let uuid = target.uuid.to_ascii_lowercase();
    if let Some(a) = args.iter().find(|a| a.starts_with("cryptdevice=")) {
        return item(
            "内核参数",
            Status::Fail,
            format!("发现 {a}：这是 busybox encrypt 钩子的写法，不支持 TPM2/FIDO2 令牌"),
        );
    }
    let luks: Vec<&&str> = args.iter().filter(|a| a.starts_with("rd.luks.")).collect();
    if luks.is_empty() {
        return item(
            "内核参数",
            Status::Info,
            "没有 rd.luks.* 参数（数据盘或由 crypttab 处理时属正常）",
        );
    }
    let opts = luks
        .iter()
        .filter(|a| a.starts_with("rd.luks.options="))
        .map(|a| a.to_string())
        .collect::<Vec<_>>();
    let mentions_target =
        uuid.is_empty() || luks.iter().any(|a| a.to_ascii_lowercase().contains(&uuid));
    let token_opt = opts
        .iter()
        .any(|o| o.contains("tpm2-device=") || o.contains("fido2-device="));
    let summary = luks
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    if token_opt {
        item("内核参数", Status::Ok, summary)
    } else if mentions_target {
        item(
            "内核参数",
            Status::Info,
            format!(
                "{summary}\n（未显式指定 tpm2-device=/fido2-device=，sd-encrypt 通常会自动尝试令牌）"
            ),
        )
    } else {
        item(
            "内核参数",
            Status::Info,
            format!("{summary}\n（参数中未出现该设备的 UUID）"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            uuid: "1A2B-uuid".into(),
            path: "/dev/nvme0n1p2".into(),
            mapping: Some("cryptroot".into()),
        }
    }

    #[test]
    fn mkinitcpio_encrypt_fails() {
        let conf = "# HOOKS=(base systemd sd-encrypt)\nHOOKS=(base udev autodetect modconf block encrypt filesystems fsck)\n";
        assert_eq!(analyze_mkinitcpio(conf).status, Status::Fail);
    }

    #[test]
    fn mkinitcpio_sd_encrypt_ok_and_dropin_overrides() {
        let conf = "HOOKS=(base udev encrypt)\nHOOKS=(base systemd autodetect keyboard sd-vconsole block sd-encrypt filesystems)\n";
        assert_eq!(analyze_mkinitcpio(conf).status, Status::Ok);
        let conf = "HOOKS=(base sd-encrypt)";
        assert_eq!(analyze_mkinitcpio(conf).status, Status::Warn);
    }

    #[test]
    fn dracut_modules() {
        assert_eq!(
            analyze_dracut("add_dracutmodules+=\" tpm2-tss \"").status,
            Status::Ok
        );
    }

    #[test]
    fn crypttab_matching() {
        let t = "# comment\ndata UUID=1a2b-uuid none luks,discard,tpm2-device=auto\n";
        let i = analyze_crypttab(t, &target());
        assert_eq!(i.status, Status::Ok);
        let t = "other UUID=ffff none luks\n";
        assert_eq!(analyze_crypttab(t, &target()).status, Status::Info);
        let t = "cryptroot /dev/disk/by-uuid/1A2B-uuid none luks\n";
        assert!(
            analyze_crypttab(t, &target())
                .detail
                .contains("没有 tpm2-device")
        );
    }

    #[test]
    fn cmdline() {
        assert_eq!(
            analyze_cmdline("root=/dev/x cryptdevice=UUID=1:cryptroot", &target()).status,
            Status::Fail
        );
        assert_eq!(
            analyze_cmdline(
                "rd.luks.name=1a2b-uuid=root rd.luks.options=tpm2-device=auto",
                &target()
            )
            .status,
            Status::Ok
        );
        assert_eq!(analyze_cmdline("quiet", &target()).status, Status::Info);
    }
}
