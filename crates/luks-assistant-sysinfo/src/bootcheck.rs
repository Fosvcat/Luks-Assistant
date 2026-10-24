//! "Will TPM2 / FIDO2 unlocking work at boot?" — a quick, best-effort check.
//!
//! Boot setups differ wildly between distributions, so this only inspects
//! the obvious places (initramfs generator configuration, crypttab, kernel
//! command line, token plugins) and explains what it finds. It never
//! changes anything.

use crate::cmd;
use crate::t;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            t!("TPM 2.0 device"),
            Status::Ok,
            t!(
                "{} available",
                tpm.dev_node
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "tpm0".into())
            ),
        )
    } else if tpm.present {
        item(t!("TPM 2.0 device"), Status::Fail, t!("not TPM 2.0"))
    } else {
        item(t!("TPM 2.0 device"), Status::Warn, t!("No TPM detected"))
    });

    items.push(check_plugins());

    let fw = crate::firmware::Firmware::detect();
    items.push(match fw.secure_boot {
        _ if !fw.uefi => item(t!("Secure Boot"), Status::Warn, t!("Legacy BIOS")),
        Some(true) => item(t!("Secure Boot"), Status::Ok, t!("enabled")),
        Some(false) => item(t!("Secure Boot"), Status::Warn, t!("disabled")),
        None => item(
            t!("Secure Boot"),
            Status::Unknown,
            t!("Cannot read the SecureBoot variable"),
        ),
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
            t!("usually does not support systemd-cryptenroll tokens; the password is still needed at boot"),
        ));
    }
    if Path::new("/etc/booster.yaml").exists() {
        found_generator = true;
        items.push(item(
            "booster",
            Status::Info,
            t!("supports systemd-tpm2 / systemd-fido2 tokens"),
        ));
    }
    if !found_generator {
        items.push(item(
            t!("initramfs generator"),
            Status::Unknown,
            t!("not recognized"),
        ));
    }

    let crypttab = std::fs::read_to_string("/etc/crypttab").unwrap_or_default();
    items.push(analyze_crypttab(&crypttab, target));

    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    items.push(analyze_cmdline(&cmdline, target));

    items
}

/// `GRUB_ENABLE_CRYPTODISK=y` in /etc/default/grub: GRUB itself unlocks a
/// LUKS volume (usually /boot) and needs PBKDF2 key slots.
pub fn grub_cryptodisk() -> bool {
    std::fs::read_to_string("/etc/default/grub")
        .map(|t| grub_cryptodisk_in(&t))
        .unwrap_or(false)
}

pub fn grub_cryptodisk_in(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim();
        !l.starts_with('#') && l.replace(['"', '\''], "") == "GRUB_ENABLE_CRYPTODISK=y"
    })
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
            t!("cryptsetup token plugins"),
            Status::Warn,
            t!("libcryptsetup-token-systemd-*.so not found"),
        )
    } else {
        item(
            t!("cryptsetup token plugins"),
            Status::Ok,
            t!("Installed: {}", found.join(", ")),
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
        return item("mkinitcpio", Status::Unknown, t!("No HOOKS= setting found"));
    };
    let has = |h: &str| hooks.iter().any(|x| x == h);
    let list = hooks.join(" ");
    if has("sd-encrypt") {
        if has("systemd") {
            item(
                "mkinitcpio",
                Status::Ok,
                t!("systemd + sd-encrypt. HOOKS=({})", list),
            )
        } else {
            item(
                "mkinitcpio",
                Status::Warn,
                t!(
                    "sd-encrypt is present but the systemd hook is missing. HOOKS=({})",
                    list
                ),
            )
        }
    } else if has("encrypt") {
        item(
            "mkinitcpio",
            Status::Fail,
            t!(
                "The encrypt hook does not support tokens; switch to systemd + sd-encrypt. HOOKS=({})",
                list
            ),
        )
    } else {
        item(
            "mkinitcpio",
            Status::Info,
            t!("No encryption hook. HOOKS=({})", list),
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
            t!(
                "tpm2-tss module added{}",
                if has_fido {
                    t!("and the fido2 module")
                } else {
                    ""
                }
            ),
        ),
        (false, true) => item(
            "dracut",
            Status::Ok,
            t!("fido2 module added (tpm2-tss not added)"),
        ),
        (false, false) => item(
            "dracut",
            if available {
                Status::Warn
            } else {
                Status::Fail
            },
            if available {
                t!("tpm2-tss / fido2 modules not added explicitly (hostonly may include them)")
            } else {
                t!("tpm2-tss module not found")
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
                t!(
                    "Entry {} sets no tpm2-device= / fido2-device= (tokens are usually tried anyway)",
                    fields[0]
                ),
            )
        } else {
            item(
                "/etc/crypttab",
                Status::Ok,
                t!("Entry {} is configured: {}", fields[0], found.join(", ")),
            )
        };
    }
    item(
        "/etc/crypttab",
        Status::Info,
        t!("No entry for this device"),
    )
}

pub fn analyze_cmdline(cmdline: &str, target: &Target) -> Item {
    let args: Vec<&str> = cmdline.split_whitespace().collect();
    let uuid = target.uuid.to_ascii_lowercase();
    if let Some(a) = args.iter().find(|a| a.starts_with("cryptdevice=")) {
        return item(
            t!("Kernel command line"),
            Status::Fail,
            t!("{}: encrypt hook syntax, no token support", a),
        );
    }
    let luks: Vec<&&str> = args.iter().filter(|a| a.starts_with("rd.luks.")).collect();
    if luks.is_empty() {
        return item(
            t!("Kernel command line"),
            Status::Info,
            t!("No rd.luks.* options"),
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
        item(t!("Kernel command line"), Status::Ok, summary)
    } else if mentions_target {
        item(t!("Kernel command line"), Status::Info, summary)
    } else {
        item(
            t!("Kernel command line"),
            Status::Info,
            t!("{} (does not contain this device's UUID)", summary),
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
    fn grub_cryptodisk_detection() {
        assert!(grub_cryptodisk_in(
            "GRUB_TIMEOUT=5\nGRUB_ENABLE_CRYPTODISK=y\n"
        ));
        assert!(grub_cryptodisk_in("GRUB_ENABLE_CRYPTODISK=\"y\""));
        assert!(!grub_cryptodisk_in("#GRUB_ENABLE_CRYPTODISK=y"));
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
                .contains("sets no tpm2-device")
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
