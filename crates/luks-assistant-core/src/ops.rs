//! Write operations: a [`Request`] is turned into a [`Plan`] (pure — only
//! read-only commands run while planning), the plan is shown to the user
//! with its equivalent shell commands, and [`execute`] runs it.
//!
//! Every plan that modifies the header starts with a header backup.

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::exec::{Cmd, CmdOutput};
use crate::guard;
use crate::header::{self, Header, Priority};
use crate::i18n::Text;
use crate::notes::{self, KeyKind, Location, Note, NoteSet, Notes};
use crate::pcr::{self, Snapshots, Tpm2Token};
use crate::secret::Secret;
use crate::slots::{Overview, SlotKind};
use crate::tx;
use crate::util;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Proof of an existing key, needed by most operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Credential {
    Passphrase(Secret),
    Keyfile(PathBuf),
}

impl Credential {
    /// Append as cryptsetup `--key-file`.
    fn cryptsetup(&self, cmd: Cmd, label: Text) -> Cmd {
        match self {
            Credential::Passphrase(s) => cmd.arg("--key-file").secret_arg(label, s.clone()),
            Credential::Keyfile(p) => cmd.arg("--key-file").arg(p.to_string_lossy()),
        }
    }

    /// Add to a systemd-cryptenroll call.
    fn cryptenroll(&self, ctx: &Ctx, cmd: Cmd) -> Result<Cmd> {
        match self {
            Credential::Passphrase(s) => Ok(cmd.secret_env("PASSWORD", s.clone())),
            Credential::Keyfile(p) if ctx.caps.unlock_key_file => {
                Ok(cmd.arg(format!("--unlock-key-file={}", p.to_string_lossy())))
            }
            Credential::Keyfile(_) => Err(Error::Unsupported(tx!(
                "systemd < 252 不支持用密钥文件验证，请用密码"
            ))),
        }
    }

    fn check(&self) -> Result<()> {
        match self {
            Credential::Passphrase(s) if s.is_empty() => Err(Error::Invalid(tx!("请输入现有密码"))),
            Credential::Keyfile(p) if !p.is_file() => {
                Err(Error::Invalid(tx!("密钥文件不存在: {}", p.display())))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteInput {
    pub text: String,
    pub location: Location,
}

/// PBKDF for new passphrase / key file slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KdfChoice {
    /// cryptsetup default (argon2id).
    #[default]
    Default,
    /// PBKDF2, for boot loaders without Argon2 support (GRUB).
    Pbkdf2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    AddPassphrase {
        auth: Credential,
        new: Secret,
        slot: Option<u32>,
        kdf: KdfChoice,
        note: Option<NoteInput>,
    },
    AddKeyfile {
        auth: Credential,
        path: PathBuf,
        /// Create a new random key file of this many bytes first.
        generate: Option<usize>,
        slot: Option<u32>,
        kdf: KdfChoice,
        note: Option<NoteInput>,
    },
    ChangePassphrase {
        slot: u32,
        old: Credential,
        new: Secret,
        kdf: KdfChoice,
    },
    AddRecoveryKey {
        auth: Credential,
        replace: Option<u32>,
        note: Option<NoteInput>,
    },
    RemoveSlot {
        slot: u32,
        auth: Credential,
    },
    SetPriority {
        slot: u32,
        priority: Priority,
    },
    SetNote {
        slot: u32,
        text: String,
        location: Location,
    },
    EnrollTpm2 {
        auth: Credential,
        pcrs: Vec<u8>,
        pin: Option<Secret>,
        replace: Option<u32>,
        note: Option<NoteInput>,
    },
    EnrollFido2 {
        auth: Credential,
        /// Token PIN, answered automatically when no terminal is available.
        #[serde(default)]
        pin: Option<Secret>,
        client_pin: bool,
        user_presence: bool,
        user_verification: bool,
        replace: Option<u32>,
        note: Option<NoteInput>,
    },
    EnrollPkcs11 {
        auth: Credential,
        #[serde(default)]
        pin: Option<Secret>,
        uri: String,
        replace: Option<u32>,
        note: Option<NoteInput>,
    },
    /// Remove a token bound to no key slot.
    RemoveOrphanToken {
        token: u32,
    },
    /// Delete notes of slots that were removed or rewritten.
    PruneNotes,
    BackupHeader {
        dest: Option<PathBuf>,
    },
    RestoreHeader {
        file: PathBuf,
    },
    /// Persistently allow or forbid TRIM pass-through (header flag
    /// `allow-discards`). Needs the volume to be unlocked.
    SetDiscards {
        enable: bool,
        auth: Credential,
    },
    /// Re-encrypt a PBKDF2 key slot with Argon2id.
    ConvertKdf {
        slot: u32,
        auth: Credential,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Danger {
    Normal,
    High,
    Critical,
}

/// A slot referenced by a step: fixed, or the one created earlier in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotRef {
    Fixed(u32),
    New,
}

#[derive(Debug, Clone)]
pub enum KindUpdate {
    Keep,
    Set(Option<KeyKind>),
}

#[derive(Debug, Clone)]
pub enum Action {
    EnsurePrivateDir(PathBuf),
    GenerateKeyfile {
        path: PathBuf,
        bytes: usize,
    },
    /// Create/replace/delete the note of a slot. Empty text with no kind removes it.
    SetNote {
        slot: SlotRef,
        text: Option<String>,
        kind: KindUpdate,
        location: Location,
    },
    /// Re-attach the note of `from` to the (possibly new) slot after its key changed.
    RebindNote {
        from: u32,
        to: SlotRef,
        kind: Option<KeyKind>,
    },
    DropNote {
        slot: u32,
    },
    PruneStaleNotes,
    ExpectDiscards(bool),
    SavePcrSnapshot {
        slot: SlotRef,
    },
    ExpectSlot {
        slot: SlotRef,
        present: bool,
    },
}

#[derive(Debug, Clone)]
pub enum Step {
    Run {
        desc: Text,
        cmd: Cmd,
        creates_slot: bool,
    },
    Internal {
        desc: Text,
        action: Action,
    },
}

impl Step {
    fn run(desc: impl Into<Text>, cmd: Cmd) -> Step {
        Step::Run {
            desc: desc.into(),
            cmd,
            creates_slot: false,
        }
    }

    fn run_new(desc: impl Into<Text>, cmd: Cmd) -> Step {
        Step::Run {
            desc: desc.into(),
            cmd,
            creates_slot: true,
        }
    }

    fn internal(desc: impl Into<Text>, action: Action) -> Step {
        Step::Internal {
            desc: desc.into(),
            action,
        }
    }

    pub fn desc(&self) -> &Text {
        match self {
            Step::Run { desc, .. } | Step::Internal { desc, .. } => desc,
        }
    }

    /// Equivalent shell command, if the step is a command.
    pub fn command(&self) -> Option<String> {
        self.command_in(crate::i18n::lang())
    }

    pub fn command_in(&self, lang: crate::i18n::Lang) -> Option<String> {
        match self {
            Step::Run { cmd, .. } => Some(cmd.display_in(lang)),
            Step::Internal { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub title: Text,
    pub device: PathBuf,
    pub steps: Vec<Step>,
    pub warnings: Vec<Text>,
    pub danger: Danger,
    /// Text the user must type to confirm, for critical plans.
    pub confirm_word: Option<String>,
    pub backup_file: Option<PathBuf>,
}

impl Plan {
    pub fn commands(&self) -> Vec<String> {
        self.steps.iter().filter_map(Step::command).collect()
    }

    pub fn is_interactive(&self) -> bool {
        self.steps
            .iter()
            .any(|s| matches!(s, Step::Run { cmd, .. } if cmd.interactive))
    }
}

struct Builder<'a> {
    ctx: &'a Ctx,
    ov: &'a Overview,
    dev: String,
    plan: Plan,
}

impl<'a> Builder<'a> {
    fn new(ctx: &'a Ctx, ov: &'a Overview, title: impl Into<Text>) -> Self {
        Builder {
            ctx,
            ov,
            dev: ov.device.path.to_string_lossy().into_owned(),
            plan: Plan {
                title: title.into(),
                device: ov.device.path.clone(),
                steps: Vec::new(),
                warnings: Vec::new(),
                danger: Danger::Normal,
                confirm_word: None,
                backup_file: None,
            },
        }
    }

    fn cryptsetup(&self, sub: &str) -> Cmd {
        Cmd::new("cryptsetup").arg(sub).arg(&self.dev)
    }

    fn cryptenroll(&self) -> Result<Cmd> {
        if !self.ctx.caps.cryptenroll {
            return Err(Error::Unsupported(tx!(
                "需要 systemd-cryptenroll (systemd ≥ 248)"
            )));
        }
        Ok(Cmd::new("systemd-cryptenroll").arg(&self.dev))
    }

    /// `luksAddKey` targeting slot `n`.
    fn add_key(&self, n: u32) -> Cmd {
        let flag = if self.ctx.caps.new_key_slot {
            "--new-key-slot"
        } else {
            "--key-slot"
        };
        self.cryptsetup("luksAddKey").arg(flag).arg(n.to_string())
    }

    fn kdf_args(&self, cmd: Cmd, kdf: KdfChoice) -> Cmd {
        let cmd = match kdf {
            KdfChoice::Default => cmd,
            KdfChoice::Pbkdf2 => cmd.args(["--pbkdf", "pbkdf2"]),
        };
        cmd.args(self.ctx.extra_kdf_args.iter().cloned())
    }

    /// Start with a header backup into Luks Assistant's state directory.
    fn backup(&mut self, tag: &str) {
        let dir = self.ctx.paths.backups_dir(self.ov.uuid());
        let file = unique_backup_path(&dir, tag);
        self.plan.steps.push(Step::internal(
            tx!("创建备份目录 {}", dir.display()),
            Action::EnsurePrivateDir(dir),
        ));
        self.plan.steps.push(Step::run(
            tx!("备份 LUKS 头部"),
            self.cryptsetup("luksHeaderBackup")
                .arg("--header-backup-file")
                .arg(file.to_string_lossy()),
        ));
        self.plan.backup_file = Some(file);
    }

    fn step(&mut self, s: Step) {
        self.plan.steps.push(s);
    }

    fn warn(&mut self, w: impl IntoIterator<Item = Text>) {
        for m in w {
            if !self.plan.warnings.contains(&m) {
                self.plan.warnings.push(m);
            }
        }
    }

    fn note(
        &mut self,
        slot: SlotRef,
        note: Option<&NoteInput>,
        kind: Option<KeyKind>,
    ) -> Result<()> {
        let (text, location) = match note {
            Some(n) => {
                notes::validate_text(&n.text)?;
                (n.text.clone(), n.location)
            }
            None => (String::new(), Location::Header),
        };
        if text.is_empty() && kind.is_none() {
            return Ok(());
        }
        let desc = if text.is_empty() {
            tx!(
                "在头部记录槽位类型（{}）",
                kind.map(KeyKind::text).unwrap_or_else(|| Text::plain(""))
            )
        } else {
            tx!("保存备注“{}”（{}）", text, location.text())
        };
        self.step(Step::internal(
            desc,
            Action::SetNote {
                slot,
                text: Some(text),
                kind: KindUpdate::Set(kind),
                location,
            },
        ));
        Ok(())
    }

    fn expect(&mut self, slot: SlotRef, present: bool) {
        let desc = match (slot, present) {
            (SlotRef::Fixed(n), true) => tx!("验证槽位 {} 已存在", n),
            (SlotRef::Fixed(n), false) => tx!("验证槽位 {} 已删除", n),
            (SlotRef::New, _) => tx!("验证新槽位已写入"),
        };
        self.step(Step::internal(desc, Action::ExpectSlot { slot, present }));
    }

    fn finish(self) -> Plan {
        self.plan
    }
}

fn unique_backup_path(dir: &Path, tag: &str) -> PathBuf {
    let base = format!("{}-{tag}", util::stamp(util::now_unix()));
    let mut p = dir.join(format!("{base}.img"));
    let mut i = 1;
    while p.exists() {
        p = dir.join(format!("{base}-{i}.img"));
        i += 1;
    }
    p
}

/// Check that `cred` opens some slot and return which one. Read-only.
pub fn verify_credential(ctx: &Ctx, device: &Path, cred: &Credential) -> Result<u32> {
    cred.check()?;
    let cmd = Cmd::new("cryptsetup")
        .args([
            "open",
            "--test-passphrase",
            "--disable-external-tokens",
            "-v",
        ])
        .arg(device.to_string_lossy());
    let cmd = cred.cryptsetup(cmd, tx!("密码"));
    let out = ctx.runner.run(&cmd)?;
    let text = format!("{}\n{}", out.stdout_lossy(), out.stderr);
    if !out.success() {
        return Err(Error::Invalid(tx!("密码或密钥文件不正确")));
    }
    parse_unlocked_slot(&text).ok_or_else(|| Error::Parse(tx!("cryptsetup 没有报告解锁的槽位")))
}

fn parse_unlocked_slot(text: &str) -> Option<u32> {
    text.lines().find_map(|l| {
        l.trim()
            .strip_prefix("Key slot ")
            .and_then(|r| r.strip_suffix(" unlocked."))
            .and_then(|n| n.trim().parse().ok())
    })
}

/// Hardware/token unlock methods that can be verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    Tpm2,
    Fido2,
    Pkcs11,
}

impl TokenKind {
    pub fn token_type(self) -> &'static str {
        match self {
            TokenKind::Tpm2 => "systemd-tpm2",
            TokenKind::Fido2 => "systemd-fido2",
            TokenKind::Pkcs11 => "systemd-pkcs11",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TokenKind::Tpm2 => "TPM2",
            TokenKind::Fido2 => "FIDO2",
            TokenKind::Pkcs11 => "PKCS#11",
        }
    }
}

/// One token unlock test (`cryptsetup open --test-passphrase --token-only`).
#[derive(Debug, Clone)]
pub struct TokenTest {
    pub token: u32,
    pub slots: Vec<u32>,
    pub cmd: Cmd,
}

/// Tests for every token of `kind`, in token order. Nothing is activated.
///
/// Tokens that may prompt (FIDO2, PKCS#11, TPM2+PIN) are interactive: a
/// terminal frontend hands over its terminal, the helper answers `pin`
/// on a pseudo-terminal.
pub fn token_tests(ov: &Overview, kind: TokenKind, pin: Option<&Secret>) -> Vec<TokenTest> {
    token_cmds(ov, kind, pin, None)
}

/// Like [`token_tests`], but each command really opens the volume as `name`.
pub fn token_unlocks(
    ov: &Overview,
    kind: TokenKind,
    pin: Option<&Secret>,
    name: &str,
) -> Vec<TokenTest> {
    token_cmds(ov, kind, pin, Some(name))
}

fn token_cmds(
    ov: &Overview,
    kind: TokenKind,
    pin: Option<&Secret>,
    open_as: Option<&str>,
) -> Vec<TokenTest> {
    ov.header
        .tokens
        .values()
        .filter(|t| t.kind == kind.token_type() && !t.keyslots.is_empty())
        .map(|t| {
            let mut cmd = Cmd::new("cryptsetup").arg("open");
            if open_as.is_none() {
                cmd = cmd.arg("--test-passphrase");
            }
            cmd = cmd
                .args(["--token-only", "-v", "--token-id"])
                .arg(t.id.to_string())
                .arg(ov.device.path.to_string_lossy());
            if let Some(name) = open_as {
                cmd = cmd.arg(name);
            }
            let may_prompt = match kind {
                TokenKind::Tpm2 => Tpm2Token::from_token(t).is_some_and(|x| x.pin),
                _ => true,
            };
            if may_prompt {
                cmd = cmd.interactive();
                if let Some(p) = pin {
                    cmd = cmd.answer("pin", p.clone());
                }
            }
            TokenTest {
                token: t.id,
                slots: t.keyslots.clone(),
                cmd,
            }
        })
        .collect()
}

/// Name for a new mapping of the volume (systemd's `luks-<UUID>`).
pub fn mapping_name(ov: &Overview) -> String {
    format!("luks-{}", ov.header.uuid)
}

fn check_unlockable(ov: &Overview) -> Result<()> {
    if let Some(m) = &ov.device.mapping {
        return Err(Error::Invalid(tx!("已经解锁（{}）", m)));
    }
    Ok(())
}

/// `cryptsetup open` with a password or key file.
pub fn unlock_cmd(ov: &Overview, cred: &Credential) -> Result<Cmd> {
    check_unlockable(ov)?;
    let cmd = Cmd::new("cryptsetup")
        .arg("open")
        .arg(ov.device.path.to_string_lossy())
        .arg(mapping_name(ov));
    Ok(cred.cryptsetup(cmd, tx!("密码")))
}

/// Token unlocks for [`token_unlocks`], after the same checks as [`unlock_cmd`].
pub fn token_unlock_cmds(
    ov: &Overview,
    kind: TokenKind,
    pin: Option<&Secret>,
) -> Result<Vec<TokenTest>> {
    check_unlockable(ov)?;
    Ok(token_unlocks(ov, kind, pin, &mapping_name(ov)))
}

/// `cryptsetup close`. The volume of the running system cannot be locked.
pub fn lock_cmd(ov: &Overview) -> Result<Cmd> {
    let Some(m) = &ov.device.mapping else {
        return Err(Error::Invalid(tx!("卷没有解锁")));
    };
    if ov.device.holds_root() {
        return Err(Error::Blocked(tx!("这是当前系统所在的卷，不能锁定")));
    }
    Ok(Cmd::new("cryptsetup").arg("close").arg(m))
}

/// Why a token test failed, from cryptsetup's messages.
pub fn token_failure(out: &CmdOutput) -> Text {
    let text = format!("{}\n{}", String::from_utf8_lossy(&out.stdout), out.stderr);
    if text.contains("requires additional missing resource") {
        return tx!("找不到所需设备（TPM 或安全密钥）");
    }
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    lines
        .iter()
        .rev()
        .find(|l| !l.starts_with("Command failed"))
        .or(lines.last())
        .map(|l| Text::plain(*l))
        .unwrap_or_else(|| Text::plain(""))
}

fn check_tpm(ctx: &Ctx) -> Result<()> {
    if ctx.tpm2_device != "auto" {
        return Ok(());
    }
    let tpm = luks_assistant_sysinfo::tpm::TpmInfo::detect();
    if tpm.is_tpm2() {
        Ok(())
    } else {
        Err(Error::Blocked(tx!("没有检测到可用的 TPM 2.0 设备")))
    }
}

/// Turn a request into a plan, enforcing the guards.
pub fn plan(ctx: &Ctx, ov: &Overview, req: &Request) -> Result<Plan> {
    use Request::*;
    match req {
        BackupHeader { dest } => {
            let mut b = Builder::new(ctx, ov, tx!("备份 LUKS 头部"));
            match dest {
                Some(d) => {
                    if d.exists() {
                        return Err(Error::Invalid(tx!("{} 已存在", d.display())));
                    }
                    b.step(Step::run(
                        tx!("备份 LUKS 头部"),
                        b.cryptsetup("luksHeaderBackup")
                            .arg("--header-backup-file")
                            .arg(d.to_string_lossy()),
                    ));
                    b.plan.backup_file = Some(d.clone());
                }
                None => b.backup("manual"),
            }
            b.warn([tx!("备份文件加上任一旧密码即可解密数据，请妥善保管")]);
            return Ok(b.finish());
        }
        RestoreHeader { file } => return plan_restore(ctx, ov, file),
        _ => {}
    }

    guard::ensure_writable(ov)?;
    match req {
        AddPassphrase {
            auth,
            new,
            slot,
            kdf,
            note,
        } => {
            auth.check()?;
            let n = guard::free_slot(ov, *slot)?;
            let mut b = Builder::new(ctx, ov, tx!("在槽位 {} 添加密码", n));
            b.warn(guard::check_new_passphrase(new)?);
            if *kdf == KdfChoice::Pbkdf2 {
                b.warn([tx!("PBKDF2 抗暴力破解能力弱于 Argon2id")]);
            }
            b.backup("add-passphrase");
            let cmd = b.add_key(n);
            let cmd = b.kdf_args(cmd, *kdf);
            let cmd = auth
                .cryptsetup(cmd, tx!("现有密码"))
                .secret_arg(tx!("新密码"), new.clone());
            b.step(Step::run(tx!("写入新密码到槽位 {}", n), cmd));
            b.expect(SlotRef::Fixed(n), true);
            b.note(SlotRef::Fixed(n), note.as_ref(), Some(KeyKind::Passphrase))?;
            Ok(b.finish())
        }
        AddKeyfile {
            auth,
            path,
            generate,
            slot,
            kdf,
            note,
        } => {
            auth.check()?;
            let n = guard::free_slot(ov, *slot)?;
            let mut b = Builder::new(ctx, ov, tx!("在槽位 {} 添加密钥文件", n));
            match generate {
                Some(bytes) => {
                    if path.exists() {
                        return Err(Error::Invalid(tx!("{} 已存在", path.display())));
                    }
                    if !(16..=8 * 1024 * 1024).contains(bytes) {
                        return Err(Error::Invalid(tx!("密钥文件大小应在 16 字节到 8 MiB 之间")));
                    }
                    b.warn([tx!(
                        "将生成新密钥文件 {}（权限 0400）。请把它备份到安全的位置",
                        path.display()
                    )]);
                }
                None => b.warn(check_keyfile(path)?),
            }
            b.backup("add-keyfile");
            if let Some(bytes) = generate {
                b.step(Step::internal(
                    tx!("生成 {} 字节随机密钥文件 {}", bytes, path.display()),
                    Action::GenerateKeyfile {
                        path: path.clone(),
                        bytes: *bytes,
                    },
                ));
            }
            let cmd = b.add_key(n);
            let cmd = b.kdf_args(cmd, *kdf);
            let cmd = auth
                .cryptsetup(cmd, tx!("现有密码"))
                .arg(path.to_string_lossy());
            b.step(Step::run(tx!("把密钥文件写入槽位 {}", n), cmd));
            b.expect(SlotRef::Fixed(n), true);
            let default_note = NoteInput {
                text: default_keyfile_note(path),
                location: Location::Header,
            };
            let note = match note {
                Some(n) if !n.text.is_empty() => n.clone(),
                Some(n) => NoteInput {
                    location: n.location,
                    ..default_note
                },
                None => default_note,
            };
            b.note(SlotRef::Fixed(n), Some(&note), Some(KeyKind::Keyfile))?;
            Ok(b.finish())
        }
        ChangePassphrase {
            slot,
            old,
            new,
            kdf,
        } => {
            old.check()?;
            let s = ov
                .slot(*slot)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::Invalid(tx!("槽位 {} 是空的", slot)))?;
            if !s.kind.is_plain() {
                return Err(Error::Blocked(tx!(
                    "槽位 {} 是“{}”，只能修改密码/密钥文件槽位",
                    slot,
                    s.kind.text()
                )));
            }
            let mut b = Builder::new(ctx, ov, tx!("修改槽位 {} 的密码", slot));
            b.warn(guard::check_new_passphrase(new)?);
            b.backup("change-passphrase");
            let cmd = b
                .cryptsetup("luksChangeKey")
                .arg("--key-slot")
                .arg(slot.to_string());
            let cmd = b.kdf_args(cmd, *kdf);
            let cmd = old
                .cryptsetup(cmd, tx!("旧密码"))
                .secret_arg(tx!("新密码"), new.clone());
            b.step(Step::run_new(tx!("用新密码替换槽位 {}", slot), cmd));
            b.step(Step::internal(
                tx!("更新备注以对应新的密钥材料"),
                Action::RebindNote {
                    from: *slot,
                    to: SlotRef::New,
                    kind: Some(KeyKind::Passphrase),
                },
            ));
            Ok(b.finish())
        }
        AddRecoveryKey {
            auth,
            replace,
            note,
        } => {
            auth.check()?;
            if let Some(r) = replace {
                guard::check_replace(ov, *r, &SlotKind::Recovery)?;
            } else {
                guard::ensure_any_free(ov)?;
            }
            let mut b = Builder::new(
                ctx,
                ov,
                if replace.is_some() {
                    tx!("重新生成恢复密钥")
                } else {
                    tx!("生成恢复密钥")
                },
            );
            b.warn([tx!("恢复密钥只显示一次")]);
            b.backup("recovery-key");
            let mut cmd = auth.cryptenroll(ctx, b.cryptenroll()?.arg("--recovery-key"))?;
            if let Some(r) = replace {
                cmd = cmd.arg(format!("--wipe-slot={r}"));
                b.plan.danger = Danger::High;
            }
            b.step(Step::run_new(
                tx!("生成并写入恢复密钥"),
                cmd.secret_stdout(),
            ));
            b.expect(SlotRef::New, true);
            if let Some(r) = replace {
                b.expect(SlotRef::Fixed(*r), false);
                b.step(Step::internal(
                    tx!("删除槽位 {} 的备注", r),
                    Action::DropNote { slot: *r },
                ));
            }
            b.note(SlotRef::New, note.as_ref(), None)?;
            Ok(b.finish())
        }
        RemoveSlot { slot, auth } => {
            let auth_slot = verify_credential(ctx, &ov.device.path, auth)?;
            let warnings = guard::check_removal(ov, *slot, Some(auth_slot))?;
            let s = ov.slot(*slot).expect("checked");
            let mut b = Builder::new(ctx, ov, tx!("删除槽位 {}（{}）", slot, s.kind.text()));
            b.warn(warnings);
            b.plan.danger = Danger::Critical;
            b.plan.confirm_word = Some(slot.to_string());
            b.backup(&format!("remove-slot{slot}"));
            let shared = ov.header.tokens_for(*slot).any(|t| t.keyslots.len() > 1);
            let systemd_token = ov
                .header
                .tokens_for(*slot)
                .any(|t| t.kind.starts_with("systemd-"));
            if systemd_token && !shared && ctx.caps.cryptenroll {
                b.step(Step::run(
                    tx!("擦除槽位 {} 及其令牌", slot),
                    b.cryptenroll()?.arg(format!("--wipe-slot={slot}")),
                ));
            } else {
                b.step(Step::run(
                    tx!("擦除槽位 {}", slot),
                    b.cryptsetup("luksKillSlot").arg(slot.to_string()).arg("-q"),
                ));
                // cryptsetup leaves tokens behind with an empty keyslot list.
                for t in ov
                    .header
                    .tokens_for(*slot)
                    .filter(|t| t.keyslots == [*slot])
                {
                    b.step(Step::run(
                        tx!("删除遗留令牌 {}（{}）", t.id, t.kind),
                        Cmd::new("cryptsetup")
                            .args(["token", "remove", "--token-id"])
                            .arg(t.id.to_string())
                            .arg(&b.dev),
                    ));
                }
            }
            b.expect(SlotRef::Fixed(*slot), false);
            if s.note.is_some()
                || ov.notes.header.get(*slot).is_some()
                || ov.notes.local.get(*slot).is_some()
            {
                b.step(Step::internal(
                    tx!("删除槽位 {} 的备注", slot),
                    Action::DropNote { slot: *slot },
                ));
            }
            Ok(b.finish())
        }
        SetPriority { slot, priority } => {
            let w = guard::check_priority(ov, *slot, *priority)?;
            let mut b = Builder::new(
                ctx,
                ov,
                tx!("把槽位 {} 的优先级设为“{}”", slot, priority.text()),
            );
            b.warn(w);
            b.backup("priority");
            b.step(Step::run(
                tx!("修改优先级"),
                b.cryptsetup("config")
                    .arg("--key-slot")
                    .arg(slot.to_string())
                    .arg("--priority")
                    .arg(priority.as_arg()),
            ));
            Ok(b.finish())
        }
        SetNote {
            slot,
            text,
            location,
        } => {
            notes::validate_text(text)?;
            if ov.slot(*slot).is_none_or(|s| s.is_empty()) {
                return Err(Error::Invalid(tx!("槽位 {} 是空的", slot)));
            }
            let mut b = Builder::new(ctx, ov, tx!("编辑槽位 {} 的备注", slot));
            let touches_header =
                *location == Location::Header || ov.notes.header.get(*slot).is_some();
            if touches_header {
                b.backup("note");
            }
            if *location == Location::Header && !text.is_empty() {
                b.warn([tx!("头部未加密，备注对任何人可见")]);
            }
            let desc = if text.is_empty() {
                tx!("删除备注")
            } else {
                tx!("保存备注“{}”（{}）", text, location.text())
            };
            b.step(Step::internal(
                desc,
                Action::SetNote {
                    slot: SlotRef::Fixed(*slot),
                    text: Some(text.clone()),
                    kind: KindUpdate::Keep,
                    location: *location,
                },
            ));
            Ok(b.finish())
        }
        EnrollTpm2 {
            auth,
            pcrs,
            pin,
            replace,
            note,
        } => {
            auth.check()?;
            check_tpm(ctx)?;
            if let Some(r) = replace {
                guard::check_replace(ov, *r, &SlotKind::Tpm2)?;
            } else {
                guard::ensure_any_free(ov)?;
            }
            let mut pcrs = pcrs.clone();
            pcrs.sort();
            pcrs.dedup();
            if pcrs.iter().any(|&p| p > 23) {
                return Err(Error::Invalid(tx!("PCR 编号必须在 0-23 之间")));
            }
            let title = match replace {
                Some(r) => tx!(
                    "重新录入 TPM2（替换槽位 {}，PCR {}）",
                    r,
                    pcr::format_list(&pcrs)
                ),
                None => tx!("录入 TPM2（PCR {}）", pcr::format_list(&pcrs)),
            };
            let mut b = Builder::new(ctx, ov, title);
            let sb = luks_assistant_sysinfo::firmware::Firmware::detect().secure_boot;
            b.warn(pcr::selection_warnings(&pcrs, sb));
            b.warn(guard::token_only_warning(ov));
            b.backup("tpm2");
            let mut cmd = auth.cryptenroll(ctx, b.cryptenroll()?)?;
            cmd = cmd
                .arg(format!("--tpm2-device={}", ctx.tpm2_device))
                .arg(format!("--tpm2-pcrs={}", pcr::format_list(&pcrs)));
            if let Some(p) = pin {
                if !ctx.caps.tpm2_pin {
                    return Err(Error::Unsupported(tx!("TPM2 + PIN 需要 systemd ≥ 251")));
                }
                if p.is_empty() {
                    return Err(Error::Invalid(tx!("PIN 不能为空")));
                }
                b.warn(
                    guard::check_new_passphrase(p)?
                        .into_iter()
                        .filter(|w| w.en().contains("ASCII")),
                );
                cmd = cmd
                    .arg("--tpm2-with-pin=yes")
                    .secret_env("NEWPIN", p.clone());
            }
            if let Some(r) = replace {
                cmd = cmd.arg(format!("--wipe-slot={r}"));
                b.plan.danger = Danger::High;
            }
            b.step(Step::run_new(tx!("录入 TPM2 令牌"), cmd));
            b.expect(SlotRef::New, true);
            if let Some(r) = replace {
                b.expect(SlotRef::Fixed(*r), false);
                b.step(Step::internal(
                    tx!("删除槽位 {} 的备注", r),
                    Action::DropNote { slot: *r },
                ));
            }
            b.step(Step::internal(
                tx!("记录当前 PCR 值作为基准"),
                Action::SavePcrSnapshot { slot: SlotRef::New },
            ));
            let carried = carry_note(ov, *replace, note.as_ref());
            b.note(SlotRef::New, carried.as_ref(), None)?;
            Ok(b.finish())
        }
        EnrollFido2 {
            auth,
            pin,
            client_pin,
            user_presence,
            user_verification,
            replace,
            note,
        } => {
            auth.check()?;
            if let Some(r) = replace {
                guard::check_replace(ov, *r, &SlotKind::Fido2)?;
            } else {
                guard::ensure_any_free(ov)?;
            }
            let mut b = Builder::new(
                ctx,
                ov,
                if replace.is_some() {
                    tx!("重新录入 FIDO2 安全密钥")
                } else {
                    tx!("录入 FIDO2 安全密钥")
                },
            );
            b.warn(guard::token_only_warning(ov));
            b.warn([tx!("执行时请触摸安全密钥")]);
            b.backup("fido2");
            let mut cmd = auth
                .cryptenroll(ctx, b.cryptenroll()?)?
                .arg("--fido2-device=auto");
            if ctx.caps.fido2_options {
                let yn = |v: bool| if v { "yes" } else { "no" };
                cmd = cmd
                    .arg(format!("--fido2-with-client-pin={}", yn(*client_pin)))
                    .arg(format!("--fido2-with-user-presence={}", yn(*user_presence)))
                    .arg(format!(
                        "--fido2-with-user-verification={}",
                        yn(*user_verification)
                    ));
            }
            if let Some(r) = replace {
                cmd = cmd.arg(format!("--wipe-slot={r}"));
                b.plan.danger = Danger::High;
            }
            if let Some(p) = pin {
                cmd = cmd.answer("pin", p.clone());
            }
            b.step(Step::run_new(tx!("录入 FIDO2 令牌"), cmd.interactive()));
            b.expect(SlotRef::New, true);
            if let Some(r) = replace {
                b.expect(SlotRef::Fixed(*r), false);
                b.step(Step::internal(
                    tx!("删除槽位 {} 的备注", r),
                    Action::DropNote { slot: *r },
                ));
            }
            let carried = carry_note(ov, *replace, note.as_ref());
            b.note(SlotRef::New, carried.as_ref(), None)?;
            Ok(b.finish())
        }
        EnrollPkcs11 {
            auth,
            pin,
            uri,
            replace,
            note,
        } => {
            auth.check()?;
            if let Some(r) = replace {
                guard::check_replace(ov, *r, &SlotKind::Pkcs11)?;
            } else {
                guard::ensure_any_free(ov)?;
            }
            let uri = if uri.trim().is_empty() {
                "auto".to_owned()
            } else {
                uri.trim().to_owned()
            };
            let mut b = Builder::new(ctx, ov, tx!("录入 PKCS#11 智能卡"));
            b.warn(guard::token_only_warning(ov));
            b.backup("pkcs11");
            let mut cmd = auth
                .cryptenroll(ctx, b.cryptenroll()?)?
                .arg(format!("--pkcs11-token-uri={uri}"));
            if let Some(r) = replace {
                cmd = cmd.arg(format!("--wipe-slot={r}"));
                b.plan.danger = Danger::High;
            }
            if let Some(p) = pin {
                cmd = cmd.answer("pin", p.clone());
            }
            b.step(Step::run_new(tx!("录入 PKCS#11 令牌"), cmd.interactive()));
            b.expect(SlotRef::New, true);
            if let Some(r) = replace {
                b.expect(SlotRef::Fixed(*r), false);
                b.step(Step::internal(
                    tx!("删除槽位 {} 的备注", r),
                    Action::DropNote { slot: *r },
                ));
            }
            let carried = carry_note(ov, *replace, note.as_ref());
            b.note(SlotRef::New, carried.as_ref(), None)?;
            Ok(b.finish())
        }
        RemoveOrphanToken { token } => {
            let t = ov
                .header
                .tokens
                .get(token)
                .ok_or_else(|| Error::Invalid(tx!("令牌 {} 不存在", token)))?;
            if !t.keyslots.is_empty() {
                return Err(Error::Blocked(tx!(
                    "令牌 {} 仍关联槽位 {}",
                    token,
                    format!("{:?}", t.keyslots)
                )));
            }
            if notes::is_notes_token(&t.kind) {
                return Err(Error::Blocked(tx!("这是 Luks Assistant 的备注令牌")));
            }
            let mut b = Builder::new(ctx, ov, tx!("删除孤立令牌 {}（{}）", token, t.kind));
            b.backup(&format!("remove-token{token}"));
            b.step(Step::run(
                tx!("删除令牌"),
                Cmd::new("cryptsetup")
                    .args(["token", "remove", "--token-id"])
                    .arg(token.to_string())
                    .arg(&b.dev),
            ));
            Ok(b.finish())
        }
        PruneNotes => {
            let stale = ov.notes.stale(&ov.header);
            if stale.is_empty() {
                return Err(Error::Invalid(tx!("没有过期的备注")));
            }
            let mut b = Builder::new(ctx, ov, tx!("清理过期备注"));
            if stale.iter().any(|(l, _)| *l == Location::Header) {
                b.backup("prune-notes");
            }
            let list = stale
                .iter()
                .map(|(l, s)| tx!("槽位 {}（{}）", s, l.text()))
                .collect::<Vec<_>>();
            let list = Text::join(list, tx!("、"));
            b.step(Step::internal(
                tx!("删除 {} 的备注", list),
                Action::PruneStaleNotes,
            ));
            Ok(b.finish())
        }
        SetDiscards { enable, auth } => {
            auth.check()?;
            let Some(mapping) = ov.device.mapping.clone() else {
                return Err(Error::Blocked(tx!("卷未解锁，无法写入 TRIM 标志")));
            };
            if ov.header.allows_discards() == *enable {
                return Err(Error::Invalid(tx!(
                    "TRIM 穿透已经是{}状态",
                    if *enable {
                        tx!("开启")
                    } else {
                        tx!("关闭")
                    }
                )));
            }
            let mut b = Builder::new(
                ctx,
                ov,
                if *enable {
                    tx!("开启 TRIM 穿透（写入头部）")
                } else {
                    tx!("关闭 TRIM 穿透（写入头部）")
                },
            );
            if *enable {
                b.warn([tx!("TRIM 会暴露已用空间和文件系统类型")]);
                b.warn([tx!(
                    "mkinitcpio encrypt 钩子不读取此标志，仍需启动参数 :allow-discards"
                )]);
            }
            b.backup("discards");
            let mut cmd = Cmd::new("cryptsetup").arg("refresh").arg(&mapping);
            if *enable {
                cmd = cmd.arg("--allow-discards");
            }
            let cmd = auth.cryptsetup(cmd.arg("--persistent"), tx!("现有密码"));
            b.step(Step::run(tx!("刷新映射并写入持久标志"), cmd));
            b.step(Step::internal(
                tx!("验证头部标志"),
                Action::ExpectDiscards(*enable),
            ));
            Ok(b.finish())
        }
        ConvertKdf { slot, auth } => {
            auth.check()?;
            let s = ov
                .slot(*slot)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::Invalid(tx!("槽位 {} 是空的", slot)))?;
            if !s.kind.is_plain() {
                return Err(Error::Blocked(tx!(
                    "槽位 {} 是“{}”，令牌槽位不需要转换",
                    slot,
                    s.kind.text()
                )));
            }
            let kdf = &s.keyslot.as_ref().expect("used slot").kdf;
            if kdf.kind != "pbkdf2" {
                return Err(Error::Invalid(tx!("槽位 {} 已经是 {}", slot, kdf.kind)));
            }
            let mut b = Builder::new(ctx, ov, tx!("把槽位 {} 转换为 Argon2id", slot));
            if luks_assistant_sysinfo::bootcheck::grub_cryptodisk() {
                b.warn([tx!("检测到 GRUB_ENABLE_CRYPTODISK=y：GRUB 2.12 之前不支持 Argon2，若 GRUB 用此槽位解锁将无法启动")]);
                b.plan.danger = Danger::High;
            }
            b.backup(&format!("convert-slot{slot}"));
            let mut cmd = b
                .cryptsetup("luksConvertKey")
                .arg("--key-slot")
                .arg(slot.to_string())
                .args(["--pbkdf", "argon2id"]);
            if ctx
                .extra_kdf_args
                .iter()
                .any(|a| a == "--pbkdf-force-iterations")
            {
                cmd = cmd.args(["--pbkdf-force-iterations", "4", "--pbkdf-memory", "32"]);
            }
            let cmd = auth.cryptsetup(cmd, tx!("该槽位的密码"));
            b.step(Step::run(tx!("转换槽位 {}", slot), cmd));
            b.expect(SlotRef::Fixed(*slot), true);
            b.step(Step::internal(
                tx!("更新备注指纹"),
                Action::RebindNote {
                    from: *slot,
                    to: SlotRef::Fixed(*slot),
                    kind: None,
                },
            ));
            Ok(b.finish())
        }
        BackupHeader { .. } | RestoreHeader { .. } => unreachable!("handled above"),
    }
}

/// Keep the note of a replaced slot unless a new one was given.
fn carry_note(ov: &Overview, replace: Option<u32>, note: Option<&NoteInput>) -> Option<NoteInput> {
    if let Some(n) = note.filter(|n| !n.text.is_empty()) {
        return Some(n.clone());
    }
    let old = replace
        .and_then(|r| ov.slot(r))
        .and_then(|s| s.note.as_ref())?;
    Some(NoteInput {
        text: old.note.text.clone(),
        location: old.location,
    })
}

fn default_keyfile_note(path: &Path) -> String {
    let full = path.to_string_lossy();
    if full.chars().count() <= notes::MAX_NOTE_CHARS {
        full.into_owned()
    } else {
        path.file_name()
            .map(|n| {
                n.to_string_lossy()
                    .chars()
                    .take(notes::MAX_NOTE_CHARS)
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn check_keyfile(path: &Path) -> Result<Vec<Text>> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::Invalid(format!("{}: {e}", path.display()).into()))?;
    if !meta.is_file() {
        return Err(Error::Invalid(tx!("{} 不是普通文件", path.display())));
    }
    if meta.len() == 0 {
        return Err(Error::Invalid(tx!("密钥文件是空的")));
    }
    if meta.len() > 8 * 1024 * 1024 {
        return Err(Error::Invalid(tx!(
            "密钥文件超过 cryptsetup 默认上限 8 MiB"
        )));
    }
    let mut w = Vec::new();
    if meta.permissions().mode() & 0o077 != 0 {
        w.push(tx!("{} 对其他用户可读", path.display()));
    }
    Ok(w)
}

fn plan_restore(ctx: &Ctx, ov: &Overview, file: &Path) -> Result<Plan> {
    if !file.is_file() {
        return Err(Error::Invalid(tx!("{} 不存在", file.display())));
    }
    let out = ctx.runner.run(
        &Cmd::new("cryptsetup")
            .arg("luksUUID")
            .arg(file.to_string_lossy()),
    )?;
    if !out.success() {
        return Err(Error::Invalid(tx!("{} 不是 LUKS 头部备份", file.display())));
    }
    let uuid = out.stdout_lossy().trim().to_owned();
    if uuid != ov.header.uuid {
        return Err(Error::Blocked(tx!(
            "备份 UUID ({}) 与设备 ({}) 不一致",
            uuid,
            ov.header.uuid
        )));
    }
    let mut b = Builder::new(ctx, ov, tx!("从 {} 恢复 LUKS 头部", file.display()));
    b.plan.danger = Danger::Critical;
    b.plan.confirm_word = Some("RESTORE".into());
    b.warn([
        tx!("备份之后新增的密钥将失效，之后删除的密钥会恢复"),
        tx!("会先备份当前头部"),
    ]);
    b.backup("before-restore");
    b.step(Step::run(
        tx!("恢复头部"),
        b.cryptsetup("luksHeaderRestore")
            .arg("-q")
            .arg("--header-backup-file")
            .arg(file.to_string_lossy()),
    ));
    Ok(b.finish())
}

// ---------------------------------------------------------------------------
// Execution

/// Callbacks from [`execute`] to the frontend.
pub trait Hooks {
    /// Called before an interactive command runs (leave the TUI).
    fn suspend(&mut self) {}
    /// Called after an interactive command finished.
    fn resume(&mut self) {}
    fn progress(&mut self, _step: &str) {}
}

pub struct NoHooks;
impl Hooks for NoHooks {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepReport {
    pub desc: Text,
    pub command: Option<String>,
    pub ok: bool,
    pub output: Text,
}

#[derive(Debug, Default)]
pub struct Report {
    pub ok: bool,
    pub steps: Vec<StepReport>,
    pub new_slot: Option<u32>,
    pub recovery_key: Option<Secret>,
    pub error: Option<Text>,
    pub backup_file: Option<PathBuf>,
}

struct State {
    new_slot: Option<u32>,
}

impl State {
    fn resolve(&self, r: SlotRef) -> Result<u32> {
        match r {
            SlotRef::Fixed(n) => Ok(n),
            SlotRef::New => self
                .new_slot
                .ok_or_else(|| Error::Invalid(tx!("没有检测到新写入的槽位"))),
        }
    }
}

struct Lock(std::fs::File);

impl Lock {
    fn acquire(ctx: &Ctx) -> Result<Lock> {
        use std::os::fd::AsRawFd;
        util::ensure_private_dir(&ctx.paths.state_dir, 0o700)?;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(ctx.paths.lock_file())?;
        // SAFETY: valid descriptor owned by `f`.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Blocked(tx!(
                "另一个 Luks Assistant 实例正在执行操作"
            )));
        }
        Ok(Lock(f))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: valid descriptor.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Run `plan`. Stops at the first failing step.
pub fn execute(ctx: &Ctx, plan: &Plan, hooks: &mut dyn Hooks) -> Report {
    let mut report = Report {
        backup_file: plan.backup_file.clone(),
        ..Report::default()
    };
    let _lock = match Lock::acquire(ctx) {
        Ok(l) => l,
        Err(e) => {
            report.error = Some(e.text());
            return report;
        }
    };
    let before: Vec<u32> = match header::read(ctx, &plan.device) {
        Ok(h) => h.keyslots.keys().copied().collect(),
        Err(e) => {
            report.error = Some(tx!("读取头部失败: {}", e.text()));
            return report;
        }
    };
    let mut state = State { new_slot: None };
    for step in &plan.steps {
        hooks.progress(&step.desc().to_string());
        let result = run_step(ctx, plan, step, &before, &mut state, &mut report, hooks);
        let ok = result.is_ok();
        let output = match &result {
            Ok(s) => s.clone(),
            Err(e) => e.text(),
        };
        report.steps.push(StepReport {
            desc: step.desc().to_owned(),
            command: step.command(),
            ok,
            output,
        });
        if let Err(e) = result {
            report.error = Some(tx!("{}: {}", step.desc(), e.text()));
            break;
        }
    }
    report.ok = report.error.is_none();
    report.new_slot = state.new_slot;
    log_history(ctx, plan, &report);
    report
}

fn run_step(
    ctx: &Ctx,
    plan: &Plan,
    step: &Step,
    before: &[u32],
    state: &mut State,
    report: &mut Report,
    hooks: &mut dyn Hooks,
) -> Result<Text> {
    match step {
        Step::Run {
            cmd, creates_slot, ..
        } => {
            if cmd.interactive {
                hooks.suspend();
            }
            let out = ctx.runner.run(cmd);
            if cmd.interactive {
                hooks.resume();
            }
            let out = out?.check(&cmd.program)?;
            if cmd.secret_stdout {
                let key = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                if !key.is_empty() {
                    report.recovery_key = Some(Secret::from(key));
                }
            }
            if *creates_slot {
                let h = header::read(ctx, &plan.device)?;
                let new: Vec<u32> = h
                    .keyslots
                    .keys()
                    .copied()
                    .filter(|k| !before.contains(k))
                    .collect();
                state.new_slot = new.first().copied();
            }
            let mut text = out.stderr.trim().to_owned();
            if !cmd.secret_stdout && !out.stdout.is_empty() {
                let so = out.stdout_lossy();
                text = format!("{}\n{text}", so.trim()).trim().to_owned();
            }
            Ok(Text::plain(text))
        }
        Step::Internal { action, .. } => run_action(ctx, plan, action, state),
    }
}

fn run_action(ctx: &Ctx, plan: &Plan, action: &Action, state: &mut State) -> Result<Text> {
    match action {
        Action::EnsurePrivateDir(dir) => {
            util::ensure_private_dir(dir, 0o700)?;
            Ok(Text::plain(""))
        }
        Action::GenerateKeyfile { path, bytes } => {
            use std::io::{Read, Write};
            use std::os::unix::fs::OpenOptionsExt;
            let mut key = zeroize::Zeroizing::new(vec![0u8; *bytes]);
            std::fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(path)?;
            f.write_all(&key)?;
            f.sync_all()?;
            Ok(tx!("已生成 {}", path.display()))
        }
        Action::ExpectSlot { slot, present } => {
            let n = state.resolve(*slot)?;
            let h = header::read(ctx, &plan.device)?;
            if h.keyslots.contains_key(&n) == *present {
                Ok(tx!(
                    "槽位 {} {}",
                    n,
                    if *present {
                        tx!("存在")
                    } else {
                        tx!("已删除")
                    }
                ))
            } else {
                Err(Error::Invalid(tx!("槽位 {} 状态与预期不符", n)))
            }
        }
        Action::SetNote {
            slot,
            text,
            kind,
            location,
        } => {
            let n = state.resolve(*slot)?;
            let (text, kind, location) = (text.clone(), kind.clone(), *location);
            edit_notes(ctx, plan, move |h, header_set, local_set| {
                let ks = h
                    .keyslots
                    .get(&n)
                    .ok_or_else(|| Error::Invalid(tx!("槽位 {} 不存在", n)))?;
                let fp = notes::fingerprint(ks);
                let current = header_set
                    .get(n)
                    .or_else(|| local_set.get(n))
                    .filter(|x| x.fp == fp)
                    .cloned();
                let new_kind = match kind {
                    KindUpdate::Keep => current.as_ref().and_then(|c| c.kind),
                    KindUpdate::Set(k) => k,
                };
                let new_text = text.unwrap_or_else(|| {
                    current.as_ref().map(|c| c.text.clone()).unwrap_or_default()
                });
                header_set.remove(n);
                local_set.remove(n);
                if new_text.is_empty() && new_kind.is_none() {
                    return Ok(());
                }
                // The kind marker always stays in the header so the slot
                // type survives even when the text is kept locally.
                let note = Note {
                    text: new_text.clone(),
                    kind: new_kind,
                    fp: fp.clone(),
                    updated: util::now_unix(),
                };
                match location {
                    Location::Header => header_set.set(n, note),
                    Location::Local => {
                        local_set.set(n, note);
                        if let Some(k) = new_kind {
                            header_set.set(
                                n,
                                Note {
                                    text: String::new(),
                                    kind: Some(k),
                                    fp,
                                    updated: util::now_unix(),
                                },
                            );
                        }
                    }
                }
                Ok(())
            })
        }
        Action::RebindNote { from, to, kind } => {
            let to = state.resolve(*to).unwrap_or(*from);
            let (from, kind) = (*from, *kind);
            edit_notes(ctx, plan, move |h, header_set, local_set| {
                let ks = h
                    .keyslots
                    .get(&to)
                    .ok_or_else(|| Error::Invalid(tx!("槽位 {} 不存在", to)))?;
                let fp = notes::fingerprint(ks);
                let now = util::now_unix();
                if let Some(mut n) = local_set.remove(from) {
                    n.fp = fp.clone();
                    n.updated = now;
                    local_set.set(to, n);
                }
                let mut n = header_set.remove(from).unwrap_or(Note {
                    text: String::new(),
                    kind: None,
                    fp: String::new(),
                    updated: 0,
                });
                if kind.is_some() {
                    n.kind = kind;
                }
                if !n.text.is_empty() || n.kind.is_some() {
                    n.fp = fp;
                    n.updated = now;
                    header_set.set(to, n);
                }
                Ok(())
            })
            .map(|s| tx!("{}（槽位 {}）", s, to))
        }
        Action::DropNote { slot } => {
            let n = *slot;
            edit_notes(ctx, plan, move |_, header_set, local_set| {
                header_set.remove(n);
                local_set.remove(n);
                Ok(())
            })
        }
        Action::PruneStaleNotes => edit_notes(ctx, plan, |h, header_set, local_set| {
            let notes = Notes {
                header: header_set.clone(),
                header_token: None,
                local: local_set.clone(),
            };
            for (loc, slot) in notes.stale(h) {
                match loc {
                    Location::Header => header_set.remove(slot),
                    Location::Local => local_set.remove(slot),
                };
            }
            Ok(())
        }),
        Action::ExpectDiscards(enable) => {
            let h = header::read(ctx, &plan.device)?;
            if h.allows_discards() == *enable {
                Ok(Text::plain(format!("allow-discards = {enable}")))
            } else {
                Err(Error::Invalid(tx!("头部 TRIM 标志与预期不符")))
            }
        }
        Action::SavePcrSnapshot { slot } => {
            let n = state.resolve(*slot)?;
            let h = header::read(ctx, &plan.device)?;
            let tok = h
                .tokens_for(n)
                .find_map(Tpm2Token::from_token)
                .ok_or_else(|| Error::Invalid(tx!("槽位 {} 没有 TPM2 令牌", n)))?;
            let values = luks_assistant_sysinfo::tpm::read_pcrs(&tok.bank, &ctx.tpm2_device)
                .map_err(|e| Error::Invalid(e.into()))?;
            let mut snaps = Snapshots::load(&ctx.paths, &h.uuid);
            snaps.remember(&tok, &values);
            snaps.save(&ctx.paths, &h.uuid)?;
            let status = pcr::evaluate(&tok, Some(&values), &snaps);
            Ok(tx!(
                "PCR {} 已记录；{}",
                pcr::format_list(&tok.pcrs),
                status.text()
            ))
        }
    }
}

/// Load both note stores, let `f` edit them, and write back what changed.
fn edit_notes<F>(ctx: &Ctx, plan: &Plan, f: F) -> Result<Text>
where
    F: FnOnce(&Header, &mut NoteSet, &mut NoteSet) -> Result<()>,
{
    let h = header::read(ctx, &plan.device)?;
    let notes = Notes::load(&h, &ctx.paths);
    let (mut header_set, mut local_set) = (notes.header.clone(), notes.local.clone());
    f(&h, &mut header_set, &mut local_set)?;
    let mut done = Vec::new();
    if header_set != notes.header {
        notes::check_header_space(&h, &notes.header, &header_set)?;
        for cmd in header_note_cmds(ctx, &h, notes.header_token, &header_set, &plan.device) {
            ctx.runner.run(&cmd)?.check("cryptsetup token")?;
            done.push(Text::plain(cmd.display_in(crate::i18n::Lang::En)));
        }
    }
    if local_set != notes.local {
        notes::write_local(&ctx.paths, &h.uuid, &local_set)?;
        done.push(tx!("写入 {}", ctx.paths.local_notes(&h.uuid).display()));
    }
    Ok(if done.is_empty() {
        tx!("无变化")
    } else {
        Text::join(done, Text::plain("\n"))
    })
}

fn header_note_cmds(
    ctx: &Ctx,
    h: &Header,
    existing: Option<u32>,
    set: &NoteSet,
    dev: &Path,
) -> Vec<Cmd> {
    let dev = dev.to_string_lossy().into_owned();
    let remove = |id: u32| {
        Cmd::new("cryptsetup")
            .args(["token", "remove", "--token-id"])
            .arg(id.to_string())
            .arg(&dev)
    };
    let import = |id: u32, replace: bool| {
        let mut c = Cmd::new("cryptsetup")
            .args(["token", "import", "--token-id"])
            .arg(id.to_string());
        if replace {
            c = c.arg("--token-replace");
        }
        c.arg(&dev).stdin(notes::token_json(set).into_bytes())
    };
    match (existing, set.is_empty()) {
        (None, true) => Vec::new(),
        (Some(id), true) => vec![remove(id)],
        (Some(id), false) if ctx.caps.token_replace => vec![import(id, true)],
        (Some(id), false) => match h.free_token_id_high() {
            Some(free) => vec![import(free, false), remove(id)],
            None => vec![remove(id), import(id, false)],
        },
        (None, false) => match h.free_token_id_high() {
            Some(free) => vec![import(free, false)],
            None => Vec::new(),
        },
    }
}

/// What happened, in English: for the history file and the GUI log.
pub fn log_text(plan: &Plan, report: &Report) -> String {
    let mut text = format!(
        "{} — {} — {}\n",
        plan.device.display(),
        plan.title.en(),
        if report.ok { "OK" } else { "FAILED" }
    );
    for (step, r) in plan.steps.iter().zip(&report.steps) {
        let mark = if r.ok { "✓" } else { "✗" };
        match step.command_in(crate::i18n::Lang::En) {
            Some(c) => text.push_str(&format!("    {mark} {c}\n")),
            None => text.push_str(&format!("    {mark} {}\n", step.desc().en())),
        }
    }
    if let Some(e) = &report.error {
        text.push_str(&format!("    error: {}\n", e.en()));
    }
    text
}

fn log_history(ctx: &Ctx, plan: &Plan, report: &Report) {
    use std::io::Write;
    let text = format!(
        "[{}] {}",
        util::format_time(util::now_unix()),
        log_text(plan, report)
    );
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ctx.paths.history_log())
        .and_then(|mut f| f.write_all(text.as_bytes()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slots::tests::{sample_overview, test_ctx};

    #[test]
    fn explains_token_failure() {
        let out = |stdout: &str| CmdOutput {
            code: 1,
            stdout: zeroize::Zeroizing::new(stdout.as_bytes().to_vec()),
            stderr: String::new(),
        };
        assert_eq!(
            token_failure(&out(
                "Token 0 requires additional missing resource.\nCommand failed with code -1 (wrong or missing parameters).\n"
            ))
            .to_string(),
            "找不到所需设备（TPM 或安全密钥）"
        );
        assert_eq!(
            token_failure(&out(
                "No usable token is available.\nCommand failed with code -2.\n"
            ))
            .to_string(),
            "No usable token is available."
        );
    }

    #[test]
    fn unlock_and_lock_commands() {
        let mut ov = sample_overview();
        let pw = Credential::Passphrase(Secret::from_text("x"));
        let open = unlock_cmd(&ov, &pw).unwrap().display();
        assert!(
            open.starts_with(&format!(
                "cryptsetup open /dev/test luks-{} --key-file",
                ov.header.uuid
            )),
            "{open}"
        );
        assert!(lock_cmd(&ov).is_err()); // not unlocked

        ov.device.mapping = Some("cryptdata".into());
        assert!(unlock_cmd(&ov, &pw).is_err()); // already unlocked
        assert_eq!(
            lock_cmd(&ov).unwrap().display(),
            "cryptsetup close cryptdata"
        );

        ov.device.mountpoints = vec!["/".into()];
        assert!(matches!(lock_cmd(&ov), Err(Error::Blocked(_)))); // the running system
    }

    #[test]
    fn parses_unlocked_slot() {
        assert_eq!(
            parse_unlocked_slot(
                "No usable token is available.\nKey slot 3 unlocked.\nCommand successful.\n"
            ),
            Some(3)
        );
        assert_eq!(
            parse_unlocked_slot("No key available with this passphrase.\n"),
            None
        );
    }

    fn pw(s: &str) -> Credential {
        Credential::Passphrase(Secret::from_text(s))
    }

    #[test]
    fn add_passphrase_plan() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let ov = sample_overview();
        let p = plan(
            &ctx,
            &ov,
            &Request::AddPassphrase {
                auth: pw("old"),
                new: Secret::from_text("new passphrase"),
                slot: None,
                kdf: KdfChoice::Default,
                note: Some(NoteInput {
                    text: "备用".into(),
                    location: Location::Header,
                }),
            },
        )
        .unwrap();
        let cmds = p.commands();
        assert!(cmds[0].starts_with("cryptsetup luksHeaderBackup /dev/test --header-backup-file "));
        assert_eq!(
            cmds[1],
            "cryptsetup luksAddKey /dev/test --key-slot 4 --key-file <(现有密码) <(新密码)"
        );
        assert!(p.warnings.is_empty());
        assert_eq!(p.danger, Danger::Normal);
        assert!(!p.is_interactive());
    }

    #[test]
    fn tpm2_enroll_requires_cryptenroll_and_builds_command() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(dir.path());
        let ov = sample_overview();
        let req = Request::EnrollTpm2 {
            auth: pw("old"),
            pcrs: vec![7],
            pin: None,
            replace: Some(2),
            note: None,
        };
        assert!(matches!(plan(&ctx, &ov, &req), Err(Error::Unsupported(_))));
        ctx.caps.cryptenroll = true;
        let p = plan(&ctx, &ov, &req).unwrap();
        let cmds = p.commands();
        assert_eq!(
            cmds[1],
            "PASSWORD=<已隐藏> systemd-cryptenroll /dev/test --tpm2-device=swtpm:host=127.0.0.1,port=1 --tpm2-pcrs=7 --wipe-slot=2"
        );
        assert_eq!(p.danger, Danger::High);
        // replacing a non-TPM slot is refused
        let req = Request::EnrollTpm2 {
            auth: pw("old"),
            pcrs: vec![7],
            pin: None,
            replace: Some(0),
            note: None,
        };
        assert!(matches!(plan(&ctx, &ov, &req), Err(Error::Blocked(_))));
    }

    #[test]
    fn change_only_plain_slots() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let ov = sample_overview();
        let req = Request::ChangePassphrase {
            slot: 2,
            old: pw("a"),
            new: Secret::from_text("bbbbbbbbbb"),
            kdf: KdfChoice::Default,
        };
        assert!(matches!(plan(&ctx, &ov, &req), Err(Error::Blocked(_))));
        let req = Request::ChangePassphrase {
            slot: 5,
            old: pw("a"),
            new: Secret::from_text("bbbbbbbbbb"),
            kdf: KdfChoice::Pbkdf2,
        };
        let p = plan(&ctx, &ov, &req).unwrap();
        assert_eq!(
            p.commands()[1],
            "cryptsetup luksChangeKey /dev/test --key-slot 5 --pbkdf pbkdf2 --key-file <(旧密码) <(新密码)"
        );
    }

    #[test]
    fn orphan_token_rules() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_ctx(dir.path());
        let ov = sample_overview();
        assert!(plan(&ctx, &ov, &Request::RemoveOrphanToken { token: 7 }).is_ok());
        assert!(plan(&ctx, &ov, &Request::RemoveOrphanToken { token: 1 }).is_err());
        assert!(plan(&ctx, &ov, &Request::RemoveOrphanToken { token: 31 }).is_err());
    }

    #[test]
    fn note_commands() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(dir.path());
        let h = crate::header::tests::sample();
        let mut set = NoteSet::default();
        set.set(
            0,
            Note {
                text: "x".into(),
                kind: None,
                fp: "f".into(),
                updated: 0,
            },
        );
        let dev = Path::new("/dev/test");
        let c = header_note_cmds(&ctx, &h, Some(31), &set, dev);
        assert_eq!(c.len(), 2);
        assert!(
            c[0].display()
                .contains("token import --token-id 30 /dev/test")
        );
        assert!(
            c[1].display()
                .ends_with("token remove --token-id 31 /dev/test")
        );
        ctx.caps.token_replace = true;
        let c = header_note_cmds(&ctx, &h, Some(31), &set, dev);
        assert_eq!(c.len(), 1);
        assert!(c[0].display().contains("--token-id 31 --token-replace"));
        let c = header_note_cmds(&ctx, &h, Some(31), &NoteSet::default(), dev);
        assert!(c[0].display().contains("token remove"));
    }
}
