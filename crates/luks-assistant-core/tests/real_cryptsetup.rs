//! End-to-end tests against real cryptsetup / systemd-cryptenroll on LUKS2
//! image files. Skipped unless running as root with cryptsetup installed.
//!
//! TPM2 tests additionally need a software TPM: set
//! `LUKS_ASSISTANT_TEST_SWTPM=swtpm:host=127.0.0.1,port=2321` (see CONTRIBUTING).

use luks_assistant_core::ctx::{Ctx, Paths, fast_kdf_args};
use luks_assistant_core::device::LuksDevice;
use luks_assistant_core::health;
use luks_assistant_core::notes::{KeyKind, Location};
use luks_assistant_core::ops::{self, Credential, KdfChoice, NoHooks, NoteInput, Request};
use luks_assistant_core::pcr::TpmStatus;
use luks_assistant_core::slots::{Overview, SlotKind};
use luks_assistant_core::{Error, Secret};
use std::path::PathBuf;
use std::process::Command;

fn available() -> bool {
    let ok = luks_assistant_sysinfo::is_root()
        && Command::new("cryptsetup")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("skipping: needs root and cryptsetup");
    }
    ok
}

struct Env {
    _dir: tempfile::TempDir,
    img: PathBuf,
    ctx: Ctx,
}

fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    std::fs::File::create(&img)
        .unwrap()
        .set_len(32 << 20)
        .unwrap();
    let mut child = Command::new("cryptsetup")
        .args(["luksFormat", "--type", "luks2", "-q", "--key-file=-"])
        .args(fast_kdf_args())
        .arg(&img)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"first-pass")
        .unwrap();
    assert!(child.wait().unwrap().success());
    let mut ctx = Ctx::system();
    ctx.paths = Paths::under(dir.path());
    ctx.extra_kdf_args = fast_kdf_args();
    Env {
        _dir: dir,
        img,
        ctx,
    }
}

impl Env {
    fn ov(&self) -> Overview {
        Overview::load(&self.ctx, LuksDevice::from_path(&self.img)).unwrap()
    }

    fn run(&self, req: Request) -> ops::Report {
        let ov = self.ov();
        let plan = ops::plan(&self.ctx, &ov, &req).unwrap_or_else(|e| panic!("plan failed: {e}"));
        let report = ops::execute(&self.ctx, &plan, &mut NoHooks);
        assert!(
            report.ok,
            "execution failed: {:?}\n{:#?}",
            report.error, report.steps
        );
        report
    }

    fn unlocks(&self, pass: &str) -> Option<u32> {
        ops::verify_credential(&self.ctx, &self.img, &pw(pass)).ok()
    }
}

fn pw(s: &str) -> Credential {
    Credential::Passphrase(Secret::from_text(s))
}

fn note(text: &str, location: Location) -> Option<NoteInput> {
    Some(NoteInput {
        text: text.into(),
        location,
    })
}

#[test]
fn passphrase_keyfile_notes_and_removal() {
    if !available() {
        return;
    }
    let env = setup();
    let ov = env.ov();
    assert_eq!(ov.used().count(), 1);
    assert_eq!(ov.slots[0].kind, SlotKind::Secret);

    // add passphrase with a header note
    env.run(Request::AddPassphrase {
        auth: pw("first-pass"),
        new: Secret::from_text("second-pass"),
        slot: Some(3),
        kdf: KdfChoice::Default,
        note: note("备用密码", Location::Header),
    });
    let ov = env.ov();
    assert_eq!(ov.slots[3].kind, SlotKind::Passphrase);
    assert_eq!(ov.slots[3].note.as_ref().unwrap().note.text, "备用密码");
    assert_eq!(env.unlocks("second-pass"), Some(3));
    assert!(env.ctx.paths.history_log().exists());
    assert_eq!(
        std::fs::read_dir(env.ctx.paths.backups_dir(ov.uuid()))
            .unwrap()
            .count(),
        1
    );

    // generated key file
    let kf = env._dir.path().join("usb.key");
    env.run(Request::AddKeyfile {
        auth: pw("first-pass"),
        path: kf.clone(),
        generate: Some(64),
        slot: None,
        kdf: KdfChoice::Default,
        note: None,
    });
    let ov = env.ov();
    assert_eq!(ov.slots[1].kind, SlotKind::Keyfile);
    assert_eq!(
        ov.slots[1].note.as_ref().unwrap().note.text,
        kf.to_string_lossy()
    );
    assert_eq!(
        ops::verify_credential(&env.ctx, &env.img, &Credential::Keyfile(kf.clone())).unwrap(),
        1
    );

    // change passphrase: note and kind follow the slot
    env.run(Request::ChangePassphrase {
        slot: 3,
        old: pw("second-pass"),
        new: Secret::from_text("third-pass!"),
        kdf: KdfChoice::Default,
    });
    let ov = env.ov();
    let changed = ov
        .used()
        .find(|s| s.note.as_ref().is_some_and(|n| n.note.text == "备用密码"))
        .expect("note kept");
    assert_eq!(changed.kind, SlotKind::Passphrase);
    assert_eq!(env.unlocks("third-pass!"), Some(changed.id));
    assert_eq!(env.unlocks("second-pass"), None);

    // local note on slot 0
    env.run(Request::SetNote {
        slot: 0,
        text: "主密码".into(),
        location: Location::Local,
    });
    let ov = env.ov();
    let n = ov.slots[0].note.as_ref().unwrap();
    assert_eq!(
        (n.note.text.as_str(), n.location),
        ("主密码", Location::Local)
    );
    assert!(env.ctx.paths.local_notes(ov.uuid()).exists());

    // removal: credential of the removed slot is refused
    let ov = env.ov();
    let req = Request::RemoveSlot {
        slot: 1,
        auth: Credential::Keyfile(kf.clone()),
    };
    assert!(matches!(
        ops::plan(&env.ctx, &ov, &req),
        Err(Error::Blocked(_))
    ));
    // wrong password is refused
    let req = Request::RemoveSlot {
        slot: 1,
        auth: pw("nope"),
    };
    assert!(matches!(
        ops::plan(&env.ctx, &ov, &req),
        Err(Error::Invalid(_))
    ));
    let plan = ops::plan(
        &env.ctx,
        &ov,
        &Request::RemoveSlot {
            slot: 1,
            auth: pw("first-pass"),
        },
    )
    .unwrap();
    assert_eq!(plan.confirm_word.as_deref(), Some("1"));
    assert!(ops::execute(&env.ctx, &plan, &mut NoHooks).ok);
    let ov = env.ov();
    assert!(ov.slots[1].is_empty());
    assert!(ov.notes.header.get(1).is_none());

    // remove down to one knowledge slot, then the guard stops us
    let other = changed.id;
    env.run(Request::RemoveSlot {
        slot: other,
        auth: pw("first-pass"),
    });
    let ov = env.ov();
    assert_eq!(ov.knowledge_slots(), vec![0]);
    let err = ops::plan(
        &env.ctx,
        &ov,
        &Request::RemoveSlot {
            slot: 0,
            auth: pw("first-pass"),
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::Blocked(_)), "{err}");
}

#[test]
fn recovery_key_priority_orphans_and_restore() {
    if !available() || !Ctx::system().caps.cryptenroll {
        return;
    }
    let env = setup();
    let report = env.run(Request::AddRecoveryKey {
        auth: pw("first-pass"),
        replace: None,
        note: note("打印在纸上", Location::Header),
    });
    let first_backup = report.backup_file.clone().expect("backup taken");
    let key = report.recovery_key.expect("recovery key returned");
    let key = String::from_utf8(key.expose().to_vec()).unwrap();
    assert_eq!(key.split('-').count(), 8, "{key}");
    let slot = report.new_slot.unwrap();
    let ov = env.ov();
    assert_eq!(ov.slots[slot as usize].kind, SlotKind::Recovery);
    assert_eq!(env.unlocks(&key), Some(slot));
    // the secret must not leak into the step output
    assert!(report.steps.iter().all(|s| !s.output.contains(&key)));

    // regenerate (replace) keeps the note on the new slot
    let report = env.run(Request::AddRecoveryKey {
        auth: pw("first-pass"),
        replace: Some(slot),
        note: None,
    });
    let ov = env.ov();
    let new = report.new_slot.unwrap();
    assert!(ov.slots[slot as usize].is_empty());
    assert_eq!(ov.slots[new as usize].kind, SlotKind::Recovery);

    // priority
    env.run(Request::SetPriority {
        slot: 0,
        priority: luks_assistant_core::header::Priority::Prefer,
    });
    assert_eq!(
        env.ov().slots[0].keyslot.as_ref().unwrap().priority,
        luks_assistant_core::header::Priority::Prefer
    );

    // orphan token from another tool → found by health check → removed
    let mut child = Command::new("cryptsetup")
        .args(["token", "import", "--token-id", "9"])
        .arg(&env.img)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"type":"x-test","keyslots":[]}"#)
        .unwrap();
    assert!(child.wait().unwrap().success());
    let issues = health::check(&env.ov());
    let fix = issues
        .iter()
        .find_map(|i| {
            i.fix
                .clone()
                .filter(|f| matches!(f, Request::RemoveOrphanToken { token: 9 }))
        })
        .unwrap();
    env.run(fix);
    assert!(!env.ov().header.tokens.contains_key(&9));

    // restore the very first backup: the recovery key slot disappears again
    let ov = env.ov();
    assert_eq!(
        std::fs::read_dir(env.ctx.paths.backups_dir(ov.uuid()))
            .unwrap()
            .count(),
        4
    );
    let plan = ops::plan(
        &env.ctx,
        &ov,
        &Request::RestoreHeader { file: first_backup },
    )
    .unwrap();
    assert_eq!(plan.confirm_word.as_deref(), Some("RESTORE"));
    assert!(ops::execute(&env.ctx, &plan, &mut NoHooks).ok);
    let ov = env.ov();
    assert_eq!(ov.used().count(), 1);
    // header notes live in the header, so they were rolled back as well
    assert!(ov.notes.header.is_empty());
}

fn tpm_tcti() -> Option<String> {
    std::env::var("LUKS_ASSISTANT_TEST_SWTPM")
        .ok()
        .filter(|s| !s.is_empty())
}

fn pcrextend(tcti: &str, pcr: u8) {
    let st = Command::new("tpm2_pcrextend")
        .args(["-T", tcti])
        .arg(format!(
            "{pcr}:sha256=00000000000000000000000000000000000000000000000000000000000000ff"
        ))
        .status()
        .unwrap();
    assert!(st.success());
}

#[test]
fn tpm2_enroll_detect_drift_and_reenroll() {
    let Some(tcti) = tpm_tcti() else {
        eprintln!("skipping: LUKS_ASSISTANT_TEST_SWTPM not set");
        return;
    };
    if !available() {
        return;
    }
    let mut env = setup();
    env.ctx.tpm2_device = tcti.clone();
    // a PCR nobody else in the test suite touches
    let pcr = 9;
    let report = env.run(Request::EnrollTpm2 {
        auth: pw("first-pass"),
        pcrs: vec![pcr],
        pin: None,
        replace: None,
        note: note("本机 TPM", Location::Header),
    });
    let slot = report.new_slot.unwrap();
    let ov = env.ov();
    let s = &ov.slots[slot as usize];
    assert_eq!(s.kind, SlotKind::Tpm2);
    assert_eq!(s.tpm2.as_ref().unwrap().pcrs, vec![pcr]);
    assert_eq!(s.tpm2_status, Some(TpmStatus::Match));

    pcrextend(&tcti, pcr);
    let ov = env.ov();
    assert_eq!(
        ov.slots[slot as usize].tpm2_status,
        Some(TpmStatus::Mismatch {
            changed: Some(vec![pcr])
        })
    );

    let report = env.run(Request::EnrollTpm2 {
        auth: pw("first-pass"),
        pcrs: vec![pcr],
        pin: Some(Secret::from_text("123456")),
        replace: Some(slot),
        note: None,
    });
    let new = report.new_slot.unwrap();
    let ov = env.ov();
    assert!(ov.slots[slot as usize].is_empty());
    let s = &ov.slots[new as usize];
    assert_eq!(s.tpm2_status, Some(TpmStatus::Match));
    assert!(s.tpm2.as_ref().unwrap().pin);
    assert_eq!(s.note.as_ref().unwrap().note.text, "本机 TPM");
    assert_eq!(s.note.as_ref().unwrap().note.kind, None::<KeyKind>);

    // a TPM slot can be removed, the passphrase cannot
    env.run(Request::RemoveSlot {
        slot: new,
        auth: pw("first-pass"),
    });
    assert!(env.ov().slots[new as usize].is_empty());
}
