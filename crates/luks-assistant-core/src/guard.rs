//! Safety rules. Every write operation is checked here before a plan is
//! produced; a violated rule yields [`Error::Blocked`] and there is no
//! "continue anyway".
//!
//! The central invariant: at least one *knowledge* slot (passphrase, key
//! file or recovery key) must always remain. Hardware tokens are extra
//! convenience, never the only way in.

use crate::error::{Error, Result};
use crate::header::Priority;
use crate::i18n::Text;
use crate::secret::Secret;
use crate::slots::{Overview, SlotKind};
use crate::tx;

/// cryptsetup's limit for interactive passphrases.
pub const MAX_PASSPHRASE: usize = 512;

fn blocked<T>(msg: impl Into<Text>) -> Result<T> {
    Err(Error::Blocked(msg.into()))
}

pub fn ensure_writable(ov: &Overview) -> Result<()> {
    match ov.read_only_reason() {
        Some(r) => blocked(r),
        None => Ok(()),
    }
}

/// Pick the slot for a new key: the requested one if free, else the lowest free.
pub fn free_slot(ov: &Overview, wanted: Option<u32>) -> Result<u32> {
    match wanted {
        Some(n) if n >= crate::MAX_SLOTS => blocked(tx!(
            "Slot numbers must be between 0 and {}",
            crate::MAX_SLOTS - 1
        )),
        Some(n) if ov.slot(n).is_some_and(|s| !s.is_empty()) => {
            blocked(tx!("Slot {} is in use", n))
        }
        Some(n) => Ok(n),
        None => match ov.header.free_slots().next() {
            Some(n) => Ok(n),
            None => blocked(tx!("All 32 slots are in use")),
        },
    }
}

pub fn ensure_any_free(ov: &Overview) -> Result<()> {
    free_slot(ov, None).map(|_| ())
}

/// Validate a new passphrase. Returns warnings that do not block.
pub fn check_new_passphrase(p: &Secret) -> Result<Vec<Text>> {
    let bytes = p.expose();
    if bytes.is_empty() {
        return blocked(tx!("The new password cannot be empty"));
    }
    if bytes.len() > MAX_PASSPHRASE {
        return blocked(tx!(
            "Passwords cannot be longer than {} bytes",
            MAX_PASSPHRASE
        ));
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return blocked(tx!("Passwords must be valid UTF-8 text"));
    };
    if text.chars().any(char::is_control) {
        return blocked(tx!(
            "Passwords cannot contain line breaks or control characters"
        ));
    }
    let mut warnings = Vec::new();
    if text.chars().count() < 8 {
        warnings.push(tx!("The password is shorter than 8 characters"));
    }
    if !text.is_ascii() {
        warnings.push(tx!(
            "The password has non-ASCII characters and may be impossible to type at boot"
        ));
    }
    if text.starts_with(' ') || text.ends_with(' ') {
        warnings.push(tx!("The password starts or ends with a space"));
    }
    Ok(warnings)
}

/// Rules for wiping `slot`. `auth_slot` is the slot the user's credential
/// unlocked, if verified.
pub fn check_removal(ov: &Overview, slot: u32, auth_slot: Option<u32>) -> Result<Vec<Text>> {
    let Some(s) = ov.slot(slot).filter(|s| !s.is_empty()) else {
        return blocked(tx!("Slot {} is empty", slot));
    };
    if s.kind == SlotKind::Reencrypt {
        return blocked(tx!("This slot is being used for re-encryption"));
    }
    if ov.used().count() <= 1 {
        return blocked(tx!("This is the last slot; it cannot be deleted"));
    }
    if s.kind.is_knowledge() {
        let remaining = ov
            .knowledge_slots()
            .into_iter()
            .filter(|&k| k != slot)
            .count();
        if remaining == 0 {
            return blocked(tx!(
                "This is the last password/key file/recovery key slot; it cannot be deleted"
            ));
        }
    }
    if auth_slot == Some(slot) {
        return blocked(tx!(
            "The credential used is the slot being deleted; use the credential of another slot"
        ));
    }
    let mut w = Vec::new();
    if let SlotKind::OtherToken(t) = &s.kind {
        w.push(tx!("This slot is managed by another tool ({})", t));
    }
    let shared: Vec<u32> = ov
        .header
        .tokens_for(slot)
        .filter(|t| t.keyslots.len() > 1)
        .map(|t| t.id)
        .collect();
    if !shared.is_empty() {
        w.push(tx!(
            "Token {} is bound to several slots; only slot {} is removed",
            format!("{:?}", shared),
            slot
        ));
    }
    if ov.device.holds_root() {
        w.push(tx!("This device holds the root file system"));
    }
    let remaining_knowledge = ov
        .knowledge_slots()
        .into_iter()
        .filter(|&k| k != slot)
        .count();
    if s.kind.is_knowledge() && remaining_knowledge == 1 {
        w.push(tx!("Only one password/recovery key slot will be left"));
    }
    Ok(w)
}

/// The slot an enrollment should replace must hold the same kind of key.
pub fn check_replace(ov: &Overview, replace: u32, kind: &SlotKind) -> Result<()> {
    match ov.slot(replace) {
        Some(s) if s.kind == *kind => Ok(()),
        Some(s) if s.is_empty() => blocked(tx!("Slot {} is empty", replace)),
        Some(s) => blocked(tx!(
            "Slot {} is “{}”; only {} slots can be replaced",
            replace,
            s.kind.text(),
            kind.text()
        )),
        None => blocked(tx!("Invalid slot {}", replace)),
    }
}

pub fn check_priority(ov: &Overview, slot: u32, prio: Priority) -> Result<Vec<Text>> {
    let Some(s) = ov.slot(slot).filter(|s| !s.is_empty()) else {
        return blocked(tx!("Slot {} is empty", slot));
    };
    if prio == Priority::Ignore && s.kind.is_knowledge() {
        let others = ov
            .used()
            .filter(|o| o.id != slot && o.kind.is_knowledge())
            .filter(|o| {
                o.keyslot
                    .as_ref()
                    .is_some_and(|k| k.priority != Priority::Ignore)
            })
            .count();
        if others == 0 {
            return blocked(tx!(
                "This is the last password slot that is not ignored; the password would no longer unlock at boot"
            ));
        }
        return Ok(vec![tx!("The slot will no longer be tried at boot")]);
    }
    Ok(Vec::new())
}

/// Warning shown when enrolling a token while no knowledge slot exists.
pub fn token_only_warning(ov: &Overview) -> Option<Text> {
    ov.knowledge_slots()
        .is_empty()
        .then(|| tx!("There is no password/recovery key slot at the moment"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slots::tests::sample_overview;

    #[test]
    fn passphrase_rules() {
        assert!(check_new_passphrase(&Secret::from_text("")).is_err());
        assert!(check_new_passphrase(&Secret::from_text("abc\ndef")).is_err());
        assert!(
            check_new_passphrase(&Secret::from_text("correct horse battery"))
                .unwrap()
                .is_empty()
        );
        let w = check_new_passphrase(&Secret::from_text("密码密码密码密码")).unwrap();
        assert!(w.iter().any(|m| m.to_string().contains("non-ASCII")));
        assert!(
            check_new_passphrase(&Secret::from_text("short")).unwrap()[0]
                .to_string()
                .contains("8")
        );
    }

    #[test]
    fn removal_rules() {
        let mut ov = sample_overview();
        // knowledge slots: 0 (passphrase), 1 (recovery), 5 (secret)
        assert!(check_removal(&ov, 4, None).is_err()); // empty
        assert!(check_removal(&ov, 2, Some(0)).is_ok()); // TPM slot
        assert!(check_removal(&ov, 0, Some(0)).is_err()); // auth == target
        assert!(check_removal(&ov, 0, Some(5)).is_ok());

        // Leave a single knowledge slot: it must not be removable.
        for id in [1, 5] {
            ov.slots[id].kind = SlotKind::Empty;
        }
        let err = check_removal(&ov, 0, None).unwrap_err().to_string();
        assert!(err.contains("last password"), "{err}");
        // but tokens still can be removed
        assert!(check_removal(&ov, 3, None).is_ok());
    }

    #[test]
    fn last_slot_is_never_removable() {
        let mut ov = sample_overview();
        for id in 1..32 {
            ov.slots[id].kind = SlotKind::Empty;
        }
        ov.slots[0].kind = SlotKind::Tpm2;
        assert!(
            check_removal(&ov, 0, None)
                .unwrap_err()
                .to_string()
                .contains("the last slot")
        );
    }

    #[test]
    fn slot_choice_and_replace() {
        let ov = sample_overview();
        assert_eq!(free_slot(&ov, None).unwrap(), 4);
        assert_eq!(free_slot(&ov, Some(9)).unwrap(), 9);
        assert!(free_slot(&ov, Some(0)).is_err());
        assert!(free_slot(&ov, Some(32)).is_err());
        assert!(check_replace(&ov, 2, &SlotKind::Tpm2).is_ok());
        assert!(check_replace(&ov, 0, &SlotKind::Tpm2).is_err());
    }

    #[test]
    fn priority_rules() {
        let mut ov = sample_overview();
        assert!(check_priority(&ov, 0, Priority::Ignore).is_ok());
        for id in [1, 5] {
            ov.slots[id].kind = SlotKind::Empty;
        }
        assert!(check_priority(&ov, 0, Priority::Ignore).is_err());
        assert!(check_priority(&ov, 0, Priority::Prefer).is_ok());
    }
}
