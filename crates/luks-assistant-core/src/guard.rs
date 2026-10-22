//! Safety rules. Every write operation is checked here before a plan is
//! produced; a violated rule yields [`Error::Blocked`] and there is no
//! "continue anyway".
//!
//! The central invariant: at least one *knowledge* slot (passphrase, key
//! file or recovery key) must always remain. Hardware tokens are extra
//! convenience, never the only way in.

use crate::error::{Error, Result};
use crate::header::Priority;
use crate::secret::Secret;
use crate::slots::{Overview, SlotKind};

/// cryptsetup's limit for interactive passphrases.
pub const MAX_PASSPHRASE: usize = 512;

fn blocked<T>(msg: impl Into<String>) -> Result<T> {
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
        Some(n) if n >= crate::MAX_SLOTS => {
            blocked(format!("槽位编号必须在 0-{} 之间", crate::MAX_SLOTS - 1))
        }
        Some(n) if ov.slot(n).is_some_and(|s| !s.is_empty()) => blocked(format!(
            "槽位 {n} 已被占用；如需替换请先确认后删除，或使用“修改”"
        )),
        Some(n) => Ok(n),
        None => match ov.header.free_slots().next() {
            Some(n) => Ok(n),
            None => blocked("32 个槽位已全部占用"),
        },
    }
}

pub fn ensure_any_free(ov: &Overview) -> Result<()> {
    free_slot(ov, None).map(|_| ())
}

/// Validate a new passphrase. Returns warnings that do not block.
pub fn check_new_passphrase(p: &Secret) -> Result<Vec<String>> {
    let bytes = p.expose();
    if bytes.is_empty() {
        return blocked("新密码不能为空");
    }
    if bytes.len() > MAX_PASSPHRASE {
        return blocked(format!("密码不能超过 {MAX_PASSPHRASE} 字节"));
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return blocked("密码必须是有效的 UTF-8 文本");
    };
    if text.chars().any(char::is_control) {
        return blocked("密码不能包含换行或控制字符——开机输入时无法键入它们");
    }
    let mut warnings = Vec::new();
    if text.chars().count() < 8 {
        warnings.push("密码少于 8 个字符，强度较低".into());
    }
    if !text.is_ascii() {
        warnings.push("密码包含非 ASCII 字符：开机时的 initramfs 通常只有美式键盘布局、没有输入法，可能无法输入！".into());
    }
    if text.starts_with(' ') || text.ends_with(' ') {
        warnings.push("密码首尾有空格，请确认这是有意的".into());
    }
    Ok(warnings)
}

/// Rules for wiping `slot`. `auth_slot` is the slot the user's credential
/// unlocked, if verified.
pub fn check_removal(ov: &Overview, slot: u32, auth_slot: Option<u32>) -> Result<Vec<String>> {
    let Some(s) = ov.slot(slot).filter(|s| !s.is_empty()) else {
        return blocked(format!("槽位 {slot} 是空的"));
    };
    if s.kind == SlotKind::Reencrypt {
        return blocked("该槽位正被在线重加密使用，不能删除");
    }
    if ov.used().count() <= 1 {
        return blocked("这是最后一个槽位。删除后数据将永远无法解密");
    }
    if s.kind.is_knowledge() {
        let remaining = ov
            .knowledge_slots()
            .into_iter()
            .filter(|&k| k != slot)
            .count();
        if remaining == 0 {
            return blocked(
                "这是最后一个密码/密钥文件/恢复密钥槽位。TPM2/FIDO2 等令牌不能作为唯一的解锁方式，请先添加新的密码或恢复密钥",
            );
        }
    }
    if auth_slot == Some(slot) {
        return blocked("用于验证的凭据正是要删除的这个槽位，请输入另一个保留槽位的密码或密钥文件");
    }
    let mut w = Vec::new();
    if let SlotKind::OtherToken(t) = &s.kind {
        w.push(format!(
            "该槽位由其他工具管理（令牌类型 {t}），删除后该工具的自动解锁将失效"
        ));
    }
    let shared: Vec<u32> = ov
        .header
        .tokens_for(slot)
        .filter(|t| t.keyslots.len() > 1)
        .map(|t| t.id)
        .collect();
    if !shared.is_empty() {
        w.push(format!(
            "令牌 {shared:?} 同时关联多个槽位；将只删除槽位 {slot}，不使用 systemd-cryptenroll"
        ));
    }
    if ov.device.holds_root() {
        w.push("这是系统根分区所在设备，请确认下次开机仍有可用的解锁方式".into());
    }
    let remaining_knowledge = ov
        .knowledge_slots()
        .into_iter()
        .filter(|&k| k != slot)
        .count();
    if s.kind.is_knowledge() && remaining_knowledge == 1 {
        w.push("删除后只剩一个密码/恢复密钥槽位，建议额外生成一个恢复密钥并妥善保存".into());
    }
    Ok(w)
}

/// The slot an enrollment should replace must hold the same kind of key.
pub fn check_replace(ov: &Overview, replace: u32, kind: &SlotKind) -> Result<()> {
    match ov.slot(replace) {
        Some(s) if s.kind == *kind => Ok(()),
        Some(s) if s.is_empty() => blocked(format!("槽位 {replace} 是空的，无需替换")),
        Some(s) => blocked(format!(
            "槽位 {replace} 是“{}”，只能替换同类型（{}）的槽位",
            s.kind.label(),
            kind.label()
        )),
        None => blocked(format!("无效的槽位 {replace}")),
    }
}

pub fn check_priority(ov: &Overview, slot: u32, prio: Priority) -> Result<Vec<String>> {
    let Some(s) = ov.slot(slot).filter(|s| !s.is_empty()) else {
        return blocked(format!("槽位 {slot} 是空的"));
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
            return blocked(
                "“忽略”的槽位在开机输入密码时不会被尝试；这是最后一个未被忽略的密码槽位",
            );
        }
        return Ok(vec![
            "设为“忽略”后，开机时输入该密码将无法解锁（除非显式指定槽位）".into(),
        ]);
    }
    Ok(Vec::new())
}

/// Warning shown when enrolling a token while no knowledge slot exists.
pub fn token_only_warning(ov: &Overview) -> Option<String> {
    ov.knowledge_slots()
        .is_empty()
        .then(|| "当前没有任何密码/恢复密钥槽位！强烈建议先添加一个作为备用解锁方式".into())
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
        assert!(w.iter().any(|m| m.contains("非 ASCII")));
        assert!(check_new_passphrase(&Secret::from_text("short")).unwrap()[0].contains("8"));
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
        assert!(err.contains("最后一个密码"), "{err}");
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
                .contains("最后一个槽位")
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
