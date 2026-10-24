//! Small helpers without external dependencies.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// UTC civil date of a unix timestamp: (year, month, day, hour, minute, second).
pub fn civil(ts: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (ts / 86_400) as i64;
    let secs = ts % 86_400;
    // Howard Hinnant's days_from_civil inverse.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        m,
        d,
        (secs / 3600) as u32,
        ((secs % 3600) / 60) as u32,
        (secs % 60) as u32,
    )
}

/// `2026-10-22 14:05:09 UTC`
pub fn format_time(ts: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(ts);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

/// `20261022-140509`, used in file names.
pub fn stamp(ts: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(ts);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

/// Quote a shell word for display purposes.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c))
    {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Write `data` to `path` atomically (temp file + rename) with mode `mode`.
pub fn write_atomic(path: &std::path::Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Create `dir` (and parents) and restrict it to `mode`.
/// A non-root user who started us through pkexec or sudo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
}

/// The user behind `pkexec` (`PKEXEC_UID`) or `sudo` (`SUDO_UID`), unless
/// that is root.
pub fn invoking_user() -> Option<User> {
    let uid: u32 = std::env::var("PKEXEC_UID")
        .or_else(|_| std::env::var("SUDO_UID"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if uid == 0 {
        return None;
    }
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: the buffers outlive the call; `found` points into them on success.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() {
        return None;
    }
    // SAFETY: on success pw_name is a NUL-terminated string inside `buf`.
    let name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) }
        .to_string_lossy()
        .into_owned();
    Some(User {
        uid,
        gid: pw.pw_gid,
        name,
    })
}

/// Hand `path` to `user` (owner and group).
pub fn chown(path: &std::path::Path, user: &User) -> std::io::Result<()> {
    std::os::unix::fs::chown(path, Some(user.uid), Some(user.gid))
}

pub fn ensure_private_dir(dir: &std::path::Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_time(1_792_677_909), "2026-10-22 14:05:09 UTC");
        assert_eq!(stamp(951_782_400), "20000229-000000");
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("/dev/nvme0n1p2"), "/dev/nvme0n1p2");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }
}
