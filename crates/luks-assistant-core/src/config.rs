//! Persistent settings in `<etc_dir>/config.json`.

use crate::error::Result;
use crate::tx;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Directory for header backups (`<dir>/<UUID>/*.img`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_dir: Option<PathBuf>,
}

impl Config {
    pub fn path(etc_dir: &Path) -> PathBuf {
        etc_dir.join("config.json")
    }

    pub fn load(etc_dir: &Path) -> Self {
        std::fs::read(Self::path(etc_dir))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, etc_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(etc_dir)?;
        let data = serde_json::to_vec_pretty(self).expect("serializable");
        crate::util::write_atomic(&Self::path(etc_dir), &data, 0o644)?;
        Ok(())
    }
}

/// Change the backup directory and apply it to `paths`. An empty path
/// restores the default.
pub fn set_backup_dir(paths: &mut crate::ctx::Paths, dir: Option<PathBuf>) -> Result<()> {
    if let Some(d) = &dir {
        if !d.is_absolute() {
            return Err(crate::Error::Invalid(tx!(
                "The backup directory must be an absolute path"
            )));
        }
    }
    let mut cfg = Config::load(&paths.etc_dir);
    cfg.backup_dir = dir.clone();
    cfg.save(&paths.etc_dir)?;
    paths.backup_root = dir.unwrap_or_else(|| paths.default_backup_root());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_dir_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = crate::ctx::Paths::under(dir.path());
        assert_eq!(paths.backup_root, dir.path().join("state/backups"));
        set_backup_dir(&mut paths, Some("/mnt/usb/luks".into())).unwrap();
        assert_eq!(paths.backups_dir("u"), PathBuf::from("/mnt/usb/luks/u"));
        let again = crate::ctx::Paths::under(dir.path());
        assert_eq!(again.backup_root, PathBuf::from("/mnt/usb/luks"));
        assert!(set_backup_dir(&mut paths, Some("rel".into())).is_err());
        set_backup_dir(&mut paths, None).unwrap();
        assert_eq!(
            crate::ctx::Paths::under(dir.path()).backup_root,
            dir.path().join("state/backups")
        );
    }
}
