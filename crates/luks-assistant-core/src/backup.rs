//! Header backup files.

use crate::ctx::Paths;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFile {
    pub path: PathBuf,
    /// Modification time (unix seconds).
    pub modified: u64,
    pub size: u64,
}

/// Backups of the device with `uuid`, newest first.
pub fn list(paths: &Paths, uuid: &str) -> Vec<BackupFile> {
    let mut out: Vec<BackupFile> = std::fs::read_dir(paths.backups_dir(uuid))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| {
                    let meta = e.metadata().ok()?;
                    meta.is_file().then(|| BackupFile {
                        path: e.path(),
                        modified: meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                        size: meta.len(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| b.modified.cmp(&a.modified).then(b.path.cmp(&a.path)));
    out
}
