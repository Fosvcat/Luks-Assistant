//! Execution context shared by all operations.

use crate::exec::{Runner, SystemRunner};
use luks_assistant_sysinfo::tools::{Caps, Tools};
use std::path::{Path, PathBuf};

/// Where luks-assistant keeps its own files.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Paths {
    /// Configuration and local slot notes (default `/etc/luks-assistant`).
    pub etc_dir: PathBuf,
    /// PCR snapshots, the operation log and the lock file (default `/var/lib/luks-assistant`).
    pub state_dir: PathBuf,
    /// Header backups go to `<backup_root>/<UUID>/` (default
    /// `<state_dir>/backups`, configurable in `<etc_dir>/config.json`).
    pub backup_root: PathBuf,
}

impl Paths {
    /// Defaults, overridable with `LUKS_ASSISTANT_ETC_DIR` / `LUKS_ASSISTANT_STATE_DIR`
    /// (used by tests and for development without root).
    pub fn from_env() -> Self {
        let etc_dir: PathBuf = std::env::var_os("LUKS_ASSISTANT_ETC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/etc/luks-assistant".into());
        let state_dir: PathBuf = std::env::var_os("LUKS_ASSISTANT_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/var/lib/luks-assistant".into());
        Self::with_config(etc_dir, state_dir)
    }

    pub fn under(root: &Path) -> Self {
        Self::with_config(root.join("etc"), root.join("state"))
    }

    fn with_config(etc_dir: PathBuf, state_dir: PathBuf) -> Self {
        let config = crate::config::Config::load(&etc_dir);
        Paths {
            backup_root: config
                .backup_dir
                .unwrap_or_else(|| state_dir.join("backups")),
            etc_dir,
            state_dir,
        }
    }

    pub fn default_backup_root(&self) -> PathBuf {
        self.state_dir.join("backups")
    }

    pub fn local_notes(&self, uuid: &str) -> PathBuf {
        self.etc_dir.join("notes").join(format!("{uuid}.json"))
    }

    pub fn backups_dir(&self, uuid: &str) -> PathBuf {
        self.backup_root.join(uuid)
    }

    pub fn pcr_snapshots(&self, uuid: &str) -> PathBuf {
        self.state_dir
            .join("pcr-snapshots")
            .join(format!("{uuid}.json"))
    }

    pub fn history_log(&self) -> PathBuf {
        self.state_dir.join("history.log")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.state_dir.join("lock")
    }
}

pub struct Ctx {
    pub runner: Box<dyn Runner>,
    pub paths: Paths,
    pub caps: Caps,
    pub tools: Tools,
    /// Value for systemd-cryptenroll `--tpm2-device=` (`auto`, a device
    /// node, or a TCTI spec such as `swtpm:host=127.0.0.1,port=2321`).
    pub tpm2_device: String,
    /// Extra cryptsetup arguments appended when a new key slot is written
    /// (`--pbkdf ...`). Empty means cryptsetup's defaults.
    pub extra_kdf_args: Vec<String>,
}

impl Ctx {
    /// Context for the running system.
    ///
    /// Environment overrides for development:
    /// * `LUKS_ASSISTANT_TPM2_DEVICE` — TPM device / TCTI (default `auto`)
    /// * `LUKS_ASSISTANT_FAST_KDF=1` — weak PBKDF2 for new slots (tests only!)
    pub fn system() -> Self {
        let tools = Tools::detect();
        let caps = Caps::from_tools(&tools);
        let fast = std::env::var("LUKS_ASSISTANT_FAST_KDF").is_ok_and(|v| v == "1");
        Ctx {
            runner: Box::new(SystemRunner),
            paths: Paths::from_env(),
            caps,
            tools,
            tpm2_device: std::env::var("LUKS_ASSISTANT_TPM2_DEVICE").unwrap_or_else(|_| "auto".into()),
            extra_kdf_args: if fast { fast_kdf_args() } else { Vec::new() },
        }
    }
}

/// Deliberately weak KDF settings so integration tests run quickly.
pub fn fast_kdf_args() -> Vec<String> {
    ["--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"]
        .map(String::from)
        .to_vec()
}
