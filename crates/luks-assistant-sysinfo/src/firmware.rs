//! UEFI and Secure Boot state.

use crate::t;
use serde::{Deserialize, Serialize};
use std::path::Path;

const EFI_GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Firmware {
    pub uefi: bool,
    /// `None` when the variable cannot be read (BIOS boot, efivarfs not mounted).
    pub secure_boot: Option<bool>,
    pub setup_mode: Option<bool>,
}

impl Firmware {
    pub fn detect() -> Self {
        let uefi = Path::new("/sys/firmware/efi").is_dir();
        Firmware {
            uefi,
            secure_boot: uefi.then(|| read_efi_bool("SecureBoot")).flatten(),
            setup_mode: uefi.then(|| read_efi_bool("SetupMode")).flatten(),
        }
    }

    pub fn secure_boot_label(&self) -> &'static str {
        match (self.uefi, self.secure_boot, self.setup_mode) {
            (false, _, _) => t!("Legacy BIOS"),
            (true, Some(true), _) => t!("enabled"),
            (true, Some(false), Some(true)) => t!("disabled (Setup Mode)"),
            (true, Some(false), _) => t!("disabled"),
            (true, None, _) => t!("unknown"),
        }
    }
}

/// efivarfs files start with a 4-byte attribute word followed by the data.
fn read_efi_bool(name: &str) -> Option<bool> {
    let path = format!("/sys/firmware/efi/efivars/{name}-{EFI_GLOBAL_GUID}");
    let data = std::fs::read(path).ok()?;
    data.get(4).map(|b| *b == 1)
}
