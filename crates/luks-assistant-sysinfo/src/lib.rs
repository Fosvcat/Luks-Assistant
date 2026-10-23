//! System probing for Luks Assistant: distribution, tool versions and capabilities,
//! firmware / Secure Boot state, TPM2 and FIDO2 devices, PCR values and a
//! simple boot-chain check.
//!
//! Everything in this crate is read-only.

pub mod bootcheck;
pub mod cmd;
pub mod fido2;
pub mod firmware;
pub mod i18n;
pub mod os;
pub mod tools;
pub mod tpm;

use serde::{Deserialize, Serialize};

/// A snapshot of everything we know about the running system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os: os::OsInfo,
    pub tools: tools::Tools,
    pub caps: tools::Caps,
    pub firmware: firmware::Firmware,
    pub tpm: tpm::TpmInfo,
    pub is_root: bool,
}

impl SystemInfo {
    pub fn probe() -> Self {
        let tools = tools::Tools::detect();
        let caps = tools::Caps::from_tools(&tools);
        SystemInfo {
            os: os::OsInfo::detect(),
            caps,
            tools,
            firmware: firmware::Firmware::detect(),
            tpm: tpm::TpmInfo::detect(),
            is_root: is_root(),
        }
    }
}

/// Name the process "Luks-Assistant" in ps, top and crash reports; the
/// binary names are longer than the kernel's 15 characters.
pub fn set_process_name() {
    // SAFETY: PR_SET_NAME reads a NUL-terminated string of at most 16 bytes.
    unsafe {
        libc::prctl(libc::PR_SET_NAME, c"Luks-Assistant".as_ptr());
    }
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}
