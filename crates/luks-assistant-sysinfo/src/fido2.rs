//! FIDO2 security key detection.

/// FIDO2 devices as listed by `systemd-cryptenroll --fido2-device=list`,
/// one "path manufacturer product" string per device.
pub fn list_devices() -> Vec<String> {
    crate::tpm::list_devices("--fido2-device=list")
}
