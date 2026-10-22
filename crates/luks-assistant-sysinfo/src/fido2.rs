//! FIDO2 security key and PKCS#11 token detection.

/// FIDO2 devices as listed by `systemd-cryptenroll --fido2-device=list`,
/// one "path manufacturer product" string per device.
pub fn list_devices() -> Vec<String> {
    crate::tpm::list_devices("--fido2-device=list")
}

/// PKCS#11 tokens as listed by `systemd-cryptenroll --pkcs11-token-uri=list`.
pub fn list_pkcs11() -> Vec<String> {
    match crate::cmd::run("systemd-cryptenroll", &["--pkcs11-token-uri=list"]) {
        Some(o) if o.success => parse_pkcs11(&o.stdout),
        _ => Vec::new(),
    }
}

/// Rows of the token table; each row starts with its `pkcs11:` URI.
pub fn parse_pkcs11(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("pkcs11:"))
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_pkcs11_table() {
        let t = "URI                                   LABEL   MANUFACTURER MODEL\npkcs11:model=PKCS%2315;token=card  card    Yubico       PIV\n";
        assert_eq!(
            super::parse_pkcs11(t),
            vec!["pkcs11:model=PKCS%2315;token=card card Yubico PIV"]
        );
        assert!(super::parse_pkcs11("No suitable PKCS#11 tokens found.").is_empty());
    }
}
