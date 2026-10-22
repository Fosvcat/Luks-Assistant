//! Secrets (passphrases, PINs, generated keys) that are wiped from memory
//! when dropped and never printed.

use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(Zeroizing::new(bytes))
    }

    pub fn from_text(s: &str) -> Self {
        Secret::new(s.as_bytes().to_vec())
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<{} bytes>)", self.0.len())
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Secret::new(s.into_bytes())
    }
}

// Secrets cross the GUI → helper pipe as plain strings. Never serialize a
// Secret anywhere else.
impl serde::Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&String::from_utf8_lossy(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Secret::from(s))
    }
}
