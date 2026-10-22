//! Distribution and kernel information.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Distribution families that differ in how they build the initramfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Family {
    Arch,
    Fedora,
    Debian,
    Suse,
    Other,
}

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Family::Arch => "Arch 系",
            Family::Fedora => "Fedora/RHEL 系",
            Family::Debian => "Debian/Ubuntu 系",
            Family::Suse => "openSUSE 系",
            Family::Other => "其它",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub pretty_name: String,
    pub id: String,
    pub id_like: Vec<String>,
    pub version_id: Option<String>,
    pub family: Family,
    pub kernel: String,
    pub hostname: String,
}

impl OsInfo {
    pub fn detect() -> Self {
        let text = std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .unwrap_or_default();
        let mut info = Self::from_os_release(&text);
        info.kernel = read_trim("/proc/sys/kernel/osrelease").unwrap_or_else(|| "?".into());
        info.hostname = read_trim("/proc/sys/kernel/hostname").unwrap_or_else(|| "?".into());
        info
    }

    pub fn from_os_release(text: &str) -> Self {
        let kv = parse_os_release(text);
        let id = kv.get("ID").cloned().unwrap_or_else(|| "linux".into());
        let id_like: Vec<String> = kv
            .get("ID_LIKE")
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let family = classify(&id, &id_like);
        OsInfo {
            pretty_name: kv
                .get("PRETTY_NAME")
                .or_else(|| kv.get("NAME"))
                .cloned()
                .unwrap_or_else(|| "Linux".into()),
            version_id: kv.get("VERSION_ID").cloned(),
            id,
            id_like,
            family,
            kernel: String::new(),
            hostname: String::new(),
        }
    }
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

fn classify(id: &str, id_like: &[String]) -> Family {
    let all = std::iter::once(id).chain(id_like.iter().map(String::as_str));
    for name in all {
        match name {
            "arch" | "manjaro" | "endeavouros" | "cachyos" | "garuda" => return Family::Arch,
            "fedora" | "rhel" | "centos" | "rocky" | "almalinux" => return Family::Fedora,
            "debian" | "ubuntu" | "linuxmint" | "pop" => return Family::Debian,
            "suse" | "opensuse" | "opensuse-tumbleweed" | "opensuse-leap" => return Family::Suse,
            _ => {}
        }
    }
    Family::Other
}

fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let (k, v) = line.split_once('=')?;
            let v = v.trim().trim_matches('"').trim_matches('\'');
            Some((k.trim().to_owned(), v.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ubuntu() {
        let os = OsInfo::from_os_release(
            "PRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n",
        );
        assert_eq!(os.pretty_name, "Ubuntu 24.04.5 LTS");
        assert_eq!(os.family, Family::Debian);
        assert_eq!(os.version_id.as_deref(), Some("24.04"));
    }

    #[test]
    fn classifies_derivatives() {
        let os = OsInfo::from_os_release("ID=endeavouros\nID_LIKE=arch\n");
        assert_eq!(os.family, Family::Arch);
        let os = OsInfo::from_os_release("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n");
        assert_eq!(os.family, Family::Fedora);
    }
}
