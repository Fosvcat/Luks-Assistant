//! Discovery of LUKS block devices.

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::exec::Cmd;
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct LuksDevice {
    pub path: PathBuf,
    pub size: Option<String>,
    pub uuid: Option<String>,
    /// LUKS version as reported by blkid ("1" / "2").
    pub version: Option<String>,
    /// Name of the active dm-crypt mapping (e.g. `cryptroot`), if unlocked.
    pub mapping: Option<String>,
    /// Mount points found below the mapping (filesystems, LVM volumes).
    pub mountpoints: Vec<String>,
    /// A regular file rather than a block device (header images, tests).
    pub is_file: bool,
}

impl LuksDevice {
    /// A device given explicitly by path (block device or image file).
    pub fn from_path(path: &Path) -> Self {
        let is_file = path.metadata().map(|m| m.is_file()).unwrap_or(false);
        LuksDevice {
            path: path.to_path_buf(),
            size: path
                .metadata()
                .ok()
                .filter(|_| is_file)
                .map(|m| human_size(m.len())),
            uuid: None,
            version: None,
            mapping: None,
            mountpoints: Vec::new(),
            is_file,
        }
    }

    pub fn display_name(&self) -> String {
        match &self.mapping {
            Some(m) => format!("{} ({m})", self.path.display()),
            None => self.path.display().to_string(),
        }
    }

    pub fn holds_root(&self) -> bool {
        self.mountpoints.iter().any(|m| m == "/")
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1}{}", UNITS[u])
}

/// All LUKS devices known to lsblk.
pub fn discover(ctx: &Ctx) -> Result<Vec<LuksDevice>> {
    let cols = "NAME,TYPE,FSTYPE,FSVER,UUID,SIZE,MOUNTPOINT";
    let out = ctx
        .runner
        .run(&Cmd::new("lsblk").args(["-J", "-p", "-o", cols]))?;
    let out = if out.success() {
        out
    } else {
        // util-linux < 2.36 has no FSVER column
        ctx.runner
            .run(&Cmd::new("lsblk").args([
                "-J",
                "-p",
                "-o",
                "NAME,TYPE,FSTYPE,UUID,SIZE,MOUNTPOINT",
            ]))?
            .check("lsblk")?
    };
    parse_lsblk(&out.stdout_lossy())
}

pub fn parse_lsblk(json: &str) -> Result<Vec<LuksDevice>> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error::Parse(format!("lsblk: {e}")))?;
    let mut out = Vec::new();
    if let Some(devs) = v.get("blockdevices").and_then(Value::as_array) {
        for d in devs {
            walk(d, &mut out);
        }
    }
    // A disk can appear several times below multipath/RAID members.
    out.dedup_by(|a, b| a.path == b.path);
    Ok(out)
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_owned)
}

fn walk(node: &Value, out: &mut Vec<LuksDevice>) {
    let children = node.get("children").and_then(Value::as_array);
    if s(node, "fstype").as_deref() == Some("crypto_LUKS") {
        let mapping_node = children.and_then(|c| {
            c.iter()
                .find(|ch| s(ch, "type").as_deref() == Some("crypt"))
        });
        let mut mountpoints = Vec::new();
        if let Some(m) = mapping_node {
            collect_mounts(m, &mut mountpoints);
        }
        out.push(LuksDevice {
            path: PathBuf::from(s(node, "name").unwrap_or_default()),
            size: s(node, "size"),
            uuid: s(node, "uuid"),
            version: s(node, "fsver"),
            mapping: mapping_node
                .and_then(|m| s(m, "name"))
                .map(|n| n.rsplit('/').next().unwrap_or(&n).to_owned()),
            mountpoints,
            is_file: false,
        });
    }
    if let Some(ch) = children {
        for c in ch {
            walk(c, out);
        }
    }
}

fn collect_mounts(node: &Value, out: &mut Vec<String>) {
    if let Some(m) = s(node, "mountpoint") {
        out.push(m);
    }
    if let Some(arr) = node.get("mountpoints").and_then(Value::as_array) {
        out.extend(arr.iter().filter_map(|x| x.as_str().map(str::to_owned)));
    }
    if let Some(ch) = node.get("children").and_then(Value::as_array) {
        for c in ch {
            collect_mounts(c, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_luks_partitions() {
        let json = r#"{"blockdevices":[
          {"name":"/dev/nvme0n1","type":"disk","fstype":null,"uuid":null,"size":"1.8T","mountpoint":null,"children":[
            {"name":"/dev/nvme0n1p1","type":"part","fstype":"vfat","uuid":"AB12","size":"1G","mountpoint":"/boot"},
            {"name":"/dev/nvme0n1p2","type":"part","fstype":"crypto_LUKS","fsver":"2","uuid":"4f1e","size":"1.8T","mountpoint":null,"children":[
              {"name":"/dev/mapper/cryptroot","type":"crypt","fstype":"btrfs","uuid":"x","size":"1.8T","mountpoint":"/"}
            ]}
          ]},
          {"name":"/dev/sda","type":"disk","fstype":"crypto_LUKS","fsver":"1","uuid":"old","size":"500G","mountpoint":null}
        ]}"#;
        let devs = parse_lsblk(json).unwrap();
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].path, PathBuf::from("/dev/nvme0n1p2"));
        assert_eq!(devs[0].mapping.as_deref(), Some("cryptroot"));
        assert!(devs[0].holds_root());
        assert_eq!(devs[1].version.as_deref(), Some("1"));
        assert!(devs[1].mapping.is_none());
    }
}
