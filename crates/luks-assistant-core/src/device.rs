//! Discovery of LUKS block devices.

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::exec::Cmd;
use crate::t;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// One node of the `lsblk` tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockNode {
    pub path: String,
    /// `disk`, `part`, `crypt`, `lvm`, `raid1`, `loop`, ...
    pub kind: String,
    pub size: Option<String>,
    pub fstype: Option<String>,
    pub fsver: Option<String>,
    pub uuid: Option<String>,
    pub label: Option<String>,
    pub mountpoints: Vec<String>,
    /// Discard granularity / maximum as printed by lsblk ("4K", "0B").
    pub disc_gran: Option<String>,
    pub disc_max: Option<String>,
    pub rota: Option<bool>,
    pub model: Option<String>,
    pub children: Vec<BlockNode>,
}

impl BlockNode {
    pub fn is_luks(&self) -> bool {
        self.fstype.as_deref() == Some("crypto_LUKS")
    }

    /// Does the device accept discards (TRIM)? `None` if lsblk did not say.
    pub fn trim(&self) -> Option<bool> {
        self.disc_max.as_deref().map(|m| m != "0B" && m != "0")
    }

    /// The unlocked dm-crypt mapping below a LUKS node.
    pub fn mapping(&self) -> Option<&BlockNode> {
        self.children.iter().find(|c| c.kind == "crypt")
    }

    /// Short description of the encryption state for listings.
    pub fn encryption(&self) -> String {
        if self.is_luks() {
            let v = self
                .fsver
                .as_deref()
                .map(|v| format!("LUKS{v}"))
                .unwrap_or_else(|| "LUKS".into());
            match self.mapping() {
                Some(m) => t!("{} 已解锁 → {}", v, basename(&m.path)),
                None => t!("{} 未解锁", v),
            }
        } else if self.kind == "crypt" {
            t!("解密映射").into()
        } else {
            "—".into()
        }
    }

    fn ignored(&self) -> bool {
        matches!(self.kind.as_str(), "loop" | "rom")
            || self.path.starts_with("/dev/zram")
            || self.path.starts_with("/dev/ram")
    }
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// The full block device tree.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockTree {
    pub roots: Vec<BlockNode>,
}

impl BlockTree {
    /// Depth-first list of (depth, node).
    pub fn flatten(&self) -> Vec<(usize, &BlockNode)> {
        fn walk<'a>(n: &'a BlockNode, d: usize, out: &mut Vec<(usize, &'a BlockNode)>) {
            out.push((d, n));
            for c in &n.children {
                walk(c, d + 1, out);
            }
        }
        let mut out = Vec::new();
        for r in self.roots.iter().filter(|r| !r.ignored()) {
            walk(r, 0, &mut out);
        }
        out
    }

    /// (LUKS volumes, all local volumes). Volumes are partitions, whole
    /// disks without partitions and LVM/RAID volumes, not counting anything
    /// inside an unlocked LUKS mapping.
    pub fn volume_counts(&self) -> (usize, usize) {
        fn walk(n: &BlockNode, luks: &mut usize, total: &mut usize) {
            if n.kind == "crypt" {
                return;
            }
            let leaf_disk = n.kind == "disk" && (n.children.is_empty() || n.is_luks());
            if leaf_disk
                || n.kind == "part"
                || n.kind == "lvm"
                || n.kind.starts_with("raid")
                || n.kind == "md"
            {
                *total += 1;
                if n.is_luks() {
                    *luks += 1;
                }
            }
            if !n.is_luks() {
                for c in &n.children {
                    walk(c, luks, total);
                }
            }
        }
        let (mut luks, mut total) = (0, 0);
        for r in self.roots.iter().filter(|r| !r.ignored()) {
            walk(r, &mut luks, &mut total);
        }
        (luks, total)
    }

    pub fn luks_devices(&self) -> Vec<LuksDevice> {
        let mut out: Vec<LuksDevice> = Vec::new();
        for (_, n) in self.flatten() {
            if !n.is_luks() || out.iter().any(|d| d.path.as_os_str() == n.path.as_str()) {
                continue;
            }
            let mut mountpoints = Vec::new();
            if let Some(m) = n.mapping() {
                collect_mounts(m, &mut mountpoints);
            }
            out.push(LuksDevice {
                path: PathBuf::from(&n.path),
                size: n.size.clone(),
                uuid: n.uuid.clone(),
                version: n.fsver.clone(),
                mapping: n.mapping().map(|m| basename(&m.path).to_owned()),
                mountpoints,
                is_file: false,
            });
        }
        out
    }

    pub fn find(&self, path: &str) -> Option<&BlockNode> {
        self.flatten()
            .into_iter()
            .map(|(_, n)| n)
            .find(|n| n.path == path)
    }
}

fn collect_mounts(n: &BlockNode, out: &mut Vec<String>) {
    out.extend(n.mountpoints.iter().cloned());
    for c in &n.children {
        collect_mounts(c, out);
    }
}

/// Read the block device tree with `lsblk`.
pub fn block_tree(ctx: &Ctx) -> Result<BlockTree> {
    let full = "NAME,TYPE,FSTYPE,FSVER,UUID,LABEL,SIZE,MOUNTPOINT,DISC-GRAN,DISC-MAX,ROTA,MODEL";
    let out = ctx
        .runner
        .run(&Cmd::new("lsblk").args(["-J", "-p", "-o", full]))?;
    let out = if out.success() {
        out
    } else {
        // util-linux < 2.36 has no FSVER column
        ctx.runner
            .run(&Cmd::new("lsblk").args([
                "-J",
                "-p",
                "-o",
                "NAME,TYPE,FSTYPE,UUID,LABEL,SIZE,MOUNTPOINT",
            ]))?
            .check("lsblk")?
    };
    parse_tree(&out.stdout_lossy())
}

/// All LUKS devices known to lsblk.
pub fn discover(ctx: &Ctx) -> Result<Vec<LuksDevice>> {
    Ok(block_tree(ctx)?.luks_devices())
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_owned)
}

fn node(v: &Value) -> BlockNode {
    let mut mountpoints: Vec<String> = s(v, "mountpoint").into_iter().collect();
    if let Some(arr) = v.get("mountpoints").and_then(Value::as_array) {
        mountpoints.extend(arr.iter().filter_map(|x| x.as_str().map(str::to_owned)));
    }
    mountpoints.dedup();
    let rota = v
        .get("rota")
        .and_then(|r| r.as_bool().or_else(|| r.as_str().map(|s| s == "1")));
    BlockNode {
        path: s(v, "name").unwrap_or_default(),
        kind: s(v, "type").unwrap_or_default(),
        size: s(v, "size"),
        fstype: s(v, "fstype"),
        fsver: s(v, "fsver"),
        uuid: s(v, "uuid"),
        label: s(v, "label"),
        mountpoints,
        disc_gran: s(v, "disc-gran"),
        disc_max: s(v, "disc-max"),
        rota,
        model: s(v, "model").map(|m| m.trim().to_owned()),
        children: v
            .get("children")
            .and_then(Value::as_array)
            .map(|c| c.iter().map(node).collect())
            .unwrap_or_default(),
    }
}

pub fn parse_tree(json: &str) -> Result<BlockTree> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| Error::Parse(format!("lsblk: {e}").into()))?;
    Ok(BlockTree {
        roots: v
            .get("blockdevices")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(node).collect())
            .unwrap_or_default(),
    })
}

pub fn parse_lsblk(json: &str) -> Result<Vec<LuksDevice>> {
    Ok(parse_tree(json)?.luks_devices())
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

        let tree = parse_tree(json).unwrap();
        // nvme0n1p1, nvme0n1p2 (LUKS), sda (whole-disk LUKS)
        assert_eq!(tree.volume_counts(), (2, 3));
        assert_eq!(tree.flatten().len(), 5);
        assert_eq!(
            tree.find("/dev/nvme0n1p2").unwrap().encryption(),
            "LUKS2 已解锁 → cryptroot"
        );
    }

    #[test]
    fn trim_detection() {
        let json = r#"{"blockdevices":[
          {"name":"/dev/sda","type":"disk","size":"1T","disc-gran":"0B","disc-max":"0B","rota":"1"},
          {"name":"/dev/nvme0n1","type":"disk","size":"1T","disc-gran":"512B","disc-max":"2T","rota":false},
          {"name":"/dev/loop0","type":"loop","size":"1M"}
        ]}"#;
        let t = parse_tree(json).unwrap();
        assert_eq!(t.roots[0].trim(), Some(false));
        assert_eq!(t.roots[0].rota, Some(true));
        assert_eq!(t.roots[1].trim(), Some(true));
        assert_eq!(t.volume_counts(), (0, 2));
    }
}
