//! LUKS2 header model, read through `cryptsetup luksDump`.

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::exec::Cmd;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    /// Never used unless explicitly selected (`--key-slot`).
    Ignore,
    Normal,
    /// Tried before normal slots.
    Prefer,
}

impl Priority {
    pub fn from_json(v: Option<&Value>) -> Self {
        match v.and_then(Value::as_u64) {
            Some(0) => Priority::Ignore,
            Some(2) => Priority::Prefer,
            _ => Priority::Normal,
        }
    }

    pub fn as_arg(self) -> &'static str {
        match self {
            Priority::Ignore => "ignore",
            Priority::Normal => "normal",
            Priority::Prefer => "prefer",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Priority::Ignore => "忽略",
            Priority::Normal => "普通",
            Priority::Prefer => "优先",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kdf {
    pub kind: String,
    pub hash: Option<String>,
    pub iterations: Option<u64>,
    pub time: Option<u64>,
    /// KiB
    pub memory: Option<u64>,
    pub cpus: Option<u64>,
    pub salt: String,
}

impl Kdf {
    pub fn summary(&self) -> String {
        match self.kind.as_str() {
            "pbkdf2" => format!(
                "pbkdf2-{} {} 次迭代",
                self.hash.as_deref().unwrap_or("?"),
                self.iterations.unwrap_or(0)
            ),
            k => format!(
                "{k} t={} m={}MiB p={}",
                self.time.unwrap_or(0),
                self.memory.unwrap_or(0) / 1024,
                self.cpus.unwrap_or(0)
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keyslot {
    pub id: u32,
    /// `luks2` for normal slots, `reencrypt` during online reencryption.
    pub kind: String,
    pub key_size: u64,
    pub priority: Priority,
    pub kdf: Kdf,
    pub area_encryption: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: u32,
    pub kind: String,
    pub keyslots: Vec<u32>,
    /// Full JSON object, for type-specific fields.
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub id: u32,
    pub kind: String,
    pub encryption: Option<String>,
    pub sector_size: Option<u64>,
    pub offset: Option<String>,
    pub size: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    pub id: u32,
    pub kind: String,
    pub keyslots: Vec<u32>,
    pub segments: Vec<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub json_size: u64,
    pub keyslots_size: u64,
    /// Persistent activation flags (e.g. `allow-discards`).
    pub flags: Vec<String>,
    pub requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub version: u32,
    pub uuid: String,
    pub label: Option<String>,
    pub subsystem: Option<String>,
    pub keyslots: BTreeMap<u32, Keyslot>,
    pub tokens: BTreeMap<u32, Token>,
    pub segments: Vec<Segment>,
    pub digests: Vec<Digest>,
    pub config: Config,
    /// Size of the JSON metadata when serialized compactly; compared with
    /// `config.json_size` before writing notes.
    pub json_used: usize,
}

impl Header {
    pub fn is_luks2(&self) -> bool {
        self.version == 2
    }

    /// Tokens that reference `slot`.
    pub fn tokens_for(&self, slot: u32) -> impl Iterator<Item = &Token> {
        self.tokens
            .values()
            .filter(move |t| t.keyslots.contains(&slot))
    }

    pub fn free_slots(&self) -> impl Iterator<Item = u32> + '_ {
        (0..crate::MAX_SLOTS).filter(|i| !self.keyslots.contains_key(i))
    }

    /// Highest unused token id (luks-assistant keeps low ids for systemd, which
    /// takes the lowest free one).
    pub fn free_token_id_high(&self) -> Option<u32> {
        (0..crate::MAX_SLOTS)
            .rev()
            .find(|i| !self.tokens.contains_key(i))
    }

    pub fn allows_discards(&self) -> bool {
        self.config.flags.iter().any(|f| f == "allow-discards")
    }
}

/// Fields from the text dump that are not part of the JSON metadata.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TextInfo {
    pub version: u32,
    pub uuid: String,
    pub label: Option<String>,
    pub subsystem: Option<String>,
}

pub fn parse_text_dump(text: &str) -> Result<TextInfo> {
    let mut info = TextInfo::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        let opt = |v: &str| (!v.starts_with('(') && !v.is_empty()).then(|| v.to_owned());
        match k.trim() {
            "Version" if info.version == 0 => info.version = v.parse().unwrap_or(0),
            "UUID" if info.uuid.is_empty() => info.uuid = v.to_owned(),
            "Label" => info.label = opt(v),
            "Subsystem" => info.subsystem = opt(v),
            _ => {}
        }
    }
    if info.version == 0 || info.uuid.is_empty() {
        return Err(Error::Parse("luksDump 输出中缺少 Version/UUID".into()));
    }
    Ok(info)
}

fn ids(v: Option<&Value>) -> Vec<u32> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    x.as_str()
                        .and_then(|s| s.parse().ok())
                        .or_else(|| x.as_u64().map(|n| n as u32))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn num_field(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|x| {
        x.as_u64()
            .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
    })
}

fn objects(v: &Value, key: &str) -> Vec<(u32, Value)> {
    let mut out: Vec<(u32, Value)> = v
        .get(key)
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.parse().ok()?, v.clone())))
                .collect()
        })
        .unwrap_or_default();
    out.sort_by_key(|(k, _)| *k);
    out
}

/// Build a header from the text dump info and the JSON metadata.
pub fn parse(info: TextInfo, json: &str) -> Result<Header> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| Error::Parse(format!("JSON 元数据: {e}")))?;
    let keyslots = objects(&v, "keyslots")
        .into_iter()
        .map(|(id, k)| {
            let kdf = k.get("kdf").cloned().unwrap_or(Value::Null);
            let ks = Keyslot {
                id,
                kind: str_field(&k, "type").unwrap_or_default(),
                key_size: num_field(&k, "key_size").unwrap_or(0),
                priority: Priority::from_json(k.get("priority")),
                kdf: Kdf {
                    kind: str_field(&kdf, "type").unwrap_or_default(),
                    hash: str_field(&kdf, "hash"),
                    iterations: num_field(&kdf, "iterations"),
                    time: num_field(&kdf, "time"),
                    memory: num_field(&kdf, "memory"),
                    cpus: num_field(&kdf, "cpus"),
                    salt: str_field(&kdf, "salt").unwrap_or_default(),
                },
                area_encryption: k.get("area").and_then(|a| str_field(a, "encryption")),
            };
            (id, ks)
        })
        .collect();
    let tokens = objects(&v, "tokens")
        .into_iter()
        .map(|(id, t)| {
            let tok = Token {
                id,
                kind: str_field(&t, "type").unwrap_or_default(),
                keyslots: ids(t.get("keyslots")),
                raw: t,
            };
            (id, tok)
        })
        .collect();
    let segments = objects(&v, "segments")
        .into_iter()
        .map(|(id, s)| Segment {
            id,
            kind: str_field(&s, "type").unwrap_or_default(),
            encryption: str_field(&s, "encryption"),
            sector_size: num_field(&s, "sector_size"),
            offset: str_field(&s, "offset"),
            size: str_field(&s, "size"),
        })
        .collect();
    let digests = objects(&v, "digests")
        .into_iter()
        .map(|(id, d)| Digest {
            id,
            kind: str_field(&d, "type").unwrap_or_default(),
            keyslots: ids(d.get("keyslots")),
            segments: ids(d.get("segments")),
        })
        .collect();
    let cfg = v.get("config").cloned().unwrap_or(Value::Null);
    let strings = |x: Option<&Value>| -> Vec<String> {
        x.and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let config = Config {
        json_size: num_field(&cfg, "json_size").unwrap_or(0),
        keyslots_size: num_field(&cfg, "keyslots_size").unwrap_or(0),
        flags: strings(cfg.get("flags")),
        requirements: strings(cfg.get("requirements").and_then(|r| r.get("mandatory"))),
    };
    Ok(Header {
        version: info.version,
        uuid: info.uuid,
        label: info.label,
        subsystem: info.subsystem,
        keyslots,
        tokens,
        segments,
        digests,
        config,
        json_used: serde_json::to_string(&v).map(|s| s.len()).unwrap_or(0),
    })
}

/// Header of a LUKS1 device: only the text dump is available.
fn luks1(info: TextInfo, text: &str) -> Header {
    let mut keyslots = BTreeMap::new();
    for line in text.lines() {
        // "Key Slot 0: ENABLED"
        if let Some(rest) = line.trim().strip_prefix("Key Slot ") {
            if let Some((n, state)) = rest.split_once(':') {
                if state.trim() == "ENABLED" {
                    if let Ok(id) = n.trim().parse::<u32>() {
                        keyslots.insert(
                            id,
                            Keyslot {
                                id,
                                kind: "luks1".into(),
                                key_size: 0,
                                priority: Priority::Normal,
                                kdf: Kdf {
                                    kind: "pbkdf2".into(),
                                    hash: None,
                                    iterations: None,
                                    time: None,
                                    memory: None,
                                    cpus: None,
                                    salt: String::new(),
                                },
                                area_encryption: None,
                            },
                        );
                    }
                }
            }
        }
    }
    Header {
        version: info.version,
        uuid: info.uuid,
        label: None,
        subsystem: None,
        keyslots,
        tokens: BTreeMap::new(),
        segments: Vec::new(),
        digests: Vec::new(),
        config: Config::default(),
        json_used: 0,
    }
}

/// Read the header of `device` (a block device or an image file).
pub fn read(ctx: &Ctx, device: &Path) -> Result<Header> {
    let dev = device.to_string_lossy().into_owned();
    let text = ctx
        .runner
        .run(&Cmd::new("cryptsetup").args(["luksDump", dev.as_str()]))?
        .check("cryptsetup luksDump")?
        .stdout_lossy();
    let info = parse_text_dump(&text)?;
    if info.version != 2 {
        return Ok(luks1(info, &text));
    }
    if !ctx.caps.json_dump {
        return Err(Error::Unsupported(
            "需要 cryptsetup ≥ 2.4 才能导出 JSON 元数据".into(),
        ));
    }
    let json = ctx
        .runner
        .run(&Cmd::new("cryptsetup").args(["luksDump", "--dump-json-metadata", dev.as_str()]))?
        .check("cryptsetup luksDump --dump-json-metadata")?
        .stdout_lossy();
    parse(info, &json)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const TEXT: &str = "LUKS header information\nVersion:       \t2\nEpoch:         \t5\nMetadata area: \t16384 [bytes]\nKeyslots area: \t16744448 [bytes]\nUUID:          \t4f1e7a1c-2f47-4d0c-9a59-35b4f0d2c111\nLabel:         \t(no label)\nSubsystem:     \t(no subsystem)\nFlags:       \tallow-discards\n\nData segments:\n";

    pub const JSON: &str = r#"{
  "keyslots":{
    "0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"argon2id","time":4,"memory":1048576,"cpus":4,"salt":"AAAAsaltzero0000000000000000000000000000000="}},
    "1":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"290816","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"pbkdf2","hash":"sha512","iterations":1000,"salt":"BBBBsaltone00000000000000000000000000000000="}},
    "2":{"type":"luks2","key_size":64,"priority":2,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"548864","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"pbkdf2","hash":"sha512","iterations":1000,"salt":"CCCCsalttwo00000000000000000000000000000000="}},
    "3":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"806912","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"pbkdf2","hash":"sha512","iterations":1000,"salt":"DDDDsaltthree000000000000000000000000000000="}},
    "5":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"1064960","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"argon2id","time":4,"memory":1048576,"cpus":4,"salt":"EEEEsaltfive0000000000000000000000000000000="}}
  },
  "tokens":{
    "0":{"type":"systemd-recovery","keyslots":["1"]},
    "1":{"type":"systemd-tpm2","keyslots":["2"],"tpm2-blob":"AAAA","tpm2-pcrs":[0,7],"tpm2-pcr-bank":"sha256","tpm2-primary-alg":"ecc","tpm2-policy-hash":"44f59fc517b8e3f33c65335139f041a99aab7dd77be06f4f912508e6a8f2166c","tpm2-pin":false,"tpm2_pcrlock":false},
    "2":{"type":"systemd-fido2","keyslots":["3"],"fido2-credential":"AAAA","fido2-salt":"AAAA","fido2-rp":"io.systemd.cryptsetup","fido2-clientPin-required":true,"fido2-up-required":true,"fido2-uv-required":false},
    "7":{"type":"orphan-test","keyslots":[]},
    "31":{"type":"luks-assistant-notes","keyslots":[],"version":1,"notes":{"0":{"text":"主密码","kind":"passphrase","fp":"AAAAsaltzero0000","updated":1}}}
  },
  "segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":512}},
  "digests":{"0":{"type":"pbkdf2","keyslots":["0","1","2","3","5"],"segments":["0"],"hash":"sha256","iterations":1000,"salt":"x","digest":"y"}},
  "config":{"json_size":"12288","keyslots_size":"16744448","flags":["allow-discards"]}
}"#;

    pub fn sample() -> Header {
        parse(parse_text_dump(TEXT).unwrap(), JSON).unwrap()
    }

    #[test]
    fn parses_header() {
        let h = sample();
        assert_eq!(h.version, 2);
        assert_eq!(h.uuid, "4f1e7a1c-2f47-4d0c-9a59-35b4f0d2c111");
        assert_eq!(h.label, None);
        assert_eq!(h.keyslots.len(), 5);
        assert_eq!(h.keyslots[&2].priority, Priority::Prefer);
        assert_eq!(h.keyslots[&0].kdf.memory, Some(1_048_576));
        assert_eq!(h.tokens[&1].keyslots, vec![2]);
        assert!(h.tokens[&7].keyslots.is_empty());
        assert_eq!(h.config.json_size, 12288);
        assert!(h.allows_discards());
        assert_eq!(h.free_slots().next(), Some(4));
        assert_eq!(h.free_token_id_high(), Some(30));
        assert_eq!(h.segments[0].sector_size, Some(512));
        assert!(h.json_used > 1000);
    }

    #[test]
    fn parses_luks1_text() {
        let t = "LUKS header information for x\n\nVersion:       \t1\nCipher name:   \taes\nUUID:          \tabc\n\nKey Slot 0: ENABLED\n\tIterations: 1\nKey Slot 1: DISABLED\nKey Slot 2: ENABLED\n";
        let info = parse_text_dump(t).unwrap();
        let h = luks1(info, t);
        assert_eq!(h.version, 1);
        assert_eq!(h.keyslots.keys().copied().collect::<Vec<_>>(), vec![0, 2]);
    }
}
