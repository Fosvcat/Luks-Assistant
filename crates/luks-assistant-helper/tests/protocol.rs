//! Drives the helper binary over its stdin/stdout like the GUI does.
//! Skipped unless running as root with cryptsetup installed.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

struct Helper {
    child: std::process::Child,
    out: BufReader<std::process::ChildStdout>,
    next: u64,
    events: Vec<Value>,
}

impl Helper {
    fn call(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let mut msg = json!({"id": self.next, "method": method});
        if !params.is_null() {
            msg["params"] = params;
        }
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
        loop {
            let mut line = String::new();
            assert!(self.out.read_line(&mut line).unwrap() > 0, "helper exited");
            let v: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["id"], self.next);
            if v.get("event").is_some() {
                self.events.push(v["event"].clone());
                continue;
            }
            return v;
        }
    }
}

#[test]
fn plan_execute_and_guards_over_the_wire() {
    let ok = luks_assistant_sysinfo::is_root()
        && Command::new("cryptsetup")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("skipping: needs root and cryptsetup");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    std::fs::File::create(&img)
        .unwrap()
        .set_len(32 << 20)
        .unwrap();
    let mut fmt = Command::new("cryptsetup")
        .args([
            "luksFormat",
            "--type",
            "luks2",
            "-q",
            "--key-file=-",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
        ])
        .arg(&img)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    fmt.stdin.take().unwrap().write_all(b"first").unwrap();
    assert!(fmt.wait().unwrap().success());

    let mut child = Command::new(env!("CARGO_BIN_EXE_Luks-Assistant-Helper"))
        .arg("--etc-dir")
        .arg(dir.path().join("etc"))
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--fast-kdf")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    let mut h = Helper {
        child,
        out,
        next: 0,
        events: Vec::new(),
    };
    let path = img.to_string_lossy().to_string();

    let hello = h.call("hello", Value::Null);
    assert_eq!(hello["ok"]["protocol"], 1);

    let ov = h.call("overview", json!({"path": path}));
    assert_eq!(ov["ok"]["overview"]["slots"].as_array().unwrap().len(), 32);

    let plan = h.call(
        "plan",
        json!({"path": path, "request": {"AddPassphrase": {
            "auth": {"Passphrase": "first"}, "new": "second-pass", "slot": 4,
            "kdf": "Default", "note": {"text": "via helper", "location": "Header"}}}}),
    );
    let id = plan["ok"]["id"].as_u64().expect("plan id");
    // secrets never appear in the plan view
    assert!(!plan.to_string().contains("second-pass"));

    let done = h.call("execute", json!({"plans": [id], "confirm": ""}));
    assert_eq!(done["ok"][0]["ok"], true, "{done}");
    assert!(h.events.iter().any(|e| e["kind"] == "progress"));
    assert!(h.call("execute", json!({"plans": [id], "confirm": ""}))["err"].is_string());

    let v = h.call(
        "verify_credential",
        json!({"path": path, "credential": {"Passphrase": "second-pass"}}),
    );
    assert_eq!(v["ok"], 4);

    // a wrong confirmation word is refused and the plan stays available
    let rm = h.call("plan", json!({"path": path, "request": {"RemoveSlot": {"slot": 4, "auth": {"Passphrase": "first"}}}}));
    let rid = rm["ok"]["id"].as_u64().unwrap();
    assert_eq!(rm["ok"]["confirm_word"], "4");
    assert!(h.call("execute", json!({"plans": [rid], "confirm": "x"}))["err"].is_string());
    assert_eq!(
        h.call("execute", json!({"plans": [rid], "confirm": "4"}))["ok"][0]["ok"],
        true
    );

    // the last passphrase slot cannot be removed
    let last = h.call("plan", json!({"path": path, "request": {"RemoveSlot": {"slot": 0, "auth": {"Passphrase": "first"}}}}));
    assert!(last["err"].as_str().unwrap().contains("Blocked"), "{last}");

    // the GUI path: views, then a generated form filled in and submitted
    let sys = h.call("system_view", json!({"extra": [path]}));
    assert_eq!(sys["ok"]["pcrs"].as_array().unwrap().len(), 24);
    assert_eq!(sys["ok"]["picker"][0]["selectable"], true);
    let dev = h.call("device_view", json!({"path": path}));
    let slots = dev["ok"]["device"]["slots"].as_array().unwrap();
    assert_eq!(slots.len(), 32);
    assert_eq!(slots[0]["kind"], "secret");
    let add = slots[5]["actions"][0].clone();
    assert_eq!(add["label"], "Add password");
    let mut form = h.call("build_form", json!({"path": path, "kind": add["form"]}))["ok"].clone();
    for f in form["fields"].as_array_mut().unwrap() {
        let v = match f["key"].as_str().unwrap() {
            "auth_pw" => Some(json!({"Secret": "first"})),
            "new" | "new2" => Some(json!({"Secret": "third-pass"})),
            "note" => Some(json!({"Text": "form"})),
            _ => None,
        };
        if let Some(v) = v {
            f["value"] = v;
        }
    }
    let sub = h.call("submit_form", json!({"path": path, "form": form}));
    assert_eq!(sub["ok"]["kind"], "plan", "{sub}");
    let pid = sub["ok"]["id"].as_u64().unwrap();
    assert_eq!(
        h.call("execute", json!({"plans": [pid], "confirm": ""}))["ok"][0]["ok"],
        true
    );
    let dev = h.call("device_view", json!({"path": path}));
    assert_eq!(dev["ok"]["device"]["slots"][1]["subtitle"], "form");

    let mut verify = h.call("build_form", json!({"path": path, "kind": "Verify"}))["ok"].clone();
    for f in verify["fields"].as_array_mut().unwrap() {
        if f["key"] == "auth_pw" {
            f["value"] = json!({"Secret": "third-pass"});
        }
    }
    let msg = h.call("submit_form", json!({"path": path, "form": verify}));
    assert_eq!(msg["ok"]["kind"], "message");
    assert_eq!(msg["ok"]["ok"], true);
    assert!(
        msg["ok"]["text"].as_str().unwrap().contains("Slot 1"),
        "{msg}"
    );
    assert!(
        h.call("pcr_notes", json!({"pcrs": [7]}))["ok"][0]
            .as_str()
            .unwrap()
            .contains("PCRs 7")
    );
    let rows = h.call("backup_rows", json!({"paths": [path]}));
    assert!(rows["ok"][0]["count"].as_u64().unwrap() >= 1);

    drop(h.child.stdin.take());
    assert!(h.child.wait().unwrap().success());
}
