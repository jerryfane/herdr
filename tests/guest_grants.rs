//! A guest's grant follows its agent's harness session to the terminal the agent was
//! recreated in (the outage of 2026-11-08), on a real scratch server: its own HOME, XDG
//! dirs and socket, inherited `HERDR_*` removed, a fake `omp` on PATH, and a guest relay
//! that is never reached.
#![cfg(unix)]

pub mod support;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// The directories of one scratch server, kept across its restarts.
struct Scratch {
    base: PathBuf,
    home: PathBuf,
    config_home: PathBuf,
    runtime_dir: PathBuf,
    socket_path: PathBuf,
    bin: PathBuf,
    project: PathBuf,
    data_dir: PathBuf,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        support::cleanup_test_base(&self.base);
    }
}

struct Server {
    child: Child,
    socket_path: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let pid = self.child.id();
        // A clean stop saves the session, as a restart by the owner would.
        let _ = UnixStream::connect(&self.socket_path).and_then(|mut stream| {
            writeln!(
                stream,
                "{}",
                json!({"id": "stop", "method": "server.stop", "params": {}})
            )
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        support::unregister_spawned_herdr_pid(Some(pid));
    }
}

impl Scratch {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = PathBuf::from(format!("/tmp/herdr-{name}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let base = fs::canonicalize(base).unwrap();
        let config_home = base.join("config");
        let runtime_dir = base.join("runtime");
        let scratch = Self {
            home: base.join("home"),
            socket_path: runtime_dir.join("herdr.sock"),
            bin: base.join("bin"),
            project: base.join("project"),
            data_dir: config_home.join(if cfg!(debug_assertions) {
                "herdr-dev"
            } else {
                "herdr"
            }),
            config_home,
            runtime_dir,
            base,
        };
        for dir in [
            &scratch.home,
            &scratch.bin,
            &scratch.project,
            &scratch.data_dir,
        ] {
            fs::create_dir_all(dir).unwrap();
        }
        // Not `exec`: the pane's foreground process stays `omp`.
        let omp = scratch.bin.join("omp");
        fs::write(&omp, "#!/bin/sh\nsleep 600\n").unwrap();
        fs::set_permissions(&omp, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            scratch.data_dir.join("config.toml"),
            "onboarding = false\n[terminal]\ndefault_shell = \"/bin/sh\"\n\
             [guest]\nrelay_url = \"http://127.0.0.1:9\"\n",
        )
        .unwrap();
        scratch
    }

    /// An omp session file, as the agent's conversation.
    fn session(&self, name: &str) -> String {
        let path = self.home.join(format!("{name}.jsonl"));
        fs::write(&path, "{}\n").unwrap();
        path.display().to_string()
    }

    /// The session to restore: one tab splitting `panes` side by side.
    fn write_session(&self, panes: &[Value]) {
        let mut layout = json!({"Pane": 1});
        let mut map = serde_json::Map::new();
        map.insert("1".into(), panes[0].clone());
        for (index, pane) in panes.iter().enumerate().skip(1) {
            let id = index + 1;
            layout = json!({"Split": {
                "direction": "Vertical", "ratio": 0.5, "first": layout, "second": {"Pane": id}
            }});
            map.insert(id.to_string(), pane.clone());
        }
        let snapshot = json!({
            "version": 3, "active": 0, "selected": 0,
            "workspaces": [{"id": "w1", "custom_name": "fleet", "identity_cwd": self.project,
                "tabs": [{"layout": layout, "panes": map, "zoomed": false,
                          "focused": 1, "root_pane": 1}]}]
        });
        fs::write(self.data_dir.join("session.json"), snapshot.to_string()).unwrap();
    }

    /// A named omp agent on `session` in terminal `terminal_id`.
    fn omp_pane(&self, terminal_id: &str, name: &str, session: &str) -> Value {
        json!({
            "cwd": self.project, "agent_name": name, "managed_agent_kind": "omp",
            "terminal_id": terminal_id,
            "agent_session": {"source": "herdr:omp", "agent": "omp", "kind": "path", "value": session}
        })
    }

    /// The guest store: these guests and pending invites.
    fn write_guests(&self, guests: &[Value], invites: &[Value]) {
        let dir = self.data_dir.join("guest");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("guests.json");
        fs::write(
            &path,
            json!({"guests": guests, "invites": invites}).to_string(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn start(&self) -> Server {
        support::register_runtime_dir(&self.runtime_dir);
        let mut command = Command::new(env!("CARGO_BIN_EXE_herdr"));
        command
            .arg("server")
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("HERDR_SOCKET_PATH", &self.socket_path)
            .env("SHELL", "/bin/sh")
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            );
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("HERDR_") && key != "HERDR_SOCKET_PATH" {
                command.env_remove(key);
            }
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        support::register_spawned_herdr_pid(Some(child.id()));
        let server = Server {
            child,
            socket_path: self.socket_path.clone(),
        };
        support::wait_for_socket(&self.socket_path, Duration::from_secs(5));
        server
    }

    fn request(&self, method: &str, params: Value) -> Value {
        let mut stream = UnixStream::connect(&self.socket_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        writeln!(
            stream,
            "{}",
            json!({"id": "t", "method": method, "params": params})
        )
        .unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert!(response.get("error").is_none(), "{method}: {response}");
        response["result"].clone()
    }

    fn agent(&self, name: &str) -> Value {
        let agents = self.request("agent.list", json!({}));
        agents["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["name"] == name)
            .unwrap_or_else(|| panic!("agent {name} missing: {agents}"))
            .clone()
    }

    /// The stored guest or invite with this id, as `guest.list` shows it.
    fn listed(&self, kind: &str, id: &str) -> Value {
        let list = self.request("guest.list", json!({}));
        let key = if kind == "guests" {
            "guest_id"
        } else {
            "invite_id"
        };
        list[kind]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry[key] == id)
            .unwrap_or_else(|| panic!("{id} missing from guest.list: {list}"))
            .clone()
    }

    /// Wait until the guest's grant names `terminal_id`.
    fn wait_for_grant(&self, guest_id: &str, terminal_id: &str) {
        let followed =
            support::wait_until(Duration::from_secs(10), Duration::from_millis(50), || {
                self.listed("guests", guest_id)["grant"]["terminal_id"] == terminal_id
            });
        assert!(
            followed,
            "the grant stayed on its gone terminal instead of following its agent to \
             {terminal_id}: {}",
            self.listed("guests", guest_id)
        );
    }
}

fn grant(terminal_id: &str, name: &str, session: &str) -> Value {
    json!({
        "terminal_id": terminal_id, "agent_name": name, "agent_kind": "omp",
        "agent_session": {"source": "herdr:omp", "agent": "omp", "kind": "path", "value": session}
    })
}

/// An accepted guest of the agent `grant` names, on its own device.
fn guest(guest_id: &str, grant: Value, revoked: bool) -> Value {
    json!({
        "guest_id": guest_id, "name": "nike", "device_pub": format!("device-{guest_id}"),
        "fingerprint": format!("SHA256:{guest_id}"), "device": "iPhone", "grant": grant,
        "owner_name": "Jerry", "machine_label": "dev", "created_ms": 1, "last_seen_ms": 1,
        "revoked": revoked, "revoked_ms": revoked.then_some(2), "share_gram": false
    })
}

/// A pending invite to the agent `grant` names.
fn invite(invite_id: &str, grant: Value) -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    json!({
        "invite_id": invite_id, "secret_sha256": "00", "name": "nike", "grant": grant,
        "owner_name": "Jerry", "machine_label": "dev", "created_ms": now,
        "expires_ms": now + 3_600_000, "used_by": null, "share_gram": false
    })
}

/// The outage: the server came back without the shared agent's terminal, and the owner
/// recreated the agent in a new one on the same omp session. The guest's grant and a
/// pending invite follow it there once the server starts, with no step by the owner, and
/// stay there across the next restart.
#[test]
fn a_grant_follows_its_agent_recreated_in_a_new_terminal_across_restarts() {
    let scratch = Scratch::new("grant-restart");
    let tino = scratch.session("tino");
    scratch.write_session(&[scratch.omp_pane("term_recreated.b", "tino", &tino)]);
    scratch.write_guests(
        &[guest("g-tino", grant("term_gone.7", "tino", &tino), false)],
        &[invite("i-tino", grant("term_gone.7", "tino", &tino))],
    );

    let server = scratch.start();
    assert_eq!(scratch.agent("tino")["terminal_id"], "term_recreated.b");
    scratch.wait_for_grant("g-tino", "term_recreated.b");
    let listed = scratch.listed("guests", "g-tino");
    assert_eq!(listed["revoked"], false, "{listed}");
    assert_eq!(listed["grant"]["agent_name"], "tino", "{listed}");
    assert_eq!(
        scratch.listed("invites", "i-tino")["grant"]["terminal_id"],
        "term_recreated.b"
    );
    drop(server);

    let _server = scratch.start();
    assert_eq!(scratch.agent("tino")["terminal_id"], "term_recreated.b");
    let listed = scratch.listed("guests", "g-tino");
    assert_eq!(
        listed["grant"]["terminal_id"], "term_recreated.b",
        "{listed}"
    );
    assert_eq!(listed["revoked"], false, "{listed}");
}

/// The owner closes the shared agent's pane and resumes its omp session in another pane
/// while the server runs: the grant follows as soon as the agent reports that session.
#[test]
fn a_grant_follows_its_agent_recreated_while_the_server_runs() {
    let scratch = Scratch::new("grant-live");
    let tino = scratch.session("tino");
    let spare = scratch.session("spare");
    scratch.write_session(&[
        scratch.omp_pane("term_first.1", "tino", &tino),
        scratch.omp_pane("term_second.2", "spare", &spare),
    ]);
    scratch.write_guests(
        &[guest("g-tino", grant("term_first.1", "tino", &tino), false)],
        &[],
    );
    let _server = scratch.start();
    let first = scratch.agent("tino")["pane_id"].clone();
    let second = scratch.agent("spare")["pane_id"].clone();
    assert_eq!(
        scratch.listed("guests", "g-tino")["grant"]["terminal_id"],
        "term_first.1"
    );

    scratch.request("pane.close", json!({"pane_id": first}));
    scratch.request(
        "pane.report_agent_session",
        json!({"pane_id": second, "source": "herdr:omp", "agent": "omp", "seq": 1,
               "agent_session_path": tino}),
    );
    scratch.request("agent.rename", json!({"target": second, "name": "tino"}));

    scratch.wait_for_grant("g-tino", "term_second.2");
    let listed = scratch.listed("guests", "g-tino");
    assert_eq!(listed["grant"]["agent_name"], "tino", "{listed}");
    assert_eq!(listed["revoked"], false, "{listed}");
}

/// Next to a grant that follows its agent (proof the server looked), nothing else moves:
/// not a grant whose name came back on another omp session, not one whose session two
/// terminals hold, not a revoked guest's.
#[test]
fn only_an_active_grant_with_one_exact_session_holder_follows() {
    let scratch = Scratch::new("grant-guard");
    let moved = scratch.session("moved");
    let renewed = scratch.session("renewed");
    let shared = scratch.session("shared");
    let twin = scratch.session("twin");
    scratch.write_session(&[
        scratch.omp_pane("term_moved.1", "moved", &moved),
        // The granted name, but a new conversation.
        scratch.omp_pane("term_named.2", "tino", &renewed),
        scratch.omp_pane("term_shared.3", "ui", &shared),
        scratch.omp_pane("term_twin.4", "ui-twin", &twin),
    ]);
    let _server = scratch.start();
    // Restore never resumes one session twice: the twin takes it after startup.
    let twin_pane = scratch.agent("ui-twin")["pane_id"].clone();
    scratch.request(
        "pane.report_agent_session",
        json!({"pane_id": twin_pane, "source": "herdr:omp", "agent": "omp", "seq": 1,
               "agent_session_path": shared}),
    );
    let old_tino = scratch.session("old-tino");
    scratch.write_guests(
        &[
            guest("g-moved", grant("term_gone.1", "moved", &moved), false),
            guest("g-other", grant("term_gone.2", "tino", &old_tino), false),
            guest("g-twin", grant("term_gone.3", "ui", &shared), false),
            guest("g-revoked", grant("term_gone.4", "moved", &moved), true),
        ],
        &[],
    );
    // Any agent change makes the server look again.
    let moved_pane = scratch.agent("moved")["pane_id"].clone();
    scratch.request(
        "agent.rename",
        json!({"target": moved_pane, "name": "moved-on"}),
    );

    scratch.wait_for_grant("g-moved", "term_moved.1");
    for (guest_id, terminal_id) in [
        ("g-other", "term_gone.2"),
        ("g-twin", "term_gone.3"),
        ("g-revoked", "term_gone.4"),
    ] {
        let listed = scratch.listed("guests", guest_id);
        assert_eq!(listed["grant"]["terminal_id"], terminal_id, "{listed}");
    }
    assert_eq!(scratch.listed("guests", "g-revoked")["revoked"], true);
}
