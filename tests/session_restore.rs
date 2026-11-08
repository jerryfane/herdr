//! Session restore must not wait for optional repository metadata.
#![cfg(unix)]

pub mod support;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct RestoredServer {
    child: std::process::Child,
    base: PathBuf,
}

impl Drop for RestoredServer {
    fn drop(&mut self) {
        let pid = self.child.id();
        let _ = self.child.kill();
        let _ = self.child.wait();
        support::unregister_spawned_herdr_pid(Some(pid));
        support::cleanup_test_base(&self.base);
    }
}

fn restore_request(socket_path: &Path, method: &str) -> serde_json::Value {
    let response = restore_request_with_params(socket_path, method, serde_json::json!({}));
    assert!(response.get("error").is_none(), "{response}");
    response
}

fn restore_request_with_params(
    socket_path: &Path,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket_path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(
        stream,
        "{}",
        serde_json::json!({"id": "restore", "method": method, "params": params})
    )
    .unwrap();
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .unwrap_or_else(|err| panic!("{method} blocked during session restore: {err}"));
    serde_json::from_str(&line).unwrap()
}

#[test]
fn server_restores_while_git_metadata_is_blocked() {
    use std::os::unix::fs::OpenOptionsExt;

    for saved_membership in [false, true] {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = PathBuf::from(format!("/tmp/herdr-restore-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let base = fs::canonicalize(base).unwrap();
        let config_home = base.join("config");
        let runtime_dir = base.join("runtime");
        let socket_path = runtime_dir.join("herdr.sock");
        let data_dir = config_home.join(if cfg!(debug_assertions) {
            "herdr-dev"
        } else {
            "herdr"
        });
        let repo = base.join("repo");
        fs::create_dir_all(repo.join(".git/objects")).unwrap();
        fs::create_dir_all(&data_dir).unwrap();
        fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        let config_path = repo.join(".git/config");
        assert!(Command::new("mkfifo")
            .arg(&config_path)
            .status()
            .unwrap()
            .success());
        // Keep the FIFO open without writing: metadata reads cannot finish until
        // this guard drops, so API readiness must not depend on a lucky delay.
        let _blocked_metadata = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&config_path)
            .unwrap();
        let membership = saved_membership.then(|| {
            serde_json::json!({
                "key": "saved-repo", "label": "saved-space", "repo_root": repo,
                "checkout_path": repo, "is_linked_worktree": false
            })
        });
        let healthy = base.join("healthy");
        assert!(Command::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .arg(&healthy)
            .status()
            .unwrap()
            .success());
        let healthy_membership = serde_json::json!({
            "key": healthy.join(".git"), "label": "healthy", "repo_root": healthy,
            "checkout_path": healthy, "is_linked_worktree": false
        });
        let snapshot = serde_json::json!({
            "version": 3, "active": 0, "selected": 0,
            "workspaces": [{
                "id": "w1", "custom_name": "restored", "identity_cwd": repo,
                "worktree_space": membership,
                "public_pane_numbers": {"7": 3}, "public_tab_numbers": [2],
                "tabs": [{"layout": {"Pane": 7}, "panes": {"7": {"cwd": repo}},
                          "zoomed": false, "focused": 7, "root_pane": 7}]
            }, {
                "id": "w2", "custom_name": "healthy", "identity_cwd": healthy,
                "worktree_space": healthy_membership,
                "tabs": [{"layout": {"Pane": 9}, "panes": {"9": {"cwd": healthy}},
                          "zoomed": false, "focused": 9, "root_pane": 9}]
            }]
        });
        fs::write(data_dir.join("session.json"), snapshot.to_string()).unwrap();
        fs::write(data_dir.join("config.toml"),
            "onboarding = false\n[terminal]\ndefault_shell = \"/bin/sh\"\n[ui.sidebar.spaces]\nrows = [[\"workspace\"]]\n").unwrap();
        support::register_runtime_dir(&runtime_dir);
        let child = Command::new(env!("CARGO_BIN_EXE_herdr"))
            .arg("server")
            .env("XDG_CONFIG_HOME", &config_home)
            .env("XDG_RUNTIME_DIR", &runtime_dir)
            .env("HERDR_SOCKET_PATH", &socket_path)
            .env("SHELL", "/bin/sh")
            .env_remove("HERDR_CLIENT_SOCKET_PATH")
            .env_remove("HERDR_STARTUP_CWD")
            .env_remove("HERDR_SESSION")
            .env_remove("HERDR_ENV")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        support::register_spawned_herdr_pid(Some(child.id()));
        let mut herdr = RestoredServer { child, base };
        support::wait_for_socket(&socket_path, Duration::from_secs(5));

        let workspaces = restore_request(&socket_path, "workspace.list");
        let restored = &workspaces["result"]["workspaces"][0];
        assert_eq!(restored["workspace_id"], "w1");
        assert_eq!(restored["label"], "restored");
        assert_eq!(restored["active_tab_id"], "w1:t2");
        assert_eq!(restored["pane_count"], 1);
        if saved_membership {
            for (method, params) in [
                (
                    "worktree.create",
                    serde_json::json!({"workspace_id": "w1", "branch": "blocked"}),
                ),
                (
                    "worktree.open",
                    serde_json::json!({"workspace_id": "w1", "branch": "main"}),
                ),
                ("worktree.list", serde_json::json!({"workspace_id": "w1"})),
                (
                    "worktree.remove",
                    serde_json::json!({"workspace_id": "w1", "force": true}),
                ),
            ] {
                let response = restore_request_with_params(&socket_path, method, params);
                assert_eq!(
                    response["error"]["code"], "worktree_operation_in_progress",
                    "{method}: {response}"
                );
            }
        }
        if saved_membership {
            // A blocked saved membership must not keep unrelated saved
            // memberships pending or prevent their worktree operations.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let response = restore_request_with_params(
                    &socket_path,
                    "worktree.list",
                    serde_json::json!({"workspace_id": "w2"}),
                );
                if response.get("error").is_none() {
                    break;
                }
                assert_eq!(response["error"]["code"], "worktree_operation_in_progress");
                assert!(
                    std::time::Instant::now() < deadline,
                    "healthy workspace validation waited for another checkout's blocked metadata"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        restore_request(&socket_path, "session.snapshot");
        restore_request(&socket_path, "agent.list");
        restore_request(&socket_path, "server.stop");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = herdr.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "server shutdown waited for blocked Git metadata"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(data_dir.join("session.json")).unwrap()).unwrap();
        assert_eq!(
            saved["workspaces"][0]["identity_cwd"],
            snapshot["workspaces"][0]["identity_cwd"]
        );
        assert_eq!(
            saved["workspaces"][0]["worktree_space"],
            snapshot["workspaces"][0]["worktree_space"]
        );
        drop(herdr);
    }
}

/// A scratch server restored from `snapshot`, with a fake `omp` on PATH that stays in the
/// foreground, so a resumed omp agent is a real process the pane APIs can see.
fn start_agent_restore_server(
    name: &str,
    snapshot: impl FnOnce(&Path, &Path) -> serde_json::Value,
    default_shell: &str,
) -> (RestoredServer, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = PathBuf::from(format!("/tmp/herdr-{name}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    let base = fs::canonicalize(base).unwrap();
    let home = base.join("home");
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let socket_path = runtime_dir.join("herdr.sock");
    let bin = base.join("bin");
    let project = base.join("project");
    let data_dir = config_home.join(if cfg!(debug_assertions) {
        "herdr-dev"
    } else {
        "herdr"
    });
    for dir in [&home, &bin, &project, &data_dir] {
        fs::create_dir_all(dir).unwrap();
    }
    let omp = bin.join("omp");
    fs::write(&omp, "#!/bin/sh\nexec sleep 600\n").unwrap();
    fs::set_permissions(&omp, fs::Permissions::from_mode(0o755)).unwrap();
    let session = home.join("session.jsonl");
    fs::write(&session, "{}\n").unwrap();

    fs::write(
        data_dir.join("session.json"),
        snapshot(&project, &session).to_string(),
    )
    .unwrap();
    fs::write(
        data_dir.join("config.toml"),
        format!("onboarding = false\n[terminal]\ndefault_shell = {default_shell:?}\n"),
    )
    .unwrap();
    support::register_runtime_dir(&runtime_dir);
    let mut command = Command::new(env!("CARGO_BIN_EXE_herdr"));
    command
        .arg("server")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .env("HERDR_SOCKET_PATH", &socket_path)
        .env("SHELL", "/bin/sh")
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
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
    let herdr = RestoredServer { child, base };
    support::wait_for_socket(&socket_path, Duration::from_secs(5));
    (herdr, socket_path)
}

fn omp_agent_pane(project: &Path, session: &Path, name: &str) -> serde_json::Value {
    serde_json::json!({
        "cwd": project, "agent_name": name, "managed_agent_kind": "omp",
        "agent_session": {"source": "herdr:omp", "agent": "omp", "kind": "path", "value": session}
    })
}

fn restored_agent(socket_path: &Path, name: &str) -> serde_json::Value {
    let agents = restore_request(socket_path, "agent.list");
    agents["result"]["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["name"] == name)
        .unwrap_or_else(|| panic!("agent {name} missing from agent.list: {agents}"))
        .clone()
}

/// The outage of 2026-11-08: agents in the last pane of a deep split chain never came
/// back after a cold restore. Their pane's interior was 0 columns (or rows) wide, the
/// deferred resume spawned the terminal at that size, libghostty-vt refused the 0-wide
/// grid ("ghostty error -2"), and the agent stayed listed with no process behind it.
#[test]
fn deferred_agent_resume_starts_in_a_zero_width_pane() {
    let (_herdr, socket_path) = start_agent_restore_server(
        "resume-zero",
        |project, session| {
            // Seven nested halvings, as on the affected tab: the innermost pair gets
            // no columns once borders are drawn.
            let mut layout = serde_json::json!({"Pane": 1});
            layout = serde_json::json!({"Split": {
                "direction": "Horizontal", "ratio": 0.5, "first": layout, "second": {"Pane": 2}
            }});
            let mut panes = serde_json::Map::new();
            panes.insert("1".into(), serde_json::json!({"cwd": project}));
            panes.insert("2".into(), omp_agent_pane(project, session, "deep"));
            for pane in 3..=8 {
                layout = serde_json::json!({"Split": {
                    "direction": "Horizontal", "ratio": 0.5, "first": layout,
                    "second": {"Pane": pane}
                }});
                panes.insert(pane.to_string(), serde_json::json!({"cwd": project}));
            }
            serde_json::json!({
                "version": 3, "active": 0, "selected": 0,
                "workspaces": [{"id": "w1", "custom_name": "deep", "identity_cwd": project,
                    "tabs": [{"layout": layout, "panes": panes, "zoomed": false,
                              "focused": 2, "root_pane": 1}]}]
            })
        },
        "/bin/sh",
    );

    let pane_id = restored_agent(&socket_path, "deep")["pane_id"].clone();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let info = restore_request_with_params(
            &socket_path,
            "pane.process_info",
            serde_json::json!({"pane_id": pane_id}),
        );
        if info.get("error").is_none() {
            assert_eq!(info["result"]["process_info"]["pane_id"], pane_id);
            break;
        }
        let agent = restored_agent(&socket_path, "deep");
        assert!(
            agent.get("restore_error").is_none() && agent["agent_status"] != "unknown",
            "deferred resume failed in the zero-width pane: {agent}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the agent in the zero-width pane never got a process: {info}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// When a deferred resume cannot start its shell, the agent must stop reporting the
/// `idle` it was restored with: every API that names the pane has to agree that nothing
/// runs there, so callers stop treating it as a live recipient.
#[test]
fn failed_deferred_agent_resume_reports_the_agent_as_unavailable() {
    let (_herdr, socket_path) = start_agent_restore_server(
        "resume-fail",
        |project, session| {
            serde_json::json!({
                "version": 3, "active": 0, "selected": 0,
                "workspaces": [{"id": "w1", "custom_name": "ghost", "identity_cwd": project,
                    "tabs": [{"layout": {"Pane": 1},
                              "panes": {"1": omp_agent_pane(project, session, "ghost")},
                              "zoomed": false, "focused": 1, "root_pane": 1}]}]
            })
        },
        "/nonexistent/herdr-test-shell",
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let agent = loop {
        let agent = restored_agent(&socket_path, "ghost");
        if agent.get("restore_error").is_some() || agent["agent_status"] == "unknown" {
            break agent;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a failed resume kept reporting a live agent: {agent}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(agent["agent_status"], "unknown", "{agent}");
    let reason = agent["restore_error"].as_str().unwrap();
    assert!(
        reason.starts_with("Could not start the saved shell"),
        "{agent}"
    );

    let pane_id = &agent["pane_id"];
    let pane = restore_request_with_params(
        &socket_path,
        "pane.get",
        serde_json::json!({"pane_id": pane_id}),
    );
    assert_eq!(pane["result"]["pane"]["terminal_id"], agent["terminal_id"]);
    assert_eq!(pane["result"]["pane"]["agent_status"], "unknown");
    assert_eq!(pane["result"]["pane"]["restore_error"], reason);

    let info = restore_request_with_params(
        &socket_path,
        "pane.process_info",
        serde_json::json!({"pane_id": pane_id}),
    );
    assert_eq!(info["error"]["code"], "pane_unavailable", "{info}");
    assert!(
        info["error"]["message"].as_str().unwrap().ends_with(reason),
        "{info}"
    );

    let prompt = restore_request_with_params(
        &socket_path,
        "agent.prompt",
        serde_json::json!({"target": "ghost", "text": "hello"}),
    );
    assert_eq!(prompt["error"]["code"], "agent_not_found", "{prompt}");
    assert!(
        prompt["error"]["message"]
            .as_str()
            .unwrap()
            .contains("has no running process"),
        "{prompt}"
    );
}

/// A named agent whose saved directory is gone is restored without ever detecting its
/// agent, so the readiness guards alone would call it "not an active named agent". A
/// prompt must instead fail the way `agent.list` and `pane.process_info` describe it:
/// nothing runs there, and here is why.
#[test]
fn prompting_an_agent_whose_saved_directory_is_gone_reports_the_restore_reason() {
    let (_herdr, socket_path) = start_agent_restore_server(
        "resume-gone",
        |project, session| {
            let gone = project.join("deleted");
            serde_json::json!({
                "version": 3, "active": 0, "selected": 0,
                "workspaces": [{"id": "w1", "custom_name": "gone", "identity_cwd": project,
                    "tabs": [{"layout": {"Pane": 1},
                              "panes": {"1": omp_agent_pane(&gone, session, "gone")},
                              "zoomed": false, "focused": 1, "root_pane": 1}]}]
            })
        },
        "/bin/sh",
    );

    let agent = restored_agent(&socket_path, "gone");
    assert_eq!(agent["agent_status"], "unknown", "{agent}");
    let reason = agent["restore_error"].as_str().unwrap();
    assert!(
        reason.starts_with("Saved directory is unavailable"),
        "{agent}"
    );

    let prompt = restore_request_with_params(
        &socket_path,
        "agent.prompt",
        serde_json::json!({"target": "gone", "text": "hello"}),
    );
    assert_eq!(prompt["error"]["code"], "agent_not_found", "{prompt}");
    assert!(
        prompt["error"]["message"]
            .as_str()
            .unwrap()
            .ends_with(reason),
        "{prompt}"
    );
}
