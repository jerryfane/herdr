//! `herdr server stop` / `herdr session stop` run inside a pane must not stop
//! the server hosting that pane unless forced (#383). Every server here is a
//! scratch server on its own socket under the test's base dir.

use super::harness::*;

struct PaneRun {
    code: i32,
    stderr: String,
}

fn create_root_pane(socket_path: &Path, cwd: &Path) -> String {
    let created = send_request(
        socket_path,
        &format!(
            r#"{{"id":"stop_guard_ws","method":"workspace.create","params":{{"cwd":"{}","focus":true}}}}"#,
            cwd.display()
        ),
    );
    created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap_or_else(|| panic!("workspace.create returned no root pane: {created}"))
        .to_string()
}

fn herdr_in_pane_command(base: &Path, label: &str, prefix: &str, args: &str) -> (String, PathBuf) {
    let stderr = base.join(format!("{label}.stderr"));
    let code = base.join(format!("{label}.code"));
    let command = format!(
        "{prefix}'{bin}' {args} >/dev/null 2>'{stderr}'; echo $? >'{code}.tmp'; mv '{code}.tmp' '{code}'",
        bin = env!("CARGO_BIN_EXE_herdr"),
        stderr = stderr.display(),
        code = code.display(),
    );
    (command, code)
}

/// Types `herdr <args>` into the pane's shell, so it runs with the pane's own
/// environment (`HERDR_ENV`, `HERDR_PANE_ID`, inherited `HERDR_SOCKET_PATH`),
/// and waits for its exit code.
fn run_herdr_in_pane(
    socket_path: &Path,
    pane_id: &str,
    base: &Path,
    label: &str,
    prefix: &str,
    args: &str,
) -> PaneRun {
    let (command, code) = herdr_in_pane_command(base, label, prefix, args);
    send_to_pane(socket_path, pane_id, &command);
    assert!(
        wait_until(Duration::from_secs(20), Duration::from_millis(25), || code
            .exists()),
        "`herdr {args}` in pane {pane_id} did not finish"
    );
    PaneRun {
        code: fs::read_to_string(&code).unwrap().trim().parse().unwrap(),
        stderr: fs::read_to_string(base.join(format!("{label}.stderr"))).unwrap(),
    }
}

fn send_to_pane(socket_path: &Path, pane_id: &str, command: &str) {
    let ran = run_cli_outside_pane(socket_path, &["pane", "run", pane_id, command]);
    assert!(
        ran.status.success(),
        "pane run failed: {}",
        String::from_utf8_lossy(&ran.stderr)
    );
}

/// The test runner may itself live in a Herdr pane; strip that identity.
fn run_cli_outside_pane(socket_path: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_herdr"))
        .args(args)
        .env("HERDR_SOCKET_PATH", socket_path)
        .env_remove("HERDR_PANE_ID")
        .env_remove("HERDR_ENV")
        .env_remove("HERDR_SESSION")
        .output()
        .unwrap()
}

fn server_answers(socket_path: &Path) -> bool {
    run_cli_outside_pane(socket_path, &["pane", "list"])
        .status
        .success()
}

#[test]
fn server_stop_in_a_pane_refuses_its_own_server_until_forced() {
    let base = unique_test_dir();
    let runtime_dir = base.join("runtime");
    let socket_path = runtime_dir.join("herdr.sock");
    let mut herdr = spawn_herdr(&base.join("config"), &runtime_dir, &socket_path);
    wait_for_socket(&socket_path, Duration::from_secs(5));
    let pane_id = create_root_pane(&socket_path, &base);

    let refused = run_herdr_in_pane(&socket_path, &pane_id, &base, "plain", "", "server stop");
    assert_eq!(refused.code, 1, "stderr: {}", refused.stderr);
    for expected in [
        socket_path.display().to_string(),
        "from inherited HERDR_SOCKET_PATH".to_string(),
        format!("HERDR_PANE_ID={pane_id}"),
        "--force".to_string(),
    ] {
        assert!(
            refused.stderr.contains(&expected),
            "refusal should mention {expected:?}: {}",
            refused.stderr
        );
    }
    assert!(
        server_answers(&socket_path),
        "the refused stop must leave the hosting server running"
    );

    // The pane dies with its server, so only the server's exit is observable.
    let (forced, _) = herdr_in_pane_command(&base, "forced", "", "server stop --force");
    send_to_pane(&socket_path, &pane_id, &forced);
    let pid = herdr.child.process_id();
    let status = herdr.child.wait().unwrap();
    unregister_spawned_herdr_pid(pid);
    assert!(status.success(), "--force should stop the server cleanly");
    assert!(!server_answers(&socket_path));

    cleanup_spawned_herdr(herdr, base);
}

#[test]
fn server_stop_in_a_pane_stops_another_server_with_the_same_pane_id() {
    let base = unique_test_dir();
    let runtime_a = base.join("runtime");
    let socket_a = runtime_a.join("herdr.sock");
    let runtime_b = base.join("runtime-b");
    let socket_b = runtime_b.join("herdr.sock");
    let herdr_a = spawn_herdr(&base.join("config"), &runtime_a, &socket_a);
    let mut herdr_b = spawn_herdr(&base.join("config-b"), &runtime_b, &socket_b);
    wait_for_socket(&socket_a, Duration::from_secs(5));
    wait_for_socket(&socket_b, Duration::from_secs(5));
    let pane_a = create_root_pane(&socket_a, &base);
    let pane_b = create_root_pane(&socket_b, &base);
    // B has a pane under the caller's HERDR_PANE_ID, so only the process
    // check can tell B is not the caller's host.
    assert_eq!(pane_a, pane_b);

    let stopped = run_herdr_in_pane(
        &socket_a,
        &pane_a,
        &base,
        "other",
        &format!("HERDR_SOCKET_PATH='{}' ", socket_b.display()),
        "server stop",
    );
    assert_eq!(stopped.code, 0, "stderr: {}", stopped.stderr);
    let pid = herdr_b.child.process_id();
    let status = herdr_b.child.wait().unwrap();
    unregister_spawned_herdr_pid(pid);
    assert!(status.success(), "server B should stop cleanly");
    assert!(server_answers(&socket_a), "server A must keep running");

    drop(herdr_b);
    crate::support::unregister_runtime_dir(&runtime_b);
    cleanup_spawned_herdr(herdr_a, base);
}

#[test]
fn server_stop_outside_a_pane_stops_the_server_as_before() {
    let base = unique_test_dir();
    let runtime_dir = base.join("runtime");
    let socket_path = runtime_dir.join("herdr.sock");
    let mut herdr = spawn_herdr(&base.join("config"), &runtime_dir, &socket_path);
    wait_for_socket(&socket_path, Duration::from_secs(5));
    create_root_pane(&socket_path, &base);

    let stopped = run_cli_outside_pane(&socket_path, &["server", "stop"]);
    assert!(
        stopped.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    let pid = herdr.child.process_id();
    let status = herdr.child.wait().unwrap();
    unregister_spawned_herdr_pid(pid);
    assert!(status.success());

    cleanup_spawned_herdr(herdr, base);
}

#[test]
fn session_stop_in_a_pane_refuses_its_own_session_until_forced() {
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let _server = spawn_named_server(&config_home, &runtime_dir, "alpha");
    let socket_path = named_session_socket(&config_home, "alpha");
    wait_for_socket(&socket_path, Duration::from_secs(5));
    let pane_id = create_root_pane(&socket_path, &base);

    let refused = run_herdr_in_pane(
        &socket_path,
        &pane_id,
        &base,
        "session",
        "",
        "session stop alpha",
    );
    assert_eq!(refused.code, 1, "stderr: {}", refused.stderr);
    for expected in [
        socket_path.display().to_string(),
        "from session name alpha".to_string(),
        "--force".to_string(),
    ] {
        assert!(
            refused.stderr.contains(&expected),
            "refusal should mention {expected:?}: {}",
            refused.stderr
        );
    }
    assert!(
        server_answers(&socket_path),
        "session alpha must keep running"
    );

    let (forced, _) =
        herdr_in_pane_command(&base, "session-forced", "", "session stop alpha --force");
    send_to_pane(&socket_path, &pane_id, &forced);
    assert!(
        wait_until(Duration::from_secs(15), Duration::from_millis(25), || {
            !server_answers(&socket_path)
        }),
        "--force should stop session alpha"
    );

    cleanup_test_base(&base);
}
