//! `server.update_apply` end to end: a real server started from a copy of the
//! test binary (the "installed" herdr), a loopback origin serving a signed
//! manifest whose asset is another copy of the test binary, and the real
//! update guard. Everything lives in a temp dir; nothing touches an installed
//! herdr or its config.
//!
//! Linux only, like the live handoff tests (macOS CI skips those): the guard
//! identifies the serving binary through `/proc/<pid>/exe`.
#![cfg(target_os = "linux")]

pub mod support;

#[path = "../src/update/test_signing.rs"]
mod test_signing;

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use sha2::Digest as _;
use test_signing::TestSigner;

const RELEASE_ROOT: &str = "https://github.com/jerryfane/herdr/releases/download/";
/// Far beyond any real commit time, so the test build is always older.
const NEWER_COMMIT_TIME: i64 = 4_000_000_000;
/// Long enough for a download, the switch and the 180 s observation window.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(300);

type Routes = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// A loopback HTTP origin for `HERDR_UPDATE_TEST_ORIGIN`.
struct Origin {
    port: u16,
    routes: Routes,
}

impl Origin {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let routes: Routes = Arc::default();
        let served = Arc::clone(&routes);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let routes = Arc::clone(&served);
                thread::spawn(move || serve(stream, &routes));
            }
        });
        Self { port, routes }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn publish(&self, path: &str, body: Vec<u8>) {
        self.routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(path.to_string(), body);
    }
}

fn serve(mut stream: std::net::TcpStream, routes: &Routes) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) if header == "\r\n" || header == "\n" => break,
            Ok(_) => {}
        }
    }
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let body = routes
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(path)
        .cloned();
    let _ = match body {
        Some(body) => stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .and_then(|()| stream.write_all(&body)),
        None => stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    };
}

struct SpawnedServer {
    _master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
}

impl Drop for SpawnedServer {
    fn drop(&mut self) {
        let pid = self.child.process_id();
        support::stop_spawned_herdr(&mut *self.child);
        support::unregister_spawned_herdr_pid(pid);
    }
}

/// One test's temp tree: config and runtime dirs, the "installed" binary,
/// the origin and the server running from that binary.
struct Fixture {
    base: PathBuf,
    config_home: PathBuf,
    api_socket: PathBuf,
    install: PathBuf,
    origin: Origin,
    signer: TestSigner,
    server: Option<SpawnedServer>,
}

impl Fixture {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = PathBuf::from(format!("/tmp/hsu-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let config_home = base.join("config");
        let runtime_dir = base.join("runtime");
        fs::create_dir_all(config_home.join("herdr-dev")).unwrap();
        fs::write(
            config_home.join("herdr-dev/config.toml"),
            "onboarding = false\n",
        )
        .unwrap();
        support::register_runtime_dir(&runtime_dir);
        let install = base.join("bin/herdr");
        fs::create_dir_all(install.parent().unwrap()).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_herdr"), &install).unwrap();
        fs::set_permissions(&install, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            api_socket: runtime_dir.join("herdr.sock"),
            base,
            config_home,
            install,
            origin: Origin::start(),
            signer: TestSigner::new(7),
            server: None,
        }
    }

    fn updates(&self) -> PathBuf {
        self.config_home.join("herdr-dev/updates")
    }

    /// Start the server from the installed copy with the debug-only update
    /// overrides: the loopback origin, the test key, and a running commit
    /// that differs from the one the manifest names.
    fn start_server(&mut self, extra_env: &[(&str, &str)]) {
        let runtime_dir = self.base.join("runtime");
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let mut cmd = CommandBuilder::new(&self.install);
        support::isolate_herdr_test_process(&mut cmd);
        cmd.arg("server");
        cmd.env("XDG_CONFIG_HOME", &self.config_home);
        cmd.env("XDG_RUNTIME_DIR", &runtime_dir);
        cmd.env("HERDR_SOCKET_PATH", &self.api_socket);
        cmd.env(
            "HERDR_CLIENT_SOCKET_PATH",
            runtime_dir.join("herdr-client.sock"),
        );
        cmd.env("SHELL", "/bin/sh");
        cmd.env("HERDR_UPDATE_TEST_ORIGIN", self.origin.url());
        cmd.env("HERDR_UPDATE_TEST_PUBLIC_KEY", self.signer.public_key());
        cmd.env("HERDR_UPDATE_TEST_RUNNING_COMMIT", "0000000");
        cmd.env_remove("HERDR_UPDATE_TEST_GUARD_FAULT");
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        let child = pair.slave.spawn_command(cmd).unwrap();
        support::register_spawned_herdr_pid(child.process_id());
        self.server = Some(SpawnedServer {
            _master: pair.master,
            child,
        });
        support::wait_for_socket(&self.api_socket, Duration::from_secs(20));
    }

    fn request(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        try_request(&self.api_socket, method, params)
            .unwrap_or_else(|err| panic!("{method}: {err}"))
    }

    /// Publish a signed manifest for a copy of the test binary and return it.
    /// `protocol` is the one the manifest promises; the handoff checks it.
    fn publish_build(&self, protocol: u64) -> Build {
        let version_line = run_version(&self.install);
        let commit = version_line
            .trim()
            .rsplit_once(" (")
            .and_then(|(_, commit)| commit.strip_suffix(')'))
            .unwrap_or_else(|| panic!("the test binary has no commit: {version_line:?}"))
            .to_string();
        let full_commit = format!("{commit:0<40}");
        let build_id = format!("2099-01-01-{}", &full_commit[..12]);

        // Trailing bytes make the asset's hash differ from the installed
        // binary's while it still runs: the loader ignores them.
        let mut asset = fs::read(env!("CARGO_BIN_EXE_herdr")).unwrap();
        asset.extend_from_slice(b"\0herdr-update-test-asset\0");
        let sha256 = hex(&sha2::Sha256::digest(&asset));
        let key = format!("linux-{}", std::env::consts::ARCH);
        let asset_path = format!("/releases/download/preview-{build_id}/herdr-{key}");
        let mut manifest = serde_json::json!({
            "schema_version": 2,
            "channel": "preview",
            "base_version": env!("CARGO_PKG_VERSION"),
            "build_id": build_id,
            "commit": full_commit,
            "commit_time": NEWER_COMMIT_TIME,
            "built_at": "2099-01-01T00:00:00Z",
            "protocol": protocol,
            "endpoint_generation": support::CURRENT_ENDPOINT_PROTOCOL_GENERATION,
            "notes": "Test build",
            "assets": {}
        });
        manifest["assets"][&key] = serde_json::json!({
            "url": format!("{RELEASE_ROOT}preview-{build_id}/herdr-{key}"),
            "sha256": sha256,
            "size": asset.len()
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let signature = self
            .signer
            .sign(&bytes, &format!("herdr-preview {build_id} {full_commit}"));
        self.origin.publish("/distribution/preview.json", bytes);
        self.origin
            .publish("/distribution/preview.json.minisig", signature.into_bytes());
        self.origin.publish(&asset_path, asset);
        Build { build_id, sha256 }
    }

    /// Poll `server.update_status` until the attempt has an outcome. The
    /// switch drops connections, so failed reads are retried.
    fn wait_for_outcome(&self, attempt_id: &str) -> serde_json::Value {
        let deadline = Instant::now() + ATTEMPT_TIMEOUT;
        let mut last = serde_json::Value::Null;
        while Instant::now() < deadline {
            if let Ok(response) = try_request(
                &self.api_socket,
                "server.update_status",
                serde_json::json!({}),
            ) {
                let attempt = response["result"]["attempt"].clone();
                if attempt["attempt_id"] == attempt_id && attempt.get("outcome").is_some() {
                    return attempt;
                }
                last = response;
            }
            thread::sleep(Duration::from_millis(250));
        }
        let log = fs::read_to_string(self.updates().join("guard.log")).unwrap_or_default();
        panic!("attempt {attempt_id} did not finish; last status {last}; guard log:\n{log}");
    }

    fn guard_log(&self) -> String {
        fs::read_to_string(self.updates().join("guard.log")).unwrap_or_default()
    }

    /// Wait until the lock is gone, so the guard has finished writing.
    fn wait_for_guard_exit(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.updates().join("lock").exists() {
            assert!(Instant::now() < deadline, "the guard kept the update lock");
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn apply(&self, params: serde_json::Value) -> String {
        let applied = self.request("server.update_apply", params);
        assert_eq!(applied["result"]["type"], "update_apply", "{applied}");
        applied["result"]["attempt_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no attempt id: {applied}"))
            .to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Whichever server serves now was started by this test.
        let _ = try_request(&self.api_socket, "server.stop", serde_json::json!({}));
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&self.api_socket).is_ok() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
        }
        self.server.take();
        support::cleanup_test_base(&self.base);
    }
}

struct Build {
    build_id: String,
    sha256: String,
}

fn try_request(
    socket: &Path,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut stream = UnixStream::connect(socket).map_err(|err| err.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|err| err.to_string())?;
    let line = serde_json::json!({"id": "test", "method": method, "params": params});
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|err| err.to_string())?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|err| err.to_string())?;
    serde_json::from_str(&reply).map_err(|err| format!("{err}: {reply:?}"))
}

fn run_version(exe: &Path) -> String {
    let output = std::process::Command::new(exe)
        .arg("--version")
        .output()
        .unwrap();
    String::from_utf8(output.stdout).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn file_sha256(path: &Path) -> String {
    let mut file = fs::File::open(path).unwrap();
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            return hex(&hasher.finalize());
        }
        hasher.update(&buffer[..read]);
    }
}

fn serving_pid(socket: &Path) -> u32 {
    let stream = UnixStream::connect(socket).unwrap();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            std::os::fd::AsRawFd::as_raw_fd(&stream),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "SO_PEERCRED failed");
    cred.pid as u32
}

fn alive(pid: u32) -> bool {
    let state = fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            stat.rfind(')')
                .and_then(|end| stat[end + 2..].chars().next())
        });
    matches!(state, Some(state) if state != 'Z')
}

/// A pane running a shell loop; returns its pane id and the shell's pid.
fn open_pane(fixture: &Fixture) -> (String, u32) {
    let created = fixture.request(
        "workspace.create",
        serde_json::json!({"cwd": "/tmp", "focus": true}),
    );
    let pane_id = created["result"]["root_pane"]["pane_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no pane: {created}"))
        .to_string();
    let marker = fixture.base.join("pane.pid");
    let command = format!(
        "sh -c 'echo READY $$ > {}; while read line; do echo got:$line; done'",
        marker.display()
    );
    let sent = fixture.request(
        "pane.send_input",
        serde_json::json!({"pane_id": pane_id, "text": command, "keys": ["Enter"]}),
    );
    assert!(sent.get("result").is_some(), "{sent}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(pid) = fs::read_to_string(&marker)
            .ok()
            .filter(|text| text.ends_with('\n'))
            .and_then(|text| text.split_whitespace().last()?.parse().ok())
        {
            return (pane_id, pid);
        }
        assert!(Instant::now() < deadline, "the pane's shell never started");
        thread::sleep(Duration::from_millis(50));
    }
}

fn pane_ids(fixture: &Fixture) -> Vec<String> {
    let snapshot = fixture.request("session.snapshot", serde_json::json!({}));
    snapshot["result"]["snapshot"]["panes"]
        .as_array()
        .unwrap_or_else(|| panic!("no snapshot: {snapshot}"))
        .iter()
        .filter_map(|pane| pane["pane_id"].as_str().map(str::to_string))
        .collect()
}

fn protocol(fixture: &Fixture) -> u64 {
    let pong = fixture.request("ping", serde_json::json!({}));
    pong["result"]["protocol"]
        .as_u64()
        .unwrap_or_else(|| panic!("no protocol: {pong}"))
}

struct InstallIdentity {
    inode: u64,
    sha256: String,
}

fn install_identity(path: &Path) -> InstallIdentity {
    InstallIdentity {
        inode: fs::metadata(path).unwrap().ino(),
        sha256: file_sha256(path),
    }
}

#[test]
fn update_apply_switches_live_and_installs_only_after_the_guard_passes() {
    let mut fixture = Fixture::new();
    fixture.start_server(&[]);
    let (pane_id, shell_pid) = open_pane(&fixture);
    let build = fixture.publish_build(protocol(&fixture));
    let old_pid = serving_pid(&fixture.api_socket);
    let before = install_identity(&fixture.install);

    let check = fixture.request("server.update_check", serde_json::json!({}));
    assert_eq!(check["result"]["update_available"], true, "{check}");
    assert_eq!(check["result"]["mode"], "live", "{check}");
    let attempt_id = fixture.apply(serde_json::json!({"build_id": build.build_id}));
    let attempt = fixture.wait_for_outcome(&attempt_id);
    fixture.wait_for_guard_exit();

    assert_eq!(
        attempt["outcome"],
        "updated",
        "{attempt}\n{}",
        fixture.guard_log()
    );
    assert_eq!(attempt["phase"], "installing", "{attempt}");
    assert_eq!(attempt["bytes_done"], attempt["bytes_total"], "{attempt}");
    assert!(attempt["panes"].as_u64().unwrap_or(0) >= 1, "{attempt}");
    let new_pid = serving_pid(&fixture.api_socket);
    assert_ne!(new_pid, old_pid, "the old server still serves");
    assert!(!alive(old_pid), "the old server did not exit");
    assert_eq!(
        file_sha256(Path::new(&format!("/proc/{new_pid}/exe"))),
        build.sha256
    );
    assert!(
        alive(shell_pid),
        "the pane's shell did not survive the switch"
    );
    assert!(
        pane_ids(&fixture).contains(&pane_id),
        "pane {pane_id} is gone"
    );
    let after = install_identity(&fixture.install);
    assert_eq!(
        after.sha256, build.sha256,
        "the installed binary is not the new build"
    );
    assert_ne!(after.inode, before.inode);
    assert!(fixture
        .updates()
        .join(&build.build_id)
        .join("herdr")
        .exists());
    assert!(!fixture
        .updates()
        .join(&build.build_id)
        .join("rollback-started")
        .exists());
}

#[test]
fn update_apply_changes_nothing_when_the_new_build_refuses_the_switch() {
    let mut fixture = Fixture::new();
    fixture.start_server(&[]);
    let (pane_id, shell_pid) = open_pane(&fixture);
    // The new build's handoff import refuses a protocol it does not speak,
    // so it never becomes ready and the old server restores its sockets.
    let build = fixture.publish_build(protocol(&fixture) + 1000);
    let old_pid = serving_pid(&fixture.api_socket);
    let before = install_identity(&fixture.install);

    let attempt_id = fixture.apply(serde_json::json!({"build_id": build.build_id}));
    let attempt = fixture.wait_for_outcome(&attempt_id);
    fixture.wait_for_guard_exit();

    assert_eq!(
        attempt["outcome"],
        "failed_no_change",
        "{attempt}\n{}",
        fixture.guard_log()
    );
    assert_eq!(serving_pid(&fixture.api_socket), old_pid);
    assert!(alive(shell_pid));
    assert!(pane_ids(&fixture).contains(&pane_id));
    let after = install_identity(&fixture.install);
    assert_eq!((after.inode, after.sha256), (before.inode, before.sha256));
    // Not a rollback: the same build may be tried again.
    let check = fixture.request("server.update_check", serde_json::json!({}));
    assert_eq!(check["result"]["update_available"], true, "{check}");
}

#[test]
fn update_guard_hands_back_once_and_leaves_the_install_when_a_check_fails() {
    let mut fixture = Fixture::new();
    fixture.start_server(&[("HERDR_UPDATE_TEST_GUARD_FAULT", "forward_checks")]);
    let (pane_id, shell_pid) = open_pane(&fixture);
    let build = fixture.publish_build(protocol(&fixture));
    let old_pid = serving_pid(&fixture.api_socket);
    let before = install_identity(&fixture.install);

    let attempt_id = fixture.apply(serde_json::json!({"build_id": build.build_id}));
    let attempt = fixture.wait_for_outcome(&attempt_id);
    fixture.wait_for_guard_exit();

    let log = fixture.guard_log();
    assert_eq!(attempt["outcome"], "rolled_back", "{attempt}\n{log}");
    assert_eq!(
        log.matches("live handoff to").count(),
        2,
        "expected the switch and exactly one handoff back:\n{log}"
    );
    let back_pid = serving_pid(&fixture.api_socket);
    assert_ne!(back_pid, old_pid);
    assert_eq!(
        file_sha256(Path::new(&format!("/proc/{back_pid}/exe"))),
        before.sha256,
        "the previous build does not serve"
    );
    assert!(
        alive(shell_pid),
        "the pane's shell did not survive both switches"
    );
    assert!(pane_ids(&fixture).contains(&pane_id));
    let after = install_identity(&fixture.install);
    assert_eq!((after.inode, after.sha256), (before.inode, before.sha256));
    assert!(fixture.updates().join("previous").join("herdr").exists());

    // The build that failed here is neither offered nor applied again.
    let check = fixture.request("server.update_check", serde_json::json!({}));
    assert_eq!(check["result"]["update_available"], false, "{check}");
    let again = fixture.request(
        "server.update_apply",
        serde_json::json!({"build_id": build.build_id}),
    );
    assert_eq!(again["error"]["code"], "update_not_available", "{again}");
}

#[test]
fn update_guard_needs_attention_and_kills_nothing_when_the_handoff_back_fails() {
    let mut fixture = Fixture::new();
    fixture.start_server(&[("HERDR_UPDATE_TEST_GUARD_FAULT", "rollback_handoff")]);
    let (pane_id, shell_pid) = open_pane(&fixture);
    let build = fixture.publish_build(protocol(&fixture));
    let before = install_identity(&fixture.install);

    let attempt_id = fixture.apply(serde_json::json!({"build_id": build.build_id}));
    let attempt = fixture.wait_for_outcome(&attempt_id);
    fixture.wait_for_guard_exit();

    let log = fixture.guard_log();
    assert_eq!(attempt["outcome"], "needs_attention", "{attempt}\n{log}");
    assert_eq!(log.matches("live handoff to").count(), 2, "{log}");
    // The new build keeps serving: nothing was stopped to force a state.
    let pid = serving_pid(&fixture.api_socket);
    assert_eq!(
        file_sha256(Path::new(&format!("/proc/{pid}/exe"))),
        build.sha256
    );
    assert!(alive(shell_pid));
    assert!(pane_ids(&fixture).contains(&pane_id));
    let after = install_identity(&fixture.install);
    assert_eq!((after.inode, after.sha256), (before.inode, before.sha256));
    assert!(fixture
        .updates()
        .join(&build.build_id)
        .join("rollback-started")
        .exists());
}

#[test]
fn update_apply_restart_later_installs_on_disk_without_touching_the_server() {
    let mut fixture = Fixture::new();
    fixture.start_server(&[]);
    let (pane_id, shell_pid) = open_pane(&fixture);
    let build = fixture.publish_build(protocol(&fixture));
    let old_pid = serving_pid(&fixture.api_socket);

    let attempt_id = fixture.apply(serde_json::json!({
        "build_id": build.build_id,
        "restart_later": true
    }));
    let attempt = fixture.wait_for_outcome(&attempt_id);
    fixture.wait_for_guard_exit();

    assert_eq!(
        attempt["outcome"],
        "downloaded_restart_required",
        "{attempt}\n{}",
        fixture.guard_log()
    );
    assert_eq!(attempt["restart_later"], true);
    assert_eq!(serving_pid(&fixture.api_socket), old_pid);
    assert!(alive(shell_pid));
    assert!(pane_ids(&fixture).contains(&pane_id));
    assert_eq!(file_sha256(&fixture.install), build.sha256);
    assert!(!fixture.guard_log().contains("live handoff to"));
}

#[test]
fn update_apply_refuses_a_build_the_owner_did_not_confirm() {
    let mut fixture = Fixture::new();
    fixture.start_server(&[]);
    fixture.publish_build(protocol(&fixture));

    let refused = fixture.request(
        "server.update_apply",
        serde_json::json!({"build_id": "2098-12-31-000000000000"}),
    );

    assert_eq!(
        refused["error"]["code"], "update_build_mismatch",
        "{refused}"
    );
    let status = fixture.request("server.update_status", serde_json::json!({}));
    assert!(status["result"]["attempt"].is_null(), "{status}");
    assert!(!fixture.updates().join("lock").exists());
}
