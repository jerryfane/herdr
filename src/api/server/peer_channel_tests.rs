//! Proxied one-shot requests to an SSH-bridged peer over its persistent
//! `api-bridge --multi` channel, against a fake `ssh` on `PATH` that serves
//! both the per-connection `remote-api-bridge` and `api-bridge --multi`, and
//! a live-updated peer whose channel runs the real bridge (#463).

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Condvar;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::api::client::ConnectionTarget;
use crate::api::peer_channel::PeerChannel;
use crate::api::schema::AgentTarget;

struct PathRestore(Option<std::ffi::OsString>);

impl Drop for PathRestore {
    fn drop(&mut self) {
        match self.0.take() {
            Some(path) => std::env::set_var("PATH", path),
            None => std::env::remove_var("PATH"),
        }
    }
}

/// A fake peer reached through a fake `ssh`. Every `ssh` start appends its
/// mode (`multi` or `single`) to `opens`, sleeps `open_delay`, then answers
/// each request line: `ping` with a pong advertising `api_bridge_multi` as
/// configured, `target":"slow:<secs>"` after that delay, `target":"drop"` by
/// exiting without a response, anything else at once. Responses echo the
/// request's id and target. `--multi` answers concurrently.
struct FakePeer {
    base: PathBuf,
    route: PeerRoute,
    channel: Arc<PeerChannel>,
    _bridge: crate::remote::SavedSshBridge,
    _path: PathRestore,
    _env: std::sync::MutexGuard<'static, ()>,
}

impl FakePeer {
    fn start(open_delay: &str, multi: bool) -> Self {
        let env = crate::config::test_config_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("herdr-peer-chan-{}-{nonce}", std::process::id()));
        let bin = base.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let ssh = bin.join("ssh");
        std::fs::write(&ssh, fake_ssh_script(&base, open_delay, multi)).unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = PathRestore(std::env::var_os("PATH"));
        let system_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{system_path}", bin.display()));

        let socket = crate::platform::remote_bridge_endpoint_path(
            &format!("herdr-peer-chan-{}-{nonce}.sock", std::process::id()),
            &format!("hpc-{}-{nonce}.sock", std::process::id()),
        );
        let bridge = crate::remote::start_test_ssh_bridge(
            "example",
            "herdr --session fleet remote-api-bridge",
            socket.clone(),
        )
        .unwrap();
        let channel = PeerChannel::new(Arc::new(|| {
            let mut command = Command::new("ssh");
            command
                .arg("-T")
                .arg("example")
                .arg("herdr --session fleet api-bridge --multi");
            Ok(command)
        }));
        let route = PeerRoute::for_test(ConnectionTarget::SocketPath(socket))
            .with_peer_channel(Arc::clone(&channel));
        Self {
            base,
            route,
            channel,
            _bridge: bridge,
            _path: path,
            _env: env,
        }
    }

    /// `(multi, single)` ssh starts so far.
    fn opens(&self) -> (usize, usize) {
        let log = std::fs::read_to_string(self.base.join("opens")).unwrap_or_default();
        let multi = log.lines().filter(|line| *line == "multi").count();
        let single = log.lines().filter(|line| *line == "single").count();
        (multi, single)
    }

    fn proxy(&self, id: &str, target: &str, running: &Arc<AtomicBool>) -> String {
        proxy(&self.route, id, target, running)
    }
}

fn proxy(route: &PeerRoute, id: &str, target: &str, running: &Arc<AtomicBool>) -> String {
    let request = Request {
        id: id.to_owned(),
        method: Method::AgentGet(AgentTarget {
            target: target.to_owned(),
        }),
    };
    let stamp = route.stamp();
    proxy_federated_response(route, &stamp, &request, running)
}

impl Drop for FakePeer {
    fn drop(&mut self) {
        self.route.retire();
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn fake_ssh_script(base: &std::path::Path, open_delay: &str, multi: bool) -> String {
    format!(
        r#"#!/bin/sh
for arg; do last=$arg; done
case "$last" in
*--multi*) mode=multi ;;
*) mode=single ;;
esac
echo "$mode" >> '{base}/opens'
sleep {open_delay}
printf '\nherdr-remote-output-ready:1\n'
reply() {{
    id=$(printf '%s\n' "$1" | sed -n 's/^{{"id":"\([^"]*\)".*/\1/p')
    case "$1" in
    *'"method":"ping"'*)
        printf '{{"id":"%s","result":{{"type":"pong","version":"test","protocol":1,"capabilities":{{"api_bridge_multi":{multi}}}}}}}\n' "$id"
        return ;;
    esac
    target=$(printf '%s\n' "$1" | sed -n 's/.*"target":"\([^"]*\)".*/\1/p')
    case "$target" in
    slow:*) sleep "${{target#slow:}}" ;;
    esac
    printf '{{"id":"%s","result":{{"type":"echo","target":"%s"}}}}\n' "$id" "$target"
}}
while IFS= read -r line; do
    case "$line" in
    *'"target":"drop"'*) exit 1 ;;
    esac
    if [ "$mode" = multi ]; then reply "$line" & else reply "$line"; fi
done
wait
"#,
        base = base.display(),
    )
}

fn echo(id: &str, target: &str) -> String {
    format!(r#"{{"id":"{id}","result":{{"type":"echo","target":"{target}"}}}}"#)
}

#[test]
fn sequential_proxied_requests_reuse_one_peer_channel() {
    let peer = FakePeer::start("0", true);
    peer.route.observe_api_bridge_multi(true);
    let running = Arc::new(AtomicBool::new(true));
    for index in 0..10 {
        let id = format!("app:req/{index}");
        let target = format!("w1:p{index}");
        assert_eq!(peer.proxy(&id, &target, &running), echo(&id, &target));
    }
    assert_eq!(
        peer.opens(),
        (1, 0),
        "ten requests must share one channel and start no per-request bridge"
    );
}

#[test]
fn concurrent_proxied_requests_are_demultiplexed_by_id() {
    let peer = FakePeer::start("0", true);
    peer.route.observe_api_bridge_multi(true);
    let running = Arc::new(AtomicBool::new(true));
    // Open the channel first so every request below shares it.
    assert_eq!(peer.proxy("warm", "warm", &running), echo("warm", "warm"));
    let started = Instant::now();
    // Later requests answer first: the peer replies out of order.
    let workers: Vec<_> = (0..8)
        .map(|index| {
            let route = peer.route.clone();
            let running = Arc::clone(&running);
            std::thread::spawn(move || {
                let id = format!("app:concurrent/{index}");
                let target = format!("slow:0.{}", 8 - index);
                (proxy(&route, &id, &target, &running), echo(&id, &target))
            })
        })
        .collect();
    for worker in workers {
        let (actual, expected) = worker.join().unwrap();
        assert_eq!(actual, expected);
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "requests must be in flight together on the channel, took {:?}",
        started.elapsed()
    );
    assert_eq!(peer.opens(), (1, 0));
}

#[test]
fn missing_response_is_delivery_unknown_and_next_request_reopens_channel() {
    let peer = FakePeer::start("0", true);
    peer.route.observe_api_bridge_multi(true);
    let running = Arc::new(AtomicBool::new(true));
    assert_eq!(
        peer.proxy("first", "w1:p1", &running),
        echo("first", "w1:p1")
    );

    let lost = peer.proxy("lost", "drop", &running);
    let lost: serde_json::Value = serde_json::from_str(&lost).unwrap();
    assert_eq!(lost["id"], "lost");
    assert_eq!(lost["error"]["code"], "delivery_unknown", "{lost}");
    assert_eq!(peer.opens(), (1, 0), "a written request is never retried");

    assert_eq!(peer.proxy("next", "w1:p2", &running), echo("next", "w1:p2"));
    assert_eq!(peer.opens(), (2, 0), "the next request opens a new channel");
}

#[test]
fn peer_without_api_bridge_multi_keeps_the_per_request_bridge() {
    let running = Arc::new(AtomicBool::new(true));

    // The poll has not seen `api_bridge_multi`: no channel is opened.
    let peer = FakePeer::start("0", true);
    for index in 0..3 {
        let id = format!("unadvertised/{index}");
        assert_eq!(peer.proxy(&id, "w1:p1", &running), echo(&id, "w1:p1"));
    }
    assert_eq!(peer.opens(), (0, 3));
    drop(peer);

    // The poll advertised it, but the channel's own ping does not: one open
    // attempt, then the per-request bridge (backing off before another).
    let peer = FakePeer::start("0", false);
    peer.route.observe_api_bridge_multi(true);
    for index in 0..3 {
        let id = format!("unverified/{index}");
        assert_eq!(peer.proxy(&id, "w1:p1", &running), echo(&id, "w1:p1"));
    }
    assert_eq!(peer.opens(), (1, 3));
}

#[test]
fn streaming_requests_keep_the_per_connection_bridge() {
    let peer = FakePeer::start("0", true);
    peer.route.observe_api_bridge_multi(true);
    let pane_stream: Method = serde_json::from_value(serde_json::json!({
        "method": "pane.stream",
        "params": { "pane_id": "w1:p1" },
    }))
    .unwrap();
    let subscribe = Method::EventsSubscribe(crate::api::schema::EventsSubscribeParams {
        subscriptions: Vec::new(),
        events_v2: true,
        local_only: true,
    });
    for method in [&pane_stream, &subscribe] {
        assert!(peer.channel.lease(method, None).is_none(), "{method:?}");
    }
    // The federation event relay's subscription goes per-connection.
    let request = Request {
        id: "federation:events.subscribe:1".into(),
        method: subscribe,
    };
    let mut lines = peer.route.client().request_stream(&request).unwrap();
    let first = lines.next().unwrap().unwrap();
    assert_eq!(first["id"], "federation:events.subscribe:1", "{first}");
    assert_eq!(peer.opens(), (0, 1));
}

/// N requests to a peer whose SSH start takes 300 ms: the per-request bridge
/// pays N starts, the channel one. Besides the starts, the per-request bridge
/// does at least the channel's work for each request, so the channel saves
/// the N - 1 starts it skips however slow the runner is. The bound asks for
/// half of them, leaving the rest to scheduling noise between the phases; a
/// channel paying a start per request saves none.
#[test]
fn peer_channel_pays_one_channel_open_for_many_requests() {
    const REQUESTS: usize = 6;
    const OPEN: Duration = Duration::from_millis(300);
    let running = Arc::new(AtomicBool::new(true));

    let peer = FakePeer::start("0.3", true);
    let started = Instant::now();
    for index in 0..REQUESTS {
        let id = format!("per-request/{index}");
        assert_eq!(peer.proxy(&id, "w1:p1", &running), echo(&id, "w1:p1"));
    }
    let per_request = started.elapsed();
    assert_eq!(peer.opens(), (0, REQUESTS));
    drop(peer);

    let peer = FakePeer::start("0.3", true);
    peer.route.observe_api_bridge_multi(true);
    let started = Instant::now();
    for index in 0..REQUESTS {
        let id = format!("channel/{index}");
        assert_eq!(peer.proxy(&id, "w1:p1", &running), echo(&id, "w1:p1"));
    }
    let channel = started.elapsed();
    assert_eq!(peer.opens(), (1, 0));
    eprintln!(
        "{REQUESTS} requests with a 300 ms channel open: per-request bridge {per_request:?}, peer channel {channel:?}"
    );
    assert!(per_request >= OPEN * REQUESTS as u32);
    assert!(
        channel >= OPEN
            && per_request.saturating_sub(channel) >= OPEN * (REQUESTS as u32 - 1) / 2,
        "the channel must pay one open, not one per request: per-request bridge {per_request:?}, peer channel {channel:?}"
    );
}

/// The decision behind #463: a new `origin_boot_id` is a restarted peer
/// server, whose bridge must be replaced; the first boot seen, the same boot
/// again and an answer without a boot keep the open bridge.
#[test]
fn peer_restart_recycles_the_peer_channel() {
    let peer = FakePeer::start("0", true);
    peer.route.observe_api_bridge_multi(true);
    let running = Arc::new(AtomicBool::new(true));
    let request = |id: &str| assert_eq!(peer.proxy(id, "w1:p1", &running), echo(id, "w1:p1"));

    request("open");
    peer.route.observe_remote_boot(Some("boot-a"));
    request("first-boot");
    peer.route.observe_remote_boot(Some("boot-a"));
    peer.route.observe_remote_boot(None);
    request("same-boot");
    assert_eq!(
        peer.opens(),
        (1, 0),
        "a boot the route already knows keeps the bridge"
    );

    peer.route.observe_remote_boot(Some("boot-b"));
    request("restarted");
    assert_eq!(
        peer.opens(),
        (2, 0),
        "a restarted peer must get a bridge started after its restart"
    );
    request("settled");
    assert_eq!(peer.opens(), (2, 0));
}

/// Environment of a [`bridge_child`] run: the API socket it forwards to and
/// the log it appends its exit to.
const BRIDGE_CHILD_SOCKET: &str = "HERDR_PEER_CHANNEL_TEST_SOCKET";
const BRIDGE_CHILD_LOG: &str = "HERDR_PEER_CHANNEL_TEST_LOG";

/// The real `api-bridge --multi` as a peer runs it: this test binary, started
/// by a [`LivePeer`]'s `herdr` with [`BRIDGE_CHILD_SOCKET`] set. Does nothing
/// in a normal test run.
#[test]
fn bridge_child() {
    let Some(socket) = std::env::var_os(BRIDGE_CHILD_SOCKET) else {
        return;
    };
    let log = std::env::var_os(BRIDGE_CHILD_LOG).expect("bridge child log");
    // libtest has already written its own lines to stdout; the channel skips
    // everything before this marker, as it skips a login shell's banner.
    let mut stdout = io::stdout();
    write!(stdout, "\n{}\n", crate::remote::REMOTE_OUTPUT_READY_MARKER).unwrap();
    stdout.flush().unwrap();
    let outcome = match crate::remote::run_multi_bridge(Path::new(&socket)) {
        Ok(()) => "ok".to_owned(),
        Err(error) => format!("error: {error}"),
    };
    // One write, so a reader never sees half a line.
    std::fs::OpenOptions::new()
        .append(true)
        .open(log)
        .unwrap()
        .write_all(format!("exit {} {outcome}\n", std::process::id()).as_bytes())
        .unwrap();
}

/// A peer's API server on a Unix socket, standing in for `herdr server`:
/// `ping` and `agent.list` answer as a server does, with this server's boot as
/// `origin_boot_id`, and `agent.get` echoes its target, holding `hold` until
/// [`Self::release`].
struct ScratchServer {
    path: PathBuf,
    state: Arc<ScratchState>,
}

struct ScratchState {
    boot: Mutex<String>,
    /// `(request id, target)` of every `agent.get`, in arrival order.
    seen: Mutex<Vec<(String, String)>>,
    held: Mutex<bool>,
    released: Condvar,
    stopped: AtomicBool,
}

impl ScratchServer {
    fn start(path: PathBuf, boot: &str) -> Self {
        let listener = UnixListener::bind(&path).unwrap();
        let state = Arc::new(ScratchState {
            boot: Mutex::new(boot.to_owned()),
            seen: Mutex::default(),
            held: Mutex::new(true),
            released: Condvar::new(),
            stopped: AtomicBool::new(false),
        });
        let accept_state = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if accept_state.stopped.load(Ordering::Acquire) {
                    return;
                }
                let Ok(stream) = stream else { continue };
                let state = Arc::clone(&accept_state);
                std::thread::spawn(move || state.serve(&stream));
            }
        });
        Self { path, state }
    }

    /// A live handoff as the peer's clients see it: the same API socket, now
    /// answered by a new server process.
    fn hand_off_to(&self, boot: &str) {
        *self.state.boot.lock().unwrap() = boot.to_owned();
    }

    /// Whether an `agent.get` for `target` arrived over a peer channel (with a
    /// channel id) rather than on its own connection.
    fn saw_on_channel(&self, target: &str) -> bool {
        self.state
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|(id, seen)| seen == target && id.starts_with("herdr-peer-channel:"))
    }

    fn release(&self) {
        *self.state.held.lock().unwrap() = false;
        self.state.released.notify_all();
    }

    fn stop(&self) {
        self.release();
        self.state.stopped.store(true, Ordering::Release);
        // Wake the accept loop so it sees the stop.
        let _ = UnixStream::connect(&self.path);
    }
}

impl ScratchState {
    fn serve(&self, stream: &UnixStream) {
        let mut line = String::new();
        if io::BufRead::read_line(&mut io::BufReader::new(stream), &mut line).is_err() {
            return;
        }
        let Ok(request) = serde_json::from_str::<Request>(&line) else {
            return;
        };
        let success = |result| {
            serde_json::to_string(&SuccessResponse {
                id: request.id.clone(),
                result,
            })
            .unwrap()
        };
        let reply = match &request.method {
            Method::Ping(_) => success(ResponseResult::Pong {
                version: "scratch".into(),
                protocol: crate::protocol::PROTOCOL_VERSION,
                capabilities: default_capabilities(),
            }),
            Method::AgentList(_) => success(ResponseResult::AgentList {
                agents: Vec::new(),
                origin_machine_id: None,
                origin_boot_id: Some(self.boot.lock().unwrap().clone()),
                origin_version: None,
                origin_protocol: None,
                origin_capabilities: default_capabilities(),
            }),
            Method::AgentGet(AgentTarget { target }) => {
                self.seen
                    .lock()
                    .unwrap()
                    .push((request.id.clone(), target.clone()));
                if target == "hold" {
                    let mut held = self.held.lock().unwrap();
                    while *held {
                        held = self.released.wait(held).unwrap();
                    }
                }
                echo(&request.id, target)
            }
            _ => return,
        };
        let _ = (&*stream).write_all(format!("{reply}\n").as_bytes());
    }
}

/// A peer that can be live-updated, polled and proxied to the way a
/// coordinator does it. Its server is a [`ScratchServer`]; its `bin/herdr` is
/// a build-labelled script that logs `start <pid> <build>` to `bridges` and
/// becomes the real `api-bridge --multi` ([`bridge_child`]), which logs
/// `exit <pid> <outcome>` when it returns. Like `sshd`, the channel's fake
/// `ssh` runs that `herdr` as its child, so stopping the `ssh` closes the
/// bridge's stdin and stdout but does not kill it.
struct LivePeer {
    base: PathBuf,
    server: ScratchServer,
    route: PeerRoute,
    client: ApiClient,
    presentation: Arc<RwLock<PeerPresentation>>,
    cache: Mutex<FederationStore>,
    tracker: ReachabilityTracker,
}

fn sh_quote(path: &Path) -> String {
    let path = path.to_str().unwrap();
    assert!(!path.contains('\''), "{path}");
    format!("'{path}'")
}

impl LivePeer {
    fn start() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        // Short: the API socket lives in it.
        let base = std::env::temp_dir().join(format!("hlp-{}-{nonce}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("bin")).unwrap();
        let server = ScratchServer::start(base.join("api.sock"), "boot-a");
        let ssh = base.join("ssh");
        // Not `exec`, and not the script's last command, so the shell stays
        // the bridge's parent.
        std::fs::write(
            &ssh,
            format!(
                "#!/bin/sh\n/bin/sh {} --session fleet api-bridge --multi\nexit $?\n",
                sh_quote(&base.join("bin/herdr"))
            ),
        )
        .unwrap();
        let channel = PeerChannel::new(Arc::new(move || {
            let mut command = Command::new("/bin/sh");
            command.arg(&ssh);
            Ok(command)
        }));
        // One-shot requests the channel does not carry go straight to the
        // server.
        let route = PeerRoute::for_test(ConnectionTarget::SocketPath(server.path.clone()))
            .with_peer_channel(channel);
        let peer = Self {
            client: route.client(),
            base,
            server,
            route,
            presentation: Arc::new(RwLock::new(PeerPresentation {
                profile_id: None,
                label: "peer".into(),
            })),
            cache: Mutex::default(),
            tracker: ReachabilityTracker::default(),
        };
        peer.install("a");
        peer
    }

    /// Install `build` as the peer's `herdr` the way an update replaces a
    /// binary: written beside the old one and renamed over it.
    fn install(&self, build: &str) {
        let log = sh_quote(&self.base.join("bridges"));
        let staged = self.base.join("bin/herdr.new");
        std::fs::write(
            &staged,
            format!(
                "#!/bin/sh\n\
                 echo \"start $$ {build}\" >> {log}\n\
                 export {BRIDGE_CHILD_SOCKET}={socket} {BRIDGE_CHILD_LOG}={log}\n\
                 exec {exe} --exact api::server::peer_channel_tests::bridge_child --nocapture\n",
                socket = sh_quote(&self.server.path),
                exe = sh_quote(&std::env::current_exe().unwrap()),
            ),
        )
        .unwrap();
        std::fs::rename(&staged, self.base.join("bin/herdr")).unwrap();
    }

    /// One poll of the peer, as the coordinator's poll thread runs it.
    fn poll(&mut self, running: &Arc<AtomicBool>) {
        let reachability = poll_once_into_cache(
            &self.client,
            "peer",
            None,
            Some(&self.route),
            &self.presentation,
            &self.cache,
            &mut self.tracker,
            running,
            &Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(reachability, Reachability::Reachable);
    }

    /// `(pid, build)` of every bridge started so far, and how each one that
    /// exited ended, by pid.
    fn bridges(&self) -> (Vec<(String, String)>, HashMap<String, String>) {
        let log = std::fs::read_to_string(self.base.join("bridges")).unwrap_or_default();
        let mut starts = Vec::new();
        let mut exits = HashMap::new();
        for line in log
            .split_inclusive('\n')
            .filter(|line| line.ends_with('\n'))
        {
            let mut fields = line.trim_end().splitn(3, ' ');
            match (fields.next(), fields.next(), fields.next()) {
                (Some("start"), Some(pid), Some(build)) => {
                    starts.push((pid.to_owned(), build.to_owned()));
                }
                (Some("exit"), Some(pid), Some(outcome)) => {
                    exits.insert(pid.to_owned(), outcome.to_owned());
                }
                _ => panic!("unexpected bridge log line {line:?}"),
            }
        }
        (starts, exits)
    }

    fn builds(&self) -> Vec<String> {
        self.bridges()
            .0
            .into_iter()
            .map(|(_, build)| build)
            .collect()
    }
}

impl Drop for LivePeer {
    fn drop(&mut self) {
        // Answer held requests first: a bridge whose stdin closes still
        // waits for its requests before it exits.
        self.server.release();
        self.route.retire();
        self.server.stop();
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// #463: a live update replaces the peer's server and its `herdr` binary but
/// not the `api-bridge --multi` the coordinator keeps open there. Once a poll
/// sees the new server boot, the next request starts a bridge from the new
/// build, a request still running on the old bridge is answered there, and
/// the old bridge then exits by itself.
#[test]
fn live_updated_peer_gets_a_bridge_on_its_new_build() {
    let mut peer = LivePeer::start();
    let running = Arc::new(AtomicBool::new(true));

    // The first poll learns the boot and `api_bridge_multi` on its own
    // connection; the second opens the channel, on build a.
    peer.poll(&running);
    peer.poll(&running);
    assert_eq!(
        proxy(&peer.route, "before", "w1:p1", &running),
        echo("before", "w1:p1")
    );
    assert!(peer.server.saw_on_channel("w1:p1"));
    assert_eq!(peer.builds(), ["a"]);
    let old = peer.bridges().0[0].0.clone();

    // A request the old bridge is still running when the update lands.
    let in_flight = {
        let route = peer.route.clone();
        let running = Arc::clone(&running);
        std::thread::spawn(move || {
            let request = Request {
                id: "in-flight".into(),
                method: Method::AgentGet(AgentTarget {
                    target: "hold".into(),
                }),
            };
            route
                .client()
                .request_value_bounded(&request, 64 * 1024, Duration::from_secs(60), Some(&running))
                .map_err(|error| error.to_string())
        })
    };
    wait_until(
        "the held request reaches the server over the channel",
        || peer.server.saw_on_channel("hold"),
    );

    // The live update: a new build replaces the binary and a new server
    // process takes over the API socket. The next poll still travels through
    // the old bridge and sees the new boot.
    peer.install("b");
    peer.server.hand_off_to("boot-b");
    peer.poll(&running);

    assert_eq!(
        proxy(&peer.route, "after", "w1:p2", &running),
        echo("after", "w1:p2")
    );
    assert_eq!(
        peer.builds(),
        ["a", "b"],
        "after the peer's live update the next request must start a bridge on the new build"
    );
    assert!(
        peer.server.saw_on_channel("w1:p2"),
        "the request after the update must ride the new bridge"
    );
    let (_, exits) = peer.bridges();
    assert!(
        !exits.contains_key(&old),
        "the old bridge must keep running while a request is in flight on it: {exits:?}"
    );

    // The held request is answered on the old bridge, which then exits on
    // its own.
    peer.server.release();
    let reply = in_flight.join().unwrap();
    assert_eq!(
        reply.expect("the in-flight request must be answered"),
        serde_json::from_str::<serde_json::Value>(&echo("in-flight", "hold")).unwrap()
    );
    wait_until("the old bridge exits", || {
        peer.bridges().1.contains_key(&old)
    });
    let (starts, exits) = peer.bridges();
    assert_eq!(exits[&old], "ok", "the old bridge must exit cleanly");
    assert!(!exits.contains_key(&starts[1].0), "{exits:?}");

    assert_eq!(
        proxy(&peer.route, "later", "w1:p3", &running),
        echo("later", "w1:p3")
    );
    assert_eq!(peer.builds(), ["a", "b"]);
}
