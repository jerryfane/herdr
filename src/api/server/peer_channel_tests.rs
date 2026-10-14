//! Proxied one-shot requests to an SSH-bridged peer over its persistent
//! `api-bridge --multi` channel, against a fake `ssh` on `PATH` that serves
//! both the per-connection `remote-api-bridge` and `api-bridge --multi`.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;
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

/// Per-request overhead with a 300 ms SSH channel open: N requests cost about
/// N opens on the per-request bridge, one open on the channel.
#[test]
fn peer_channel_pays_one_channel_open_for_many_requests() {
    const REQUESTS: usize = 6;
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
    assert!(per_request >= Duration::from_millis(300) * REQUESTS as u32);
    assert!(
        channel < Duration::from_millis(300) * 2,
        "the channel must pay one open, took {channel:?}"
    );
}
