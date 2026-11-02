//! What the link needs from the daemon: relay credentials, admission, the
//! guest API server, and link status reporting. [`DaemonGuestHost`] provides
//! them from the guest store and API server; tests use fakes.

use std::io;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::Receiver;

/// Relay credentials and the node's Noise static key.
#[derive(Clone)]
pub(crate) struct HostInfo {
    /// b64url of 16 bytes (22 chars); names this host at the relay.
    pub(crate) host_id: String,
    /// Bearer secret for the host socket.
    pub(crate) relay_secret: String,
    /// X25519 static secret the Noise responder proves.
    pub(crate) node_secret: [u8; 32],
    /// Base relay URL, for example `https://guest.herdrup.app`.
    pub(crate) relay_url: String,
}

/// Outcome of checking a guest's message-1 payload.
pub(crate) enum Admission<P> {
    /// Serve the guest as `principal`; `reply` is the message-2 payload.
    Admitted {
        principal: P,
        reply: serde_json::Value,
    },
    /// Refuse with one of the contract error codes (`unknown`, `revoked`, ...).
    Refused(&'static str),
}

/// Link state reported by `guest.list`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkState {
    Off,
    Connecting,
    Up,
    Retrying,
}

impl LinkState {
    /// The `guest.list` spelling.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Connecting => "connecting",
            Self::Up => "up",
            Self::Retrying => "retrying",
        }
    }
}

pub(crate) trait GuestHost: Send + Sync + 'static {
    /// Authenticated guest identity handed from `admit` to `serve`.
    type Principal: Send + 'static;

    /// Relay credentials and node key, created on first use.
    fn host_info(&self) -> io::Result<HostInfo>;

    /// True while at least one active guest or unexpired, unused invite exists.
    fn link_wanted(&self) -> bool;

    /// Decides a guest's admission from its static key and message-1 payload.
    fn admit(&self, device_pub: [u8; 32], hello: &serde_json::Value) -> Admission<Self::Principal>;

    /// Runs one API connection as `principal` and returns when `stream` ends.
    fn serve(&self, principal: Self::Principal, stream: UnixStream);

    fn set_link_status(&self, state: LinkState, last_error: Option<String>);

    /// Fires whenever guests or invites change, which may flip `link_wanted`.
    fn subscribe_changes(&self) -> Receiver<()>;
}

impl From<crate::guest::Admission> for Admission<crate::guest::GuestPrincipal> {
    fn from(admission: crate::guest::Admission) -> Self {
        match admission {
            crate::guest::Admission::Admitted { principal, reply } => {
                Self::Admitted { principal, reply }
            }
            crate::guest::Admission::Refused(code) => Self::Refused(code),
        }
    }
}

/// The daemon's guest store, config and API server.
pub(crate) struct DaemonGuestHost;

impl GuestHost for DaemonGuestHost {
    type Principal = crate::guest::GuestPrincipal;

    fn host_info(&self) -> io::Result<HostInfo> {
        let info = crate::guest::host_info()?;
        Ok(HostInfo {
            host_id: info.host_id,
            relay_secret: info.relay_secret,
            node_secret: info.node_secret,
            relay_url: info.relay_url,
        })
    }

    fn link_wanted(&self) -> bool {
        crate::guest::link_wanted()
    }

    fn admit(&self, device_pub: [u8; 32], hello: &serde_json::Value) -> Admission<Self::Principal> {
        crate::guest::admit(device_pub, hello).into()
    }

    fn serve(&self, principal: Self::Principal, stream: UnixStream) {
        crate::guest::serve(principal, stream);
    }

    fn set_link_status(&self, state: LinkState, last_error: Option<String>) {
        crate::guest::set_link_status(crate::guest::LinkStatus {
            state: state.as_str(),
            last_error,
        });
    }

    fn subscribe_changes(&self) -> Receiver<()> {
        crate::guest::subscribe_changes()
    }
}
