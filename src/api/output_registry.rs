//! Process-wide registry of live `pane.stream` output rings, keyed by public
//! pane id.
//!
//! Mirrors `pane_graphics_stream`'s `REGISTERED_STREAMS`: the app loop installs a
//! `Weak` handle when a viewer attaches so the connection thread can reach the
//! shared ring and drain raw bytes without routing every byte back through the
//! single-threaded app. Only the app loop mutates the map (attach/detach are
//! serialized there), while connection threads only look rings up.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::pane::OutputRing;

static REGISTERED_OUTPUT_RINGS: OnceLock<Mutex<HashMap<String, Weak<OutputRing>>>> =
    OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, Weak<OutputRing>>> {
    REGISTERED_OUTPUT_RINGS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Publish (or refresh) the ring for `pane_id`. Idempotent: co-viewers of the
/// same pane share one ring, so re-registering the same ring is a no-op.
pub(crate) fn register(pane_id: &str, ring: &Arc<OutputRing>) {
    let Ok(mut rings) = registry().lock() else {
        return;
    };
    rings.insert(pane_id.to_string(), Arc::downgrade(ring));
}

/// Remove the ring entry for `pane_id`. Called by the app when the last viewer
/// detaches.
pub(crate) fn unregister(pane_id: &str) {
    let Ok(mut rings) = registry().lock() else {
        return;
    };
    rings.remove(pane_id);
}

/// Resolve the live ring for `pane_id`, dropping the entry if it has died.
pub(crate) fn lookup(pane_id: &str) -> Option<Arc<OutputRing>> {
    let Ok(mut rings) = registry().lock() else {
        return None;
    };
    match rings.get(pane_id).and_then(Weak::upgrade) {
        Some(ring) => Some(ring),
        None => {
            rings.remove(pane_id);
            None
        }
    }
}
