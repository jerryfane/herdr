use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Opaque identity for a server-owned terminal.
///
/// During the pane-backed transition this is stored one-to-one beside panes,
/// but callers must not derive it from a pane id or layout position.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TerminalId(String);

static NEXT_TERMINAL_ID: AtomicU64 = AtomicU64::new(1);

impl TerminalId {
    pub fn alloc() -> Self {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_micros())
            .unwrap_or(0);
        let counter = NEXT_TERMINAL_ID.fetch_add(1, Ordering::Relaxed);
        // The `.` delimiter between the micros seed and the counter is
        // load-bearing — see `from_persisted`. Never remove it or use `/` (which
        // the federation `<alias>/<terminal_id>` split would consume).
        Self(format!("term_{micros:x}.{counter:x}"))
    }

    /// Rehydrate a terminal id persisted by an earlier boot, verbatim, so a
    /// terminal keeps a stable identity across a daemon restart.
    ///
    /// Collision safety: [`alloc`] mints `term_<micros>.<counter>` — the
    /// wall-clock micros-since-epoch, a delimiter, then a per-boot counter.
    /// The **delimiter is the structural invariant**: it makes the encoding
    /// unambiguous so no two distinct `(micros, counter)` pairs can alias to the
    /// same string (bare `term_<micros><counter>` concatenation could). A
    /// persisted id from an earlier boot normally carries a different, earlier
    /// micros than any id minted in the current session, so restore-reuse does
    /// not collide with a fresh alloc. That last part is *practical* uniqueness
    /// from the micros seed, NOT a hard guarantee — a backwards wall-clock step
    /// (NTP/manual) could re-mint an earlier micros, so "strictly increasing
    /// prefix" is NOT an invariant to rely on. A real collision would then also
    /// require the boot counter to re-reach the persisted value at that same
    /// microsecond, which is vanishingly unlikely; if it ever needed to be
    /// clock-independent, a reservation guard over the restored ids (mirroring
    /// `reserve_workspace_ids`) would do it.
    pub fn from_persisted(id: String) -> Self {
        Self(id)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TerminalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn from_persisted_is_reused_verbatim_and_stays_distinct_from_fresh_allocs() {
        // A persisted id from an earlier boot is reused as-is; fresh allocs in this
        // session are mutually distinct by their per-boot counter and do not alias
        // it (the `.` delimiter keeps the micros/counter split unambiguous).
        let persisted = "term_1abcdef42".to_string();
        let restored = TerminalId::from_persisted(persisted.clone());
        assert_eq!(
            restored.as_str(),
            persisted,
            "persisted id must be reused verbatim"
        );

        // Allocate many fresh ids in the same session; none may collide with the
        // restored id or with each other.
        let mut ids = HashSet::new();
        assert!(ids.insert(restored.as_str().to_string()));
        for _ in 0..1000 {
            let fresh = TerminalId::alloc();
            assert!(
                fresh.as_str().contains('.'),
                "alloc must keep the micros/counter delimiter: {fresh}"
            );
            assert!(
                ids.insert(fresh.as_str().to_string()),
                "alloc produced a duplicate id: {fresh}"
            );
        }
        assert!(
            ids.contains(&persisted),
            "restored id should still be present and never re-minted by alloc"
        );
    }

    #[test]
    fn terminal_id_has_no_slash_so_the_federation_split_is_unaffected() {
        // Federation addresses split `<alias>/<terminal_id>` on the FIRST '/'. A
        // `term_` id never contains '/', so a persisted id round-trips through
        // that split unchanged.
        assert!(!TerminalId::alloc().as_str().contains('/'));
        assert!(!TerminalId::from_persisted("term_abc123".into())
            .as_str()
            .contains('/'));
    }
}
