//! Guest activity log: `audit.jsonl` (0600), rotated at 10 MiB to `.1`.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::Mutex;

use crate::api::schema::GuestAuditEntry;

pub(crate) const ROTATE_BYTES: u64 = 10 * 1024 * 1024;
pub(crate) const MAX_READ_LIMIT: usize = 500;
pub(crate) const DEFAULT_READ_LIMIT: usize = 100;

/// Serializes append-and-rotate inside this process.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn append(dir: &Path, entry: &GuestAuditEntry) -> io::Result<()> {
    append_with_limit(dir, entry, ROTATE_BYTES)
}

fn append_with_limit(dir: &Path, entry: &GuestAuditEntry, rotate_bytes: u64) -> io::Result<()> {
    let _guard = WRITE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    super::store::ensure_dir(dir)?;
    let path = dir.join("audit.jsonl");
    if fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= rotate_bytes) {
        fs::rename(&path, dir.join("audit.jsonl.1"))?;
    }
    let mut line = serde_json::to_vec(entry)?;
    line.push(b'\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&line)
}

/// Entries newest first, optionally for one guest and strictly older than
/// `before_ms`. Unparseable lines are skipped.
pub(crate) fn read(
    dir: &Path,
    guest_id: Option<&str>,
    before_ms: Option<u64>,
    limit: usize,
) -> io::Result<Vec<GuestAuditEntry>> {
    let mut entries = Vec::new();
    for name in ["audit.jsonl.1", "audit.jsonl"] {
        let file = match fs::File::open(dir.join(name)) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        for line in io::BufReader::new(file).lines() {
            let Ok(entry) = serde_json::from_str::<GuestAuditEntry>(&line?) else {
                continue;
            };
            if guest_id.is_some_and(|id| id != entry.guest_id)
                || before_ms.is_some_and(|before| entry.ts_ms >= before)
            {
                continue;
            }
            entries.push(entry);
        }
    }
    entries.reverse();
    entries.truncate(limit);
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schema::GuestAuditEvent;
    use crate::guest::store::tests::TempDir;

    fn entry(ts_ms: u64, guest_id: &str) -> GuestAuditEntry {
        GuestAuditEntry {
            ts_ms,
            guest_id: guest_id.into(),
            name: "plotarmordev".into(),
            fingerprint: "SHA256:0000·0000·0000·0000".into(),
            event: GuestAuditEvent::Prompt,
            pane: "term_1".into(),
            method: Some("agent.prompt".into()),
            text: Some("x".repeat(64)),
            file: None,
        }
    }

    #[test]
    fn rotates_at_the_limit_and_reads_newest_first_across_both_files() {
        let dir = TempDir::new("audit");
        for ts in 1..=6 {
            append_with_limit(&dir.0, &entry(ts, if ts % 2 == 0 { "a" } else { "b" }), 400)
                .unwrap();
        }
        assert!(dir.0.join("audit.jsonl.1").exists(), "rotated");
        assert!(fs::metadata(dir.0.join("audit.jsonl")).unwrap().len() < 400 * 2);
        let mode = fs::metadata(dir.0.join("audit.jsonl"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let all = read(&dir.0, None, None, 500).unwrap();
        let stamps: Vec<u64> = all.iter().map(|entry| entry.ts_ms).collect();
        // Only the live file and one rotation are kept.
        assert!(
            stamps.windows(2).all(|pair| pair[0] > pair[1]),
            "{stamps:?}"
        );
        assert_eq!(stamps.first(), Some(&6));
        let only_a = read(&dir.0, Some("a"), Some(6), 1).unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].ts_ms, 4);
    }

    #[test]
    fn entries_of_retired_viewing_kinds_are_left_out() {
        // Logs written before viewing stopped being audited still hold
        // `read`, `resize`, `gram_list` and `gram_read` lines; the owner's log
        // must not show them, and a page of `limit` holds only real events.
        let dir = TempDir::new("audit-retired");
        append_with_limit(&dir.0, &entry(1, "a"), 1 << 20).unwrap();
        let mut lines = String::new();
        for (ts, kind) in [
            (2, "read"),
            (3, "resize"),
            (4, "gram_list"),
            (5, "gram_read"),
        ] {
            let mut value = serde_json::to_value(entry(ts, "a")).unwrap();
            value["event"] = kind.into();
            lines.push_str(&format!("{value}\n"));
        }
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(dir.0.join("audit.jsonl"))
            .unwrap();
        io::Write::write_all(&mut file, lines.as_bytes()).unwrap();
        append_with_limit(&dir.0, &entry(6, "a"), 1 << 20).unwrap();
        let shown: Vec<u64> = read(&dir.0, None, None, 2)
            .unwrap()
            .iter()
            .map(|entry| entry.ts_ms)
            .collect();
        assert_eq!(shown, vec![6, 1]);
    }
}
