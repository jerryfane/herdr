//! The owner's agent folders and stars (`agent.groups.*`), keyed by agent
//! name.
//!
//! One document lives at `config_dir()/agent-groups/index.json`. Clients
//! replace it whole and pass the revision they last read; a mismatch is a
//! conflict, so two devices never silently overwrite each other. Every write is
//! a read-modify-write under `.index.lock`, so a live-handoff daemon sharing
//! the directory sees the other's change, and lands through an owner-only temp
//! file and a rename. A missing, corrupt or unreadable index reads as the empty
//! document at revision 0, and the next write replaces it: a damaged file costs
//! the folders, never the daemon or later writes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::api::schema::{AgentGroupFolder, AgentGroups};

/// Most folders a document may hold.
pub const MAX_FOLDERS: usize = 64;
/// Most folder members, summed over every folder.
pub const MAX_MEMBERS: usize = 256;
/// Most starred agents.
pub const MAX_STARS: usize = 256;
/// Longest folder id, folder name or agent name, in characters.
pub const MAX_NAME_CHARS: usize = 64;

const INDEX_FILE: &str = "index.json";
const LOCK_FILE: &str = ".index.lock";

#[derive(Debug, Default, Serialize, Deserialize)]
struct IndexFile {
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    folders: Vec<AgentGroupFolder>,
    #[serde(default)]
    stars: Vec<String>,
    /// The name each terminal's agent had when the owner cleared it, kept
    /// while that name is in a folder or starred and no other agent has taken
    /// it since, so naming the agent again moves its folder and star to the
    /// new name. Entries for terminals that no longer exist are dropped on the
    /// next write. Never sent to clients.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    cleared_names: BTreeMap<String, String>,
}

impl IndexFile {
    fn document(&self) -> AgentGroups {
        AgentGroups {
            revision: self.revision,
            folders: self.folders.clone(),
            stars: self.stars.clone(),
        }
    }

    /// Whether a folder or a star holds `name`.
    fn holds(&self, name: &str) -> bool {
        self.stars.iter().any(|star| star == name)
            || self
                .folders
                .iter()
                .any(|folder| folder.members.iter().any(|member| member == name))
    }

    /// Give `old`'s folder and star to `new`. Whatever `new` held before
    /// belonged to an agent that no longer has the name, so it goes.
    fn rename(&mut self, old: &str, new: &str) {
        for folder in &mut self.folders {
            folder.members.retain(|member| member != new);
            for member in &mut folder.members {
                if *member == old {
                    *member = new.to_string();
                }
            }
        }
        self.stars.retain(|star| star != new);
        for star in &mut self.stars {
            if *star == old {
                *star = new.to_string();
            }
        }
    }

    /// The agent in `terminal_id` now goes by `name`. A name another
    /// terminal remembered from a clear now means this agent, so that
    /// terminal's claim on it ends; this terminal's own remembered name is
    /// spent. Returns whether anything was forgotten.
    fn name_taken(&mut self, terminal_id: &str, name: &str) -> bool {
        let before = self.cleared_names.len();
        self.cleared_names
            .retain(|id, remembered| id != terminal_id && remembered != name);
        self.cleared_names.len() != before
    }

    /// Apply an owner rename of the agent in `terminal_id` from `previous` to
    /// `new` (`None` = no name). Returns whether the file changed.
    fn follow_rename(
        &mut self,
        terminal_id: &str,
        previous: Option<&str>,
        new: Option<&str>,
    ) -> bool {
        match (previous, new) {
            // A clear keeps the folder and star under the old name and
            // remembers it for the next name.
            (Some(old), None) => {
                let mut changed = self.name_taken(terminal_id, old);
                if self.holds(old) {
                    self.cleared_names
                        .insert(terminal_id.to_string(), old.to_string());
                    changed = true;
                }
                changed
            }
            (previous, Some(new)) => {
                let remembered = self.cleared_names.get(terminal_id).cloned();
                let mut changed = self.name_taken(terminal_id, new);
                let old = previous
                    .map(str::to_string)
                    .or(remembered)
                    .filter(|old| old != new && self.holds(old));
                if let Some(old) = old {
                    self.rename(&old, new);
                    self.revision += 1;
                    changed = true;
                }
                changed
            }
            (None, None) => false,
        }
    }
}

/// Why `agent.groups.set` refused a document.
#[derive(Debug)]
pub enum GroupsError {
    /// The document breaks a limit or rule; the message says which.
    Invalid(String),
    /// The caller's revision is not the stored one; here is the stored
    /// document.
    Conflict(AgentGroups),
    Io(io::Error),
}

pub struct AgentGroupsStore {
    root: PathBuf,
}

impl AgentGroupsStore {
    /// The production location, `config_dir()/agent-groups`.
    pub fn default_root() -> PathBuf {
        crate::config::config_dir().join("agent-groups")
    }

    /// A unique, not-yet-created root under the temp dir, for a daemon that
    /// does not persist its session (tests).
    pub fn ephemeral_root() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "herdr-agent-groups-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    /// Nothing is read or created until the first call.
    pub fn open(root: PathBuf) -> Self {
        Self { root }
    }

    /// The stored document; the empty one at revision 0 before the first set
    /// or when the file is damaged.
    pub fn get(&self) -> AgentGroups {
        read_index(&self.root).document()
    }

    /// Replace the document when `revision` is the stored one, and return it
    /// at the next revision. `exists` says whether a terminal id is still
    /// held by this server (live or archived).
    pub fn set(
        &self,
        revision: u64,
        folders: Vec<AgentGroupFolder>,
        stars: Vec<String>,
        exists: impl Fn(&str) -> bool,
    ) -> Result<AgentGroups, GroupsError> {
        validate(&folders, &stars).map_err(GroupsError::Invalid)?;
        let mut outcome = None;
        self.mutate(exists, |index| {
            if index.revision != revision {
                outcome = Some(Err(GroupsError::Conflict(index.document())));
                return false;
            }
            index.revision += 1;
            index.folders = folders;
            index.stars = stars;
            // A remembered clear whose name the owner has since unfiled must
            // not move a later folder or star of that name.
            let unfiled: Vec<String> = index
                .cleared_names
                .iter()
                .filter(|(_, name)| !index.holds(name))
                .map(|(terminal_id, _)| terminal_id.clone())
                .collect();
            for terminal_id in unfiled {
                index.cleared_names.remove(&terminal_id);
            }
            outcome = Some(Ok(index.document()));
            true
        })
        .map_err(GroupsError::Io)?;
        outcome.expect("mutate runs the change once it holds the lock")
    }

    /// The owner renamed the agent in `terminal_id` from `previous` to `new`
    /// (`None` = no name, as after `agent rename --clear`). Its folder and
    /// star move to the new name, also when it is named again after a clear.
    /// A clear alone leaves them under the old name. Returns whether the
    /// document changed.
    pub fn follow_rename(
        &self,
        terminal_id: &str,
        previous: Option<&str>,
        new: Option<&str>,
        exists: impl Fn(&str) -> bool,
    ) -> io::Result<bool> {
        // No index: nothing is filed or starred, so nothing follows.
        if previous == new || !self.root.join(INDEX_FILE).exists() {
            return Ok(false);
        }
        let mut revised = false;
        self.mutate(exists, |index| {
            let revision = index.revision;
            let changed = index.follow_rename(terminal_id, previous, new);
            revised = index.revision != revision;
            changed
        })?;
        Ok(revised)
    }

    /// The agent in `terminal_id` took `name` other than by a rename (it was
    /// started or unarchived with it). A clear another terminal remembered
    /// for `name` no longer moves this agent's folder and star.
    pub fn name_taken(
        &self,
        terminal_id: &str,
        name: &str,
        exists: impl Fn(&str) -> bool,
    ) -> io::Result<()> {
        if !self.root.join(INDEX_FILE).exists() {
            return Ok(());
        }
        self.mutate(exists, |index| index.name_taken(terminal_id, name))
    }

    /// Read-modify-write the index under `.index.lock`, so a daemon sharing
    /// the directory never loses the other's write. `change` returns whether
    /// to write. Remembered clears of terminals `exists` no longer knows are
    /// dropped, so they never pile up.
    fn mutate(
        &self,
        exists: impl Fn(&str) -> bool,
        change: impl FnOnce(&mut IndexFile) -> bool,
    ) -> io::Result<()> {
        create_private_dir(&self.root)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join(LOCK_FILE))?;
        lock.lock()?;
        let mut index = read_index(&self.root);
        let changed = change(&mut index);
        let remembered = index.cleared_names.len();
        index
            .cleared_names
            .retain(|terminal_id, _| exists(terminal_id));
        if changed || index.cleared_names.len() != remembered {
            super::devices::save_owner_only_json(&self.root.join(INDEX_FILE), &index)?;
        }
        Ok(())
    }
}

/// The stored index; empty when missing, corrupt or unreadable.
fn read_index(root: &Path) -> IndexFile {
    let path = root.join(INDEX_FILE);
    let parsed = match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return IndexFile::default(),
        Err(err) => Err(err),
    };
    parsed.unwrap_or_else(|err| {
        tracing::warn!(path = %path.display(), err = %err, "agent groups index unreadable; reading it as empty");
        IndexFile::default()
    })
}

/// Check the limits and rules of a document a client sent.
pub fn validate(folders: &[AgentGroupFolder], stars: &[String]) -> Result<(), String> {
    if folders.len() > MAX_FOLDERS {
        return Err(format!("at most {MAX_FOLDERS} folders"));
    }
    let members: usize = folders.iter().map(|folder| folder.members.len()).sum();
    if members > MAX_MEMBERS {
        return Err(format!("at most {MAX_MEMBERS} folder members in total"));
    }
    if stars.len() > MAX_STARS {
        return Err(format!("at most {MAX_STARS} stars"));
    }
    let mut ids = BTreeSet::new();
    let mut filed = BTreeSet::new();
    for folder in folders {
        check_name("folder id", &folder.id)?;
        check_name("folder name", &folder.name)?;
        if !ids.insert(folder.id.as_str()) {
            return Err(format!("duplicate folder id {:?}", folder.id));
        }
        for member in &folder.members {
            check_name("agent name", member)?;
            if !filed.insert(member.as_str()) {
                return Err(format!("agent {member:?} is in more than one folder"));
            }
        }
    }
    let mut starred = BTreeSet::new();
    for star in stars {
        check_name("agent name", star)?;
        if !starred.insert(star.as_str()) {
            return Err(format!("agent {star:?} is starred twice"));
        }
    }
    Ok(())
}

fn check_name(what: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{what} must not be empty"));
    }
    if value.chars().count() > MAX_NAME_CHARS {
        return Err(format!(
            "{what} {value:?} is longer than {MAX_NAME_CHARS} characters"
        ));
    }
    Ok(())
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store under a fresh temp root, deleted when dropped.
    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = AgentGroupsStore::ephemeral_root();
            let _ = fs::remove_dir_all(&root);
            Self { root }
        }

        /// A fresh store over the same directory, as after a daemon restart.
        fn store(&self) -> AgentGroupsStore {
            AgentGroupsStore::open(self.root.clone())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn folder(id: &str, name: &str, order: i64, members: &[&str]) -> AgentGroupFolder {
        AgentGroupFolder {
            id: id.into(),
            name: name.into(),
            order,
            members: members.iter().map(|member| member.to_string()).collect(),
        }
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    /// Every terminal still exists.
    fn all(_: &str) -> bool {
        true
    }

    /// The remembered clears in the file, terminal id to name.
    fn remembered(fixture: &Fixture) -> BTreeMap<String, String> {
        read_index(&fixture.root).cleared_names
    }

    #[test]
    fn a_set_document_reads_back_and_survives_a_reload() {
        let fixture = Fixture::new();
        let store = fixture.store();
        assert_eq!(store.get(), AgentGroups::default());
        assert!(!fixture.root.exists(), "a read creates nothing");

        let folders = vec![
            folder("f1", "Reviews", 1, &["enyo-review", "enyo-efm"]),
            folder("f2", "Builds", 0, &[]),
        ];
        let set = store
            .set(0, folders.clone(), names(&["llm-opt"]), |_| true)
            .expect("set");
        assert_eq!(set.revision, 1);
        assert_eq!(set.folders, folders);
        assert_eq!(set.stars, names(&["llm-opt"]));
        assert_eq!(store.get(), set);

        let reloaded = fixture.store().get();
        assert_eq!(reloaded, set);
        let next = fixture
            .store()
            .set(1, Vec::new(), Vec::new(), |_| true)
            .expect("second set");
        assert_eq!(next.revision, 2);
        assert_eq!(fixture.store().get(), next);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(fixture.root.join(INDEX_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            assert!(!fixture.root.join("index.json.tmp").exists());
        }
    }

    #[test]
    fn a_stale_revision_is_a_conflict_carrying_the_stored_document() {
        let fixture = Fixture::new();
        let phone = fixture.store();
        let mac = fixture.store();
        let stored = phone
            .set(
                0,
                vec![folder("f1", "Reviews", 0, &["a"])],
                Vec::new(),
                |_| true,
            )
            .expect("first writer");

        match mac.set(0, Vec::new(), names(&["b"]), |_| true) {
            Err(GroupsError::Conflict(current)) => assert_eq!(current, stored),
            other => panic!("expected a conflict, got {other:?}"),
        }
        match mac.set(7, Vec::new(), Vec::new(), |_| true) {
            Err(GroupsError::Conflict(current)) => assert_eq!(current, stored),
            other => panic!("expected a conflict, got {other:?}"),
        }
        assert_eq!(fixture.store().get(), stored, "a conflict writes nothing");

        let merged = mac
            .set(
                stored.revision,
                stored.folders.clone(),
                names(&["b"]),
                |_| true,
            )
            .expect("retry at the current revision");
        assert_eq!(merged.revision, 2);
        assert_eq!(merged.stars, names(&["b"]));
    }

    #[test]
    fn invalid_documents_are_refused_and_change_nothing() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let long = "x".repeat(MAX_NAME_CHARS + 1);
        let at_limit = "é".repeat(MAX_NAME_CHARS);
        let too_many_folders: Vec<_> = (0..=MAX_FOLDERS)
            .map(|index| folder(&format!("f{index}"), "F", 0, &[]))
            .collect();
        // Two folders that each fit, but not together.
        let too_many_members: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|prefix| AgentGroupFolder {
                id: prefix.into(),
                name: prefix.into(),
                order: 0,
                members: (0..=MAX_MEMBERS / 2)
                    .map(|index| format!("{prefix}{index}"))
                    .collect(),
            })
            .collect();
        let too_many_stars: Vec<String> =
            (0..=MAX_STARS).map(|index| format!("s{index}")).collect();
        let cases: Vec<(Vec<AgentGroupFolder>, Vec<String>, &str)> = vec![
            (too_many_folders, Vec::new(), "folders"),
            (too_many_members, Vec::new(), "members"),
            (Vec::new(), too_many_stars, "stars"),
            (vec![folder("f1", &long, 0, &[])], Vec::new(), "longer"),
            (vec![folder(&long, "A", 0, &[])], Vec::new(), "longer"),
            (
                vec![folder("f1", "A", 0, &[long.as_str()])],
                Vec::new(),
                "longer",
            ),
            (Vec::new(), vec![long.clone()], "longer"),
            (vec![folder("f1", " ", 0, &[])], Vec::new(), "empty"),
            (vec![folder("", "A", 0, &[])], Vec::new(), "empty"),
            (Vec::new(), names(&[""]), "empty"),
            (
                vec![folder("f1", "A", 0, &[]), folder("f1", "B", 1, &[])],
                Vec::new(),
                "duplicate folder id",
            ),
            (
                vec![folder("f1", "A", 0, &["a"]), folder("f2", "B", 1, &["a"])],
                Vec::new(),
                "more than one folder",
            ),
            (
                vec![folder("f1", "A", 0, &["a", "a"])],
                Vec::new(),
                "more than one folder",
            ),
            (Vec::new(), names(&["a", "a"]), "starred twice"),
        ];
        for (folders, stars, expected) in cases {
            match store.set(0, folders, stars, |_| true) {
                Err(GroupsError::Invalid(message)) => {
                    assert!(message.contains(expected), "{message:?} lacks {expected:?}")
                }
                other => panic!("expected invalid ({expected}), got {other:?}"),
            }
        }
        assert!(!fixture.root.join(INDEX_FILE).exists());

        // The limits themselves are allowed.
        let full: Vec<_> = (0..MAX_FOLDERS)
            .map(|index| {
                let members: Vec<String> = (0..MAX_MEMBERS / MAX_FOLDERS)
                    .map(|member| format!("a{index}-{member}"))
                    .collect();
                AgentGroupFolder {
                    id: format!("f{index}"),
                    name: at_limit.clone(),
                    order: index as i64,
                    members,
                }
            })
            .collect();
        let stars: Vec<String> = (0..MAX_STARS).map(|index| format!("s{index}")).collect();
        let stored = store
            .set(0, full, stars, |_| true)
            .expect("a document at every limit");
        assert_eq!(stored.folders.len(), MAX_FOLDERS);
    }

    #[test]
    fn a_rename_moves_the_folder_and_star_to_the_new_name() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .set(
                0,
                vec![
                    folder("f1", "Reviews", 0, &["enyo-review", "gone"]),
                    folder("f2", "Other", 1, &["keep"]),
                ],
                names(&["enyo-review", "keep"]),
                |_| true,
            )
            .unwrap();

        assert!(store
            .follow_rename("t1", Some("enyo-review"), Some("enyo-rev"), all)
            .unwrap());
        let after = fixture.store().get();
        assert_eq!(
            after.revision, 2,
            "clients holding the old revision re-read"
        );
        assert_eq!(after.folders[0].members, names(&["enyo-rev", "gone"]));
        assert_eq!(after.folders[1].members, names(&["keep"]));
        assert_eq!(after.stars, names(&["enyo-rev", "keep"]));

        // A name nothing files changes nothing, not even the revision.
        assert!(!store
            .follow_rename("t2", Some("loose"), Some("looser"), all)
            .unwrap());
        assert_eq!(store.get().revision, 2);

        // Renaming onto a stale entry of a forgotten agent: the renamed
        // agent's own folder wins and the name stays in one folder.
        assert!(store
            .follow_rename("t1", Some("enyo-rev"), Some("keep"), all)
            .unwrap());
        let after = store.get();
        assert_eq!(after.folders[0].members, names(&["keep", "gone"]));
        assert!(after.folders[1].members.is_empty());
        assert_eq!(after.stars, names(&["keep"]));
    }

    #[test]
    fn a_clear_keeps_the_folder_and_naming_again_moves_it() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .set(
                0,
                vec![folder("f1", "Reviews", 0, &["enyo-review"])],
                names(&["enyo-review"]),
                |_| true,
            )
            .unwrap();

        assert!(!store
            .follow_rename("t1", Some("enyo-review"), None, all)
            .unwrap());
        let cleared = fixture.store().get();
        assert_eq!(cleared.revision, 1, "a clear leaves the document alone");
        assert_eq!(cleared.folders[0].members, names(&["enyo-review"]));
        assert_eq!(cleared.stars, names(&["enyo-review"]));

        // Another terminal's agent named for the first time moves nothing.
        assert!(!fixture
            .store()
            .follow_rename("t2", None, Some("fresh"), all)
            .unwrap());
        // Named again after a restart: the remembered name follows.
        assert!(fixture
            .store()
            .follow_rename("t1", None, Some("enyo-again"), all)
            .unwrap());
        let named = store.get();
        assert_eq!(named.revision, 2);
        assert_eq!(named.folders[0].members, names(&["enyo-again"]));
        assert_eq!(named.stars, names(&["enyo-again"]));

        // Followed once: a later clear-free naming of t1 has nothing pending.
        assert!(!store.follow_rename("t1", None, Some("other"), all).unwrap());
        assert_eq!(store.get(), named);
    }

    #[test]
    fn a_clear_whose_name_the_owner_unfiled_is_forgotten() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .set(0, vec![folder("f1", "A", 0, &["old"])], Vec::new(), |_| {
                true
            })
            .unwrap();
        store
            .follow_rename("t1", Some("old"), None, |_| true)
            .unwrap();
        // The owner takes "old" out of its folder, then files a new "old".
        store
            .set(1, vec![folder("f1", "A", 0, &[])], Vec::new(), |_| true)
            .unwrap();
        store
            .set(2, vec![folder("f1", "A", 0, &["old"])], Vec::new(), |_| {
                true
            })
            .unwrap();
        assert!(!store.follow_rename("t1", None, Some("new"), all).unwrap());
        assert_eq!(store.get().folders[0].members, names(&["old"]));
    }

    #[test]
    fn a_corrupt_index_reads_as_empty_and_the_next_set_rewrites_it() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .set(0, vec![folder("f1", "A", 0, &["a"])], names(&["a"]), |_| {
                true
            })
            .unwrap();
        for damage in [
            &b"{\"revision\": 3, \"folders\": [{\"id\""[..],
            b"\xff\xfe",
            b"{\"revision\": 5, \"folders\": 7}",
        ] {
            fs::write(fixture.root.join(INDEX_FILE), damage).unwrap();
            let reloaded = fixture.store();
            assert_eq!(reloaded.get(), AgentGroups::default());
            // Renames on the damaged file are harmless.
            assert!(!reloaded
                .follow_rename("t1", Some("a"), Some("b"), all)
                .unwrap());

            let rewritten = reloaded
                .set(0, vec![folder("f2", "B", 0, &["b"])], Vec::new(), |_| true)
                .expect("a set replaces the damaged file");
            assert_eq!(rewritten.revision, 1);
            assert_eq!(fixture.store().get(), rewritten);
        }
    }

    /// t1 is cleared while "old" is filed, then t2 takes "old" (renamed to it,
    /// or started or unarchived with it). The folder and star now mean t2:
    /// naming t1 again must not carry them off.
    #[test]
    fn a_name_another_terminal_took_after_a_clear_stays_with_that_terminal() {
        type Take = fn(&AgentGroupsStore, &str, &str);
        let by_rename: Take = |store, terminal_id, name| {
            store
                .follow_rename(terminal_id, Some("x"), Some(name), all)
                .unwrap();
        };
        let by_start: Take = |store, terminal_id, name| {
            store.name_taken(terminal_id, name, all).unwrap();
        };
        for take in [by_rename, by_start] {
            let fixture = Fixture::new();
            let store = fixture.store();
            store
                .set(
                    0,
                    vec![folder("f1", "Reviews", 0, &["old"])],
                    names(&["old"]),
                    all,
                )
                .unwrap();
            store.follow_rename("t1", Some("old"), None, all).unwrap();
            take(&store, "t2", "old");
            assert!(remembered(&fixture).is_empty());

            assert!(!store.follow_rename("t1", None, Some("new"), all).unwrap());
            let groups = store.get();
            assert_eq!(groups.revision, 1);
            assert_eq!(groups.folders[0].members, names(&["old"]));
            assert_eq!(groups.stars, names(&["old"]));
        }
    }

    #[test]
    fn remembered_clears_of_terminals_that_are_gone_are_dropped() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .set(0, vec![folder("f1", "A", 0, &["a", "b"])], Vec::new(), all)
            .unwrap();
        store.follow_rename("t1", Some("a"), None, all).unwrap();
        store.follow_rename("t2", Some("b"), None, all).unwrap();
        assert_eq!(remembered(&fixture).len(), 2);

        // t1's pane was closed: the next write forgets it, even one that
        // changes nothing else.
        let live = |terminal_id: &str| terminal_id == "t2";
        store.name_taken("t3", "unfiled", live).unwrap();
        assert_eq!(
            remembered(&fixture),
            BTreeMap::from([("t2".to_string(), "b".to_string())])
        );
        store
            .set(
                1,
                vec![folder("f1", "A", 0, &["a", "b"])],
                Vec::new(),
                |_| false,
            )
            .unwrap();
        assert!(remembered(&fixture).is_empty());
        assert!(!store.follow_rename("t2", None, Some("c"), all).unwrap());
        assert_eq!(store.get().folders[0].members, names(&["a", "b"]));
    }
}
