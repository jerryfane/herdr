//! The topics of an omp session, read from its session file. omp records each
//! topic it spawns as a `vibe-session-lifecycle` custom entry with
//! `scope: "topics"`, `action: "spawn"`, the topic `id` and its
//! `childSessionFile` (`<id>.jsonl`, in the directory named after the session
//! file, beside the session's subagents); `retitled` entries carry later
//! titles. The listing never asks the agent, so it is the same whether or not
//! the agent can be reached.
//!
//! A session file only grows (omp rewrites its padded title line in place),
//! so each file's scan is remembered with the offset it reached and continued
//! from there; a file that shrank or whose session header changed is scanned
//! again from the start.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use serde::Deserialize;

use crate::api::schema::AgentTopicSession;

const LIFECYCLE_TYPE: &str = "vibe-session-lifecycle";
/// Where a session file's header must appear.
const HEADER_BYTES: u64 = 16 * 1024;
/// Session files whose scan is remembered.
const CACHED_SCANS: usize = 64;

#[derive(Debug, Clone, Default)]
struct Scan {
    /// The session header line the scan was made under.
    header: Vec<u8>,
    /// Bytes of whole lines read so far.
    scanned: u64,
    /// Topics in spawn order.
    topics: Vec<Topic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Topic {
    id: String,
    title: Option<String>,
    created_unix_ms: Option<u64>,
}

static SCANS: LazyLock<Mutex<HashMap<PathBuf, Scan>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The topic transcripts of the session in `session`, in spawn order: every
/// topic the session file records whose own session file exists.
pub(crate) fn topic_sessions(session: &Path) -> std::io::Result<Vec<AgentTopicSession>> {
    Ok(scan(session)?
        .into_iter()
        .filter_map(|topic| {
            let path = super::subagents::child_path(session, &topic.id)?;
            path.is_file().then(|| AgentTopicSession {
                topic_id: topic.id,
                path: path.display().to_string(),
                title: topic.title,
                created_unix_ms: topic.created_unix_ms,
            })
        })
        .collect())
}

/// The session file of `session`'s topic `id`, when the session file records
/// that topic.
pub(super) fn topic_session(session: &Path, id: &str) -> Option<PathBuf> {
    scan(session)
        .ok()?
        .iter()
        .any(|topic| topic.id == id)
        .then(|| super::subagents::child_path(session, id))
        .flatten()
}

fn scan(session: &Path) -> std::io::Result<Vec<Topic>> {
    let mut file = match File::open(session) {
        Ok(file) => file,
        // omp names a new session's file before its first turn writes it.
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && session.parent().is_some_and(Path::is_dir) =>
        {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    let header = session_header(&mut file)?;
    let len = file.metadata()?.len();
    let previous = SCANS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(session);
    let mut scan = previous
        .filter(|scan| scan.header == header && scan.scanned <= len)
        .unwrap_or_else(|| Scan {
            header,
            ..Scan::default()
        });
    file.seek(SeekFrom::Start(scan.scanned))?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        // A last line without its newline is still being written: read it
        // again next time.
        if read == 0 || line.last() != Some(&b'\n') {
            break;
        }
        scan.scanned += read as u64;
        if contains(&line, LIFECYCLE_TYPE.as_bytes()) {
            apply(&mut scan.topics, &line);
        }
    }
    let topics = scan.topics.clone();
    let mut scans = SCANS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if scans.len() >= CACHED_SCANS {
        scans.clear();
    }
    scans.insert(session.to_path_buf(), scan);
    Ok(topics)
}

/// The `"type":"session"` header line in the file's first bytes; empty when
/// there is none yet.
fn session_header(file: &mut File) -> std::io::Result<Vec<u8>> {
    #[derive(Deserialize)]
    struct Header {
        #[serde(rename = "type", default)]
        kind: Option<String>,
    }
    let mut head = Vec::new();
    file.take(HEADER_BYTES).read_to_end(&mut head)?;
    Ok(head
        .split(|&byte| byte == b'\n')
        .find(|line| {
            serde_json::from_slice::<Header>(line)
                .is_ok_and(|header| header.kind.as_deref() == Some("session"))
        })
        .map(<[u8]>::to_vec)
        .unwrap_or_default())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Apply one session line that may be a topic lifecycle entry.
fn apply(topics: &mut Vec<Topic>, line: &[u8]) {
    #[derive(Deserialize)]
    struct Entry {
        #[serde(rename = "type", default)]
        kind: Option<String>,
        #[serde(rename = "customType", default)]
        custom_type: Option<String>,
        #[serde(default)]
        data: Option<Lifecycle>,
    }
    #[derive(Deserialize)]
    struct Lifecycle {
        #[serde(default)]
        scope: Option<String>,
        #[serde(default)]
        action: Option<String>,
        #[serde(default)]
        id: Option<String>,
        #[serde(rename = "childSessionFile", default)]
        child_session_file: Option<String>,
        #[serde(rename = "createdAt", default)]
        created_at: Option<f64>,
        #[serde(default)]
        title: Option<String>,
    }
    let Ok(entry) = serde_json::from_slice::<Entry>(line) else {
        return;
    };
    if entry.kind.as_deref() != Some("custom")
        || entry.custom_type.as_deref() != Some(LIFECYCLE_TYPE)
    {
        return;
    }
    let Some(Lifecycle {
        scope: Some(scope),
        action: Some(action),
        id: Some(id),
        child_session_file,
        created_at,
        title,
    }) = entry.data
    else {
        return;
    };
    if scope != "topics" {
        return;
    }
    let known = topics.iter().position(|topic| topic.id == id);
    match (action.as_str(), known) {
        ("spawn" | "retitled", Some(index)) => {
            if title.is_some() {
                topics[index].title = title;
            }
        }
        // omp claims a child file for a topic only when it is named after
        // the topic's id, which keeps it in the session's own directory.
        ("spawn", None) if child_session_file == Some(format!("{id}.jsonl")) => {
            topics.push(Topic {
                id,
                title,
                created_unix_ms: created_at
                    .filter(|ms| ms.is_finite() && *ms >= 0.0)
                    .map(|ms| ms as u64),
            });
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::agent_transcript::tests::Fixture;

    fn spawn(id: &str, title: &str, created_at: u64) -> serde_json::Value {
        json!({"type": "custom", "customType": "vibe-session-lifecycle", "data": {
            "version": 1, "id": id, "ownerId": "owner", "parentSessionId": "sess-1",
            "scope": "topics", "action": "spawn", "cli": "good", "agent": "task",
            "childSessionFile": format!("{id}.jsonl"), "createdAt": created_at, "title": title,
        }})
    }

    fn child_file(session: &Fixture, id: &str) -> PathBuf {
        let path = super::super::subagents::child_path(&session.path, id).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{\"type\":\"session\"}\n").unwrap();
        path
    }

    #[test]
    fn topic_sessions_lists_spawned_topics_with_files_and_their_newest_titles() {
        let mut session = Fixture::new("topics-list");
        session.push(spawn("Plan", "Plan the release", 1_000));
        // A Vibe worker (no topics scope) and a malformed claim are not topics.
        let mut vibe = spawn("Worker", "w", 2_000);
        vibe["data"].as_object_mut().unwrap().remove("scope");
        session.push(vibe);
        let mut stray = spawn("Stray", "s", 3_000);
        stray["data"]["childSessionFile"] = json!("../elsewhere.jsonl");
        session.push(stray);
        session.push(spawn("Docs", "Docs", 4_000));
        let plan = child_file(&session, "Plan");
        child_file(&session, "Worker");
        child_file(&session, "Stray");
        child_file(&session, "Docs");
        session.push(
            json!({"type": "custom", "customType": "vibe-session-lifecycle", "data": {
                "version": 1, "id": "Plan", "ownerId": "owner", "parentSessionId": "sess-1",
                "scope": "topics", "action": "retitled", "title": "Ship it",
            }}),
        );

        let topics = topic_sessions(&session.path).unwrap();
        assert_eq!(
            topics
                .iter()
                .map(|topic| (topic.topic_id.as_str(), topic.title.as_deref()))
                .collect::<Vec<_>>(),
            vec![("Plan", Some("Ship it")), ("Docs", Some("Docs"))]
        );
        assert_eq!(topics[0].path, plan.display().to_string());
        assert_eq!(topics[0].created_unix_ms, Some(1_000));
        assert_eq!(
            topic_session(&session.path, "Docs"),
            super::super::subagents::child_path(&session.path, "Docs")
        );
        assert_eq!(topic_session(&session.path, "Worker"), None);
    }

    #[test]
    fn topic_sessions_continue_an_appended_scan_and_skip_a_partial_line() {
        let mut session = Fixture::new("topics-append");
        session.push(spawn("One", "One", 1));
        child_file(&session, "One");
        assert_eq!(topic_sessions(&session.path).unwrap().len(), 1);

        // Half a line: not read until its newline lands.
        let line = spawn("Two", "Two", 2).to_string();
        let (head, tail) = line.split_at(line.len() / 2);
        session.raw(head);
        child_file(&session, "Two");
        assert_eq!(topic_sessions(&session.path).unwrap().len(), 1);
        session.raw(&format!("{tail}\n"));
        let ids: Vec<_> = topic_sessions(&session.path)
            .unwrap()
            .into_iter()
            .map(|topic| topic.topic_id)
            .collect();
        assert_eq!(ids, ["One", "Two"]);
    }

    #[test]
    fn a_session_not_written_yet_has_no_topics() {
        let session = Fixture::new("topics-fresh");
        std::fs::remove_file(&session.path).unwrap();
        assert_eq!(topic_sessions(&session.path).unwrap(), Vec::new());
    }
}

#[cfg(test)]
mod page_tests {
    use super::super::{read_page, PageRequest, TranscriptError};
    use super::tests_support::spawn_entry;
    use crate::agent_transcript::tests::Fixture;

    #[test]
    fn a_topic_page_reads_the_topics_own_file_and_unknown_topics_are_refused() {
        let mut session = Fixture::new("topic-page-main");
        session.push(spawn_entry("Plan"));
        session.user("main question");
        let mut topic = Fixture::new("topic-page-child");
        topic.user("topic question");
        let child = super::super::subagents::child_path(&session.path, "Plan").unwrap();
        std::fs::create_dir_all(child.parent().unwrap()).unwrap();
        std::fs::copy(&topic.path, &child).unwrap();

        let page = read_page(
            &session.path,
            &PageRequest {
                topic: Some("Plan".into()),
                ..PageRequest::default()
            },
        )
        .unwrap();
        let entries = serde_json::to_value(&page.entries).unwrap();
        assert_eq!(entries[0]["text"], "topic question", "{entries}");

        let unknown = read_page(
            &session.path,
            &PageRequest {
                topic: Some("Nope".into()),
                ..PageRequest::default()
            },
        );
        assert!(matches!(unknown, Err(TranscriptError::TopicNotFound)));
    }

    /// omp's wrappers as a real omp topics session file records them (enyo,
    /// topic InvestordeckwithNicola, entry 16e61ea9, and the Inbox's
    /// `irc:incoming` notes from that topic); the bodies are shortened and
    /// neutral.
    const INBOX_ASK: &str = "<irc>\nAsked by Inbox (`Main`):\n\nFrom enyo (Inbox): The comments on deck v33 arrived in the Inbox. Please take it from here.\n\nHis 2 comments:\n1. Slide 2: align the boxes.\n2. Two scores: Option D only.\nYour answer goes back to `Main` when this turn ends; for an interim note write `agent://Main?progress`.\n\nAnother agent started this turn, so in it you cannot ask other topics.\n</irc>";
    const TOPIC_REPLY: &str =
        "<irc>\nReply from `Review`:\n\nThe numbers on slide 7 check out.\n</irc>";
    const HELPER_ASK: &str = "<irc>\nAsked by `helper`:\n\nWhich file?\n</irc>";

    fn topic_page(session: &Fixture, topic: &str) -> serde_json::Value {
        let page = read_page(
            &session.path,
            &PageRequest {
                topic: Some(topic.into()),
                ..PageRequest::default()
            },
        )
        .unwrap();
        serde_json::to_value(&page.entries).unwrap()
    }

    fn spawned(session: &mut Fixture, id: &str, title: &str, child: &Fixture) {
        let mut spawn = spawn_entry(id);
        spawn["data"]["title"] = serde_json::json!(title);
        session.push(spawn);
        let path = super::super::subagents::child_path(&session.path, id).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::copy(&child.path, &path).unwrap();
    }

    #[test]
    fn handovers_into_a_topic_are_relays_and_other_irc_stays_the_users() {
        let mut session = Fixture::new("relay-main");
        let review = Fixture::new("relay-review");
        spawned(&mut session, "Review", "Review the numbers", &review);
        let mut deck = Fixture::new("relay-deck");
        deck.user(INBOX_ASK);
        deck.user(TOPIC_REPLY);
        deck.user(HELPER_ASK);
        deck.user("plain owner text");
        spawned(&mut session, "Deck", "Investor deck", &deck);

        let entries = topic_page(&session, "Deck");
        assert_eq!(
            entries[0],
            serde_json::json!({"kind": "relay", "id": entries[0]["id"], "ts_ms": entries[0]["ts_ms"],
                "from": "Inbox", "direction": "to_topic",
                "text": "The comments on deck v33 arrived in the Inbox. Please take it from here.\n\nHis 2 comments:\n1. Slide 2: align the boxes.\n2. Two scores: Option D only."}),
            "{entries}"
        );
        assert_eq!(entries[1]["kind"], "relay");
        assert_eq!(entries[1]["from"], "Review the numbers");
        assert_eq!(entries[1]["topic_id"], "Review");
        assert_eq!(entries[1]["text"], "The numbers on slide 7 check out.");
        // Not a topic of this session: as before.
        assert_eq!(entries[2]["kind"], "user");
        assert_eq!(entries[2]["text"], HELPER_ASK);
        assert_eq!(entries[3]["kind"], "user");
    }

    #[test]
    fn what_a_topic_sends_the_inbox_is_a_relay_and_other_agents_stay_notes() {
        let mut session = Fixture::new("relay-inbox");
        let deck = Fixture::new("relay-inbox-deck");
        spawned(&mut session, "Deck", "Investor deck", &deck);
        session.user("start the deck");
        session.note(
            "irc:incoming",
            "<irc>\nIncoming IRC message from agent `Deck` (progress; its reply follows later):\n\nBrief sent; waiting for the build.\n</irc>",
            true,
            serde_json::json!({"id": "15dc457762d6e2ec", "from": "Deck",
                "message": "Brief sent; waiting for the build.", "progress": true}),
        );
        session.note(
            "irc:incoming",
            "<irc>\nIncoming IRC message from agent `GridReview`:\n\nCap verified.\n</irc>",
            true,
            serde_json::json!({"id": "15dc", "from": "GridReview", "message": "Cap verified."}),
        );
        let page = read_page(&session.path, &PageRequest::default()).unwrap();
        let entries = serde_json::to_value(&page.entries).unwrap();
        assert_eq!(entries[1]["kind"], "relay", "{entries}");
        assert_eq!(entries[1]["from"], "Investor deck");
        assert_eq!(entries[1]["topic_id"], "Deck");
        assert_eq!(entries[1]["direction"], "to_inbox");
        assert_eq!(entries[1]["text"], "Brief sent; waiting for the build.");
        assert_eq!(entries[2]["kind"], "note", "{entries}");
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    /// A session line recording that topic `id` was spawned.
    pub(crate) fn spawn_entry(id: &str) -> serde_json::Value {
        serde_json::json!({"type": "custom", "customType": "vibe-session-lifecycle", "data": {
            "version": 1, "id": id, "ownerId": "owner", "parentSessionId": "sess-1",
            "scope": "topics", "action": "spawn", "cli": "good", "agent": "task",
            "childSessionFile": format!("{id}.jsonl"), "createdAt": 1_000, "title": id,
        }})
    }
}
