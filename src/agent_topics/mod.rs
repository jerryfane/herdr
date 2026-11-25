//! Topics (#474): the long-lived worker conversations inside one omp agent.
//!
//! An interactive omp launch with `topics.enabled` serves its topics on a
//! local control socket guarded by a per-launch token. The Herdr integration
//! running inside that omp process hands the endpoint over with
//! `pane.report_agent_control`; Herdr keeps it here, in server memory only,
//! per terminal, for as long as the agent process that offered it runs. It is
//! never persisted, exported in a live handoff, logged, or returned by the
//! API: anything that can reach the socket with the token controls the agent.
//!
//! Each endpoint also keeps the agent's last topic list ([`ListCache`]), so
//! `agent.topics.list` answers at once while the agent is busy and refreshes
//! it behind the answer.

pub(crate) mod control;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::api::schema::{
    AgentControlToken, AgentTopicChangeReason, AgentTopicInfo, AgentTopicSession, AgentTopicState,
    AgentTopicSuggestionInfo,
};
use crate::terminal::TerminalId;

/// The only control protocol this build speaks.
pub(crate) const CONTROL_PROTOCOL: u32 = 1;

/// Where one agent process serves its topics, and the secret it asks for.
/// `Debug` redacts the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlEndpoint {
    pub(crate) socket_path: PathBuf,
    pub(crate) token: AgentControlToken,
    /// The agent process that must serve the socket.
    pub(crate) pid: u32,
}

/// One registered endpoint, as a request worker takes it off the app thread.
#[derive(Clone)]
pub(crate) struct ControlHandle {
    pub(crate) endpoint: Arc<ControlEndpoint>,
    /// Changes whenever the terminal's endpoint is replaced, so topic updates
    /// read from an older one are dropped.
    pub(crate) generation: u64,
    pub(crate) updates: Arc<UpdatesSlot>,
    pub(crate) list: Arc<ListCache>,
}

/// The registered endpoints, by terminal.
#[derive(Default)]
pub(crate) struct AgentControls {
    entries: HashMap<TerminalId, Registered>,
    next_generation: u64,
    /// Tests stand in for herdr's foreground probe: `Some(pid)` is what it
    /// identifies as the pane's omp process.
    #[cfg(test)]
    pub(crate) inspected_pid_for_test: Option<Option<u32>>,
}

struct Registered {
    endpoint: Arc<ControlEndpoint>,
    generation: u64,
    updates: Arc<UpdatesSlot>,
    list: Arc<ListCache>,
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.updates.cancel();
        self.list.cancel();
    }
}

impl AgentControls {
    /// Register `endpoint` for `terminal_id`, replacing any other. The same
    /// endpoint reported again keeps its generation and its update stream.
    pub(crate) fn register(&mut self, terminal_id: TerminalId, endpoint: ControlEndpoint) {
        if self
            .entries
            .get(&terminal_id)
            .is_some_and(|registered| *registered.endpoint == endpoint)
        {
            return;
        }
        self.next_generation += 1;
        self.entries.insert(
            terminal_id,
            Registered {
                endpoint: Arc::new(endpoint),
                generation: self.next_generation,
                updates: Arc::default(),
                list: Arc::default(),
            },
        );
    }

    /// Forget the terminal's endpoint and end its update stream.
    pub(crate) fn remove(&mut self, terminal_id: &str) -> bool {
        self.entries.remove(terminal_id).is_some()
    }

    /// Whether the terminal's agent offers a control right now.
    pub(crate) fn contains(&self, terminal_id: &str) -> bool {
        self.entries.contains_key(terminal_id)
    }

    pub(crate) fn handle(&self, terminal_id: &str) -> Option<ControlHandle> {
        self.entries
            .get(terminal_id)
            .map(|registered| ControlHandle {
                endpoint: Arc::clone(&registered.endpoint),
                generation: registered.generation,
                updates: Arc::clone(&registered.updates),
                list: Arc::clone(&registered.list),
            })
    }

    /// The agent process the terminal's endpoint was offered by.
    pub(crate) fn pid(&self, terminal_id: &str) -> Option<u32> {
        self.entries
            .get(terminal_id)
            .map(|registered| registered.endpoint.pid)
    }

    pub(crate) fn is_current(&self, terminal_id: &str, generation: u64) -> bool {
        self.entries
            .get(terminal_id)
            .is_some_and(|registered| registered.generation == generation)
    }
}

/// The `topic_update` stream of one registered endpoint, opened on the first
/// `agent.topics.*` request and ended when the endpoint is dropped.
#[derive(Default)]
pub(crate) struct UpdatesSlot {
    state: Mutex<UpdatesState>,
}

#[derive(Default)]
struct UpdatesState {
    /// The endpoint was dropped: no stream may start or stay.
    cancelled: bool,
    /// A reader owns the stream (or is opening it).
    running: bool,
    stream: Option<std::os::unix::net::UnixStream>,
}

impl UpdatesSlot {
    fn lock(&self) -> std::sync::MutexGuard<'_, UpdatesState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Claim the slot for a new reader; false while one runs or once the
    /// endpoint is gone.
    pub(crate) fn claim(&self) -> bool {
        let mut state = self.lock();
        if state.cancelled || state.running {
            return false;
        }
        state.running = true;
        true
    }

    /// Keep a handle on the reader's stream so dropping the endpoint can end
    /// it; false (and the stream shut) when the endpoint is already gone.
    pub(crate) fn attach(&self, stream: std::os::unix::net::UnixStream) -> bool {
        let mut state = self.lock();
        if state.cancelled {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return false;
        }
        state.stream = Some(stream);
        true
    }

    /// The reader stopped; a later request may open a new stream.
    pub(crate) fn release(&self) {
        let mut state = self.lock();
        state.running = false;
        state.stream = None;
    }

    fn cancel(&self) {
        let mut state = self.lock();
        state.cancelled = true;
        if let Some(stream) = state.stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// The agent's last topic list for one endpoint. `agent.topics.list` answers
/// from it at once, then refreshes it from the agent behind the answer, one
/// refresh at a time; the agent's `topic_update` stream keeps it current in
/// between. Dropped with the endpoint.
#[derive(Default)]
pub(crate) struct ListCache {
    state: Mutex<ListState>,
}

#[derive(Default)]
struct ListState {
    /// The endpoint was dropped: nothing is stored or refreshed any more.
    cancelled: bool,
    /// A refresh is asking the agent.
    refreshing: bool,
    /// Something changed while it asked: it asks once more.
    again: bool,
    list: Option<TopicList>,
}

/// A topic list as `agent.topics.list` answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TopicList {
    pub(crate) topics: Vec<AgentTopicInfo>,
    pub(crate) suggestions: Option<Vec<AgentTopicSuggestionInfo>>,
    /// When the agent answered it, or when it was read from disk.
    pub(crate) as_of_unix_ms: u64,
    /// Not the agent's own latest answer: read from disk, changed since, or
    /// the last refresh failed.
    pub(crate) stale: bool,
}

impl TopicList {
    /// The topics the session file on disk records (`topic_sessions`): ids
    /// and titles only, every state `unknown`, stale until the agent answers.
    pub(crate) fn from_sessions(sessions: Vec<AgentTopicSession>, now_unix_ms: u64) -> Self {
        let topics = sessions
            .into_iter()
            .map(|session| {
                let created = session.created_unix_ms.unwrap_or(0);
                AgentTopicInfo {
                    title: session.title.unwrap_or_else(|| session.topic_id.clone()),
                    topic_id: session.topic_id,
                    state: AgentTopicState::Unknown,
                    turns: 0,
                    queued: 0,
                    created_unix_ms: created,
                    last_activity_unix_ms: created,
                    last_activity: None,
                }
            })
            .collect();
        Self {
            topics,
            suggestions: None,
            as_of_unix_ms: now_unix_ms,
            stale: true,
        }
    }
}

impl ListCache {
    fn lock(&self) -> std::sync::MutexGuard<'_, ListState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn get(&self) -> Option<TopicList> {
        self.lock().list.clone()
    }

    /// Fill an empty cache with `list`; what the cache holds afterwards.
    pub(crate) fn seed(&self, list: TopicList) -> TopicList {
        let mut state = self.lock();
        if state.cancelled {
            return list;
        }
        state.list.get_or_insert(list).clone()
    }

    /// Keep the agent's answer; whether its topics or suggestions differ
    /// from what was kept.
    pub(crate) fn store(&self, list: TopicList) -> bool {
        let mut state = self.lock();
        if state.cancelled {
            return false;
        }
        let changed = state
            .list
            .as_ref()
            .is_none_or(|kept| kept.topics != list.topics || kept.suggestions != list.suggestions);
        state.list = Some(list);
        changed
    }

    /// The agent did not answer a refresh: what is kept is stale.
    pub(crate) fn refresh_failed(&self) {
        if let Some(list) = self.lock().list.as_mut() {
            list.stale = true;
        }
    }

    /// Claim the one refresh; false while one runs (it then asks once more)
    /// or once the endpoint is gone.
    pub(crate) fn begin_refresh(&self) -> bool {
        let mut state = self.lock();
        if state.cancelled {
            return false;
        }
        if state.refreshing {
            state.again = true;
            return false;
        }
        state.refreshing = true;
        state.again = false;
        true
    }

    /// The refresh asked; true when it must ask once more, else it ends.
    pub(crate) fn end_refresh(&self) -> bool {
        let mut state = self.lock();
        if state.again && !state.cancelled {
            state.again = false;
            return true;
        }
        state.refreshing = false;
        false
    }

    /// The claimed refresh never ran or stopped early.
    pub(crate) fn abandon_refresh(&self) {
        let mut state = self.lock();
        state.refreshing = false;
        state.again = false;
    }

    /// One change from the agent's `topic_update` stream: what it says for
    /// sure is applied at once, and the list is stale until refreshed.
    pub(crate) fn apply_change(&self, topic_id: &str, reason: AgentTopicChangeReason) {
        let mut state = self.lock();
        let Some(list) = state.list.as_mut() else {
            return;
        };
        list.stale = true;
        let state = match reason {
            AgentTopicChangeReason::TurnStarted => AgentTopicState::Running,
            AgentTopicChangeReason::TurnSettled => AgentTopicState::Idle,
            AgentTopicChangeReason::Closed => AgentTopicState::Closed,
            _ => return,
        };
        if let Some(topic) = list
            .topics
            .iter_mut()
            .find(|topic| topic.topic_id == topic_id)
        {
            topic.state = state;
        }
    }

    fn cancel(&self) {
        let mut state = self.lock();
        state.cancelled = true;
        state.list = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(path: &str, pid: u32) -> ControlEndpoint {
        ControlEndpoint {
            socket_path: PathBuf::from(path),
            token: AgentControlToken::new("t".repeat(32)),
            pid,
        }
    }

    #[test]
    fn re_registering_the_same_endpoint_keeps_its_generation() {
        let mut controls = AgentControls::default();
        let terminal = TerminalId::from_persisted("term_1".into());
        controls.register(terminal.clone(), endpoint("/tmp/a.sock", 7));
        let first = controls.handle("term_1").unwrap().generation;
        controls.register(terminal.clone(), endpoint("/tmp/a.sock", 7));
        assert!(controls.is_current("term_1", first));
        controls.register(terminal, endpoint("/tmp/b.sock", 7));
        assert!(!controls.is_current("term_1", first));
        assert!(controls.remove("term_1"));
        assert_eq!(controls.pid("term_1"), None);
    }

    #[test]
    fn dropping_an_endpoint_ends_its_update_stream() {
        let mut controls = AgentControls::default();
        controls.register(
            TerminalId::from_persisted("term_1".into()),
            endpoint("/tmp/a.sock", 7),
        );
        let updates = controls.handle("term_1").unwrap().updates;
        assert!(updates.claim());
        assert!(!updates.claim(), "one reader at a time");
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(updates.attach(ours));
        controls.remove("term_1");
        let mut byte = [0u8; 1];
        // The reader's end was shut down, so its peer reads end-of-stream.
        assert_eq!(std::io::Read::read(&mut &theirs, &mut byte).unwrap(), 0);
        assert!(!updates.claim(), "a dropped endpoint never streams again");
    }

    fn topic(id: &str, state: AgentTopicState) -> AgentTopicInfo {
        AgentTopicInfo {
            topic_id: id.into(),
            title: id.into(),
            state,
            turns: 1,
            queued: 0,
            created_unix_ms: 1,
            last_activity_unix_ms: 2,
            last_activity: None,
        }
    }

    fn answer(topics: Vec<AgentTopicInfo>, as_of_unix_ms: u64) -> TopicList {
        TopicList {
            topics,
            suggestions: None,
            as_of_unix_ms,
            stale: false,
        }
    }

    #[test]
    fn one_refresh_runs_at_a_time_and_asks_once_more_for_what_came_meanwhile() {
        let cache = ListCache::default();
        assert!(cache.begin_refresh());
        assert!(!cache.begin_refresh(), "one refresh at a time");
        assert!(!cache.begin_refresh());
        assert!(cache.end_refresh(), "requests meanwhile: one more round");
        assert!(!cache.end_refresh(), "then it ends");
        assert!(cache.begin_refresh(), "a later request starts a new one");
        cache.abandon_refresh();
        assert!(cache.begin_refresh());
    }

    #[test]
    fn the_kept_list_tells_a_changed_answer_and_turns_stale_when_the_agent_fails() {
        let cache = ListCache::default();
        assert!(cache.store(answer(vec![topic("a", AgentTopicState::Idle)], 1)));
        assert!(
            !cache.store(answer(vec![topic("a", AgentTopicState::Idle)], 2)),
            "the same topics are no change"
        );
        assert_eq!(cache.get().unwrap().as_of_unix_ms, 2);
        cache.refresh_failed();
        assert!(cache.get().unwrap().stale);
        assert!(cache.store(answer(vec![topic("a", AgentTopicState::Running)], 3)));
        assert!(!cache.get().unwrap().stale);
    }

    #[test]
    fn a_seed_from_disk_fills_only_an_empty_cache() {
        let cache = ListCache::default();
        let seeded = cache.seed(TopicList::from_sessions(
            vec![AgentTopicSession {
                topic_id: "Plan".into(),
                path: "/s/Plan.jsonl".into(),
                title: None,
                created_unix_ms: Some(5),
            }],
            9,
        ));
        assert!(seeded.stale);
        assert_eq!(seeded.as_of_unix_ms, 9);
        assert_eq!(seeded.topics[0].title, "Plan");
        assert_eq!(seeded.topics[0].state, AgentTopicState::Unknown);
        assert_eq!(seeded.topics[0].last_activity_unix_ms, 5);
        cache.store(answer(vec![topic("a", AgentTopicState::Idle)], 10));
        let kept = cache.seed(TopicList::from_sessions(Vec::new(), 11));
        assert_eq!(kept.topics[0].topic_id, "a", "the agent's answer stays");
    }

    #[test]
    fn a_streamed_change_marks_the_list_stale_and_applies_what_it_says_for_sure() {
        let cache = ListCache::default();
        cache.store(answer(vec![topic("a", AgentTopicState::Idle)], 1));
        cache.apply_change("a", AgentTopicChangeReason::TurnStarted);
        let kept = cache.get().unwrap();
        assert!(kept.stale);
        assert_eq!(kept.topics[0].state, AgentTopicState::Running);
        cache.apply_change("a", AgentTopicChangeReason::Closed);
        assert_eq!(
            cache.get().unwrap().topics[0].state,
            AgentTopicState::Closed
        );
    }

    #[test]
    fn dropping_an_endpoint_drops_its_kept_list() {
        let mut controls = AgentControls::default();
        controls.register(
            TerminalId::from_persisted("term_1".into()),
            endpoint("/tmp/a.sock", 7),
        );
        let list = controls.handle("term_1").unwrap().list;
        list.store(answer(vec![topic("a", AgentTopicState::Idle)], 1));
        controls.remove("term_1");
        assert!(list.get().is_none());
        assert!(
            !list.store(answer(Vec::new(), 2)),
            "nothing is kept any more"
        );
        assert!(list.get().is_none());
        assert!(!list.begin_refresh(), "nor refreshed");
    }
}
