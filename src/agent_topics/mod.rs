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
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

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
/// refresh at a time; a list request with nothing kept waits for that same
/// refresh. The agent's `topic_update` stream keeps it current in between.
/// Dropped with the endpoint.
#[derive(Default)]
pub(crate) struct ListCache {
    state: Mutex<ListState>,
    /// Signalled when a refresh round ends (answered, failed or abandoned)
    /// and when the endpoint is dropped.
    rounds: Condvar,
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
    /// Orders the agent's answers and the stream's changes: each ask takes
    /// a ticket before it asks, each applied change takes one too.
    seq: u64,
    /// The ticket of the answer kept in `list`.
    stored: u64,
    /// The ticket of the last change applied to `list`.
    changed: u64,
    /// Refresh rounds ended so far.
    rounds: u64,
    /// Why the last round did not answer, if it did not.
    failure: Option<ListFailure>,
    /// A list request gave up waiting with nothing kept: the first answer
    /// kept after it is announced (`listed`), as nobody else got it.
    missed: bool,
}

/// Why the agent's topics could not be listed, as `agent.topics.list`
/// answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListFailure {
    pub(crate) code: &'static str,
    pub(crate) message: String,
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

    /// Taken by an ask before it asks the agent; [`Self::store`] keeps its
    /// answer only when nothing newer is kept.
    pub(crate) fn ticket(&self) -> u64 {
        let mut state = self.lock();
        state.seq += 1;
        state.seq
    }

    /// Refresh rounds ended so far; [`Self::wait_answer`] waits for the next.
    pub(crate) fn rounds(&self) -> u64 {
        self.lock().rounds
    }

    /// Keep the agent's answer to the ask that took `ticket`, unless an
    /// answer to a later ask is kept already. A change applied after the
    /// ask began may be missing from it, so it is kept stale (the refresh
    /// asks again for that change). Whether it replaced a different list,
    /// or is the first answer after a list request gave up waiting for it;
    /// otherwise the first answer goes to the requests that wait for it.
    pub(crate) fn store(&self, ticket: u64, mut list: TopicList) -> bool {
        let mut state = self.lock();
        if state.cancelled {
            return false;
        }
        state.rounds += 1;
        state.failure = None;
        self.rounds.notify_all();
        if state.list.is_some() && ticket <= state.stored {
            return false;
        }
        if ticket < state.changed {
            list.stale = true;
        }
        let changed = match state.list.as_ref() {
            Some(kept) => kept.topics != list.topics || kept.suggestions != list.suggestions,
            None => std::mem::take(&mut state.missed),
        };
        state.stored = ticket;
        state.list = Some(list);
        changed
    }

    /// The agent did not answer this round's asks, retries included: what
    /// is kept is stale, and requests waiting for the round get `failure`.
    pub(crate) fn refresh_failed(&self, failure: ListFailure) {
        let mut state = self.lock();
        state.rounds += 1;
        state.failure = Some(failure);
        if let Some(list) = state.list.as_mut() {
            list.stale = true;
        }
        self.rounds.notify_all();
    }

    /// One ask of the round failed and is retried: what is kept is stale,
    /// and requests waiting for the round keep waiting.
    pub(crate) fn mark_stale(&self) {
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
        self.rounds.notify_all();
        false
    }

    /// The claimed refresh never ran or stopped early.
    pub(crate) fn abandon_refresh(&self) {
        let mut state = self.lock();
        state.refreshing = false;
        state.again = false;
        self.rounds.notify_all();
    }

    /// Whether a refresh may be retried after a failure: the endpoint is
    /// still there.
    pub(crate) fn is_live(&self) -> bool {
        !self.lock().cancelled
    }

    /// Wait, at most `timeout`, for the refresh round after `seen` (from
    /// [`Self::rounds`]) to end, and answer with what is kept then, or why
    /// there is nothing.
    pub(crate) fn wait_answer(
        &self,
        seen: u64,
        timeout: Duration,
    ) -> Result<TopicList, ListFailure> {
        let state = self.lock();
        let (mut state, _) = self
            .rounds
            .wait_timeout_while(state, timeout, |state| {
                state.rounds == seen && state.refreshing && !state.cancelled
            })
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(list) = state.list.clone() {
            return Ok(list);
        }
        if state.cancelled {
            return Err(ListFailure {
                code: "topics_unreachable",
                message: "the agent's control endpoint went away".into(),
            });
        }
        state.missed = true;
        if state.rounds == seen && state.refreshing {
            return Err(ListFailure {
                code: "topics_timeout",
                message: "the agent did not answer in time".into(),
            });
        }
        Err(state.failure.clone().unwrap_or_else(|| ListFailure {
            code: "topics_unreachable",
            message: "could not ask the agent for its topics".into(),
        }))
    }

    /// One change from the agent's `topic_update` stream: what it says for
    /// sure is applied at once, and the list is stale until refreshed. A
    /// reopened topic's state is `unknown` until the agent tells it.
    pub(crate) fn apply_change(&self, topic_id: &str, reason: AgentTopicChangeReason) {
        let mut state = self.lock();
        state.seq += 1;
        state.changed = state.seq;
        let Some(list) = state.list.as_mut() else {
            return;
        };
        list.stale = true;
        let state = match reason {
            AgentTopicChangeReason::TurnStarted => AgentTopicState::Running,
            AgentTopicChangeReason::TurnSettled => AgentTopicState::Idle,
            AgentTopicChangeReason::Closed => AgentTopicState::Closed,
            AgentTopicChangeReason::Reopened => AgentTopicState::Unknown,
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
        self.rounds.notify_all();
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

    /// Keep `list` as the answer to an ask that began now.
    fn keep(cache: &ListCache, list: TopicList) -> bool {
        cache.store(cache.ticket(), list)
    }

    fn failure() -> ListFailure {
        ListFailure {
            code: "topics_timeout",
            message: "the agent did not answer in time".into(),
        }
    }

    #[test]
    fn the_kept_list_tells_a_changed_answer_and_turns_stale_when_the_agent_fails() {
        let cache = ListCache::default();
        assert!(
            !keep(&cache, answer(vec![topic("a", AgentTopicState::Idle)], 1)),
            "the first answer goes to the requests that wait for it"
        );
        assert!(
            !keep(&cache, answer(vec![topic("a", AgentTopicState::Idle)], 2)),
            "the same topics are no change"
        );
        assert_eq!(cache.get().unwrap().as_of_unix_ms, 2);
        cache.refresh_failed(failure());
        assert!(cache.get().unwrap().stale);
        assert!(keep(
            &cache,
            answer(vec![topic("a", AgentTopicState::Running)], 3)
        ));
        assert!(!cache.get().unwrap().stale);
    }

    #[test]
    fn an_older_answer_never_replaces_a_newer_one() {
        let cache = ListCache::default();
        let first = cache.ticket();
        let second = cache.ticket();
        cache.store(
            second,
            answer(vec![topic("a", AgentTopicState::Running)], 2),
        );
        assert!(
            !cache.store(first, answer(vec![topic("a", AgentTopicState::Idle)], 1)),
            "the ask that began first answered last"
        );
        let kept = cache.get().unwrap();
        assert_eq!(kept.as_of_unix_ms, 2);
        assert_eq!(kept.topics[0].state, AgentTopicState::Running);
        assert!(!kept.stale);
    }

    #[test]
    fn an_answer_that_may_predate_a_streamed_change_is_kept_stale() {
        let cache = ListCache::default();
        let asked = cache.ticket();
        cache.apply_change("a", AgentTopicChangeReason::TurnStarted);
        cache.store(asked, answer(vec![topic("a", AgentTopicState::Idle)], 1));
        assert!(
            cache.get().unwrap().stale,
            "the change may be missing from it"
        );
        keep(
            &cache,
            answer(vec![topic("a", AgentTopicState::Running)], 2),
        );
        assert!(!cache.get().unwrap().stale);
    }

    #[test]
    fn list_requests_with_nothing_kept_join_the_one_refresh() {
        let cache = Arc::new(ListCache::default());
        let seen = cache.rounds();
        assert!(
            cache.begin_refresh(),
            "the first request starts the refresh"
        );
        assert!(!cache.begin_refresh(), "the second joins it");
        let waiters: Vec<_> = (0..2)
            .map(|_| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || cache.wait_answer(seen, Duration::from_secs(30)))
            })
            .collect();
        let ticket = cache.ticket();
        cache.store(ticket, answer(vec![topic("a", AgentTopicState::Idle)], 1));
        for waiter in waiters {
            assert_eq!(waiter.join().unwrap().unwrap().topics[0].topic_id, "a");
        }
        assert!(
            cache.end_refresh(),
            "it asks once more for the joined request"
        );
        assert!(!cache.end_refresh());
    }

    #[test]
    fn a_waiting_list_request_gets_why_the_refresh_failed() {
        let cache = Arc::new(ListCache::default());
        let seen = cache.rounds();
        assert!(cache.begin_refresh());
        let waiter = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || cache.wait_answer(seen, Duration::from_secs(30)))
        };
        cache.refresh_failed(failure());
        assert_eq!(waiter.join().unwrap(), Err(failure()));

        let seen = cache.rounds();
        let timed_out = cache.wait_answer(seen, Duration::from_millis(10));
        assert_eq!(timed_out.unwrap_err().code, "topics_timeout");
        cache.abandon_refresh();
        assert_eq!(
            cache.wait_answer(seen, Duration::from_secs(30)),
            Err(failure()),
            "an abandoned refresh does not keep it waiting"
        );
    }

    #[test]
    fn a_waiting_list_request_gets_the_answer_of_a_retried_ask() {
        let cache = Arc::new(ListCache::default());
        let seen = cache.rounds();
        assert!(cache.begin_refresh());
        let waiter = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || cache.wait_answer(seen, Duration::from_secs(30)))
        };
        // The first ask failed; the round pauses and asks again.
        let _failed = cache.ticket();
        cache.mark_stale();
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiter.is_finished(),
            "a retried ask does not end the round"
        );
        let retried = cache.ticket();
        assert!(
            !cache.store(retried, answer(vec![topic("a", AgentTopicState::Idle)], 1)),
            "the waiting request gets it, so nothing is announced"
        );
        assert_eq!(waiter.join().unwrap().unwrap().topics[0].topic_id, "a");
    }

    #[test]
    fn the_first_answer_after_a_request_gave_up_is_announced() {
        let cache = ListCache::default();
        let seen = cache.rounds();
        assert!(cache.begin_refresh());
        let gave_up = cache.wait_answer(seen, Duration::from_millis(10));
        assert_eq!(gave_up.unwrap_err().code, "topics_timeout");
        let ticket = cache.ticket();
        assert!(
            cache.store(ticket, answer(vec![topic("a", AgentTopicState::Idle)], 1)),
            "nobody got it: `listed` tells the request that gave up"
        );
        let ticket = cache.ticket();
        assert!(!cache.store(ticket, answer(vec![topic("a", AgentTopicState::Idle)], 2)));
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
        keep(&cache, answer(vec![topic("a", AgentTopicState::Idle)], 10));
        let kept = cache.seed(TopicList::from_sessions(Vec::new(), 11));
        assert_eq!(kept.topics[0].topic_id, "a", "the agent's answer stays");
    }

    #[test]
    fn a_streamed_change_marks_the_list_stale_and_applies_what_it_says_for_sure() {
        let cache = ListCache::default();
        keep(&cache, answer(vec![topic("a", AgentTopicState::Idle)], 1));
        cache.apply_change("a", AgentTopicChangeReason::TurnStarted);
        let kept = cache.get().unwrap();
        assert!(kept.stale);
        assert_eq!(kept.topics[0].state, AgentTopicState::Running);
        cache.apply_change("a", AgentTopicChangeReason::Closed);
        assert_eq!(
            cache.get().unwrap().topics[0].state,
            AgentTopicState::Closed
        );
        cache.apply_change("a", AgentTopicChangeReason::Reopened);
        assert_eq!(
            cache.get().unwrap().topics[0].state,
            AgentTopicState::Unknown,
            "reopened: no longer closed, its state comes with the next answer"
        );
        assert!(
            keep(&cache, answer(vec![topic("a", AgentTopicState::Idle)], 2)),
            "that answer is a change, so `listed` follows"
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
        keep(&list, answer(vec![topic("a", AgentTopicState::Idle)], 1));
        controls.remove("term_1");
        assert!(list.get().is_none());
        assert!(
            !keep(&list, answer(Vec::new(), 2)),
            "nothing is kept any more"
        );
        assert!(list.get().is_none());
        assert!(!list.begin_refresh(), "nor refreshed");
        assert!(!list.is_live());
        assert_eq!(
            list.wait_answer(list.rounds(), Duration::from_secs(30))
                .unwrap_err()
                .code,
            "topics_unreachable"
        );
    }
}
