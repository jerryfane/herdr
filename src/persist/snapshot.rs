use std::collections::HashMap;
use std::path::PathBuf;

use ratatui::layout::Direction;
use serde::{Deserialize, Serialize};

use crate::layout::Node;
use crate::terminal::TerminalRuntimeRegistry;
use crate::workspace::Workspace;

/// Current snapshot format version.
///
/// Bumped 3 → 4 for the additive `archived_agents` collection. The new field is
/// `#[serde(default)]`, so a v3 `session.json` still deserializes into a v4
/// `SessionSnapshot` with an empty `archived_agents`.
pub(super) const SNAPSHOT_VERSION: u32 = 4;

/// Serializable snapshot of the entire herdr session.
#[derive(Serialize, Deserialize)]
pub struct SessionSnapshot {
    /// Format version — used to detect incompatible changes.
    #[serde(default)]
    pub version: u32,
    pub workspaces: Vec<WorkspaceSnapshot>,
    pub active: Option<usize>,
    pub selected: usize,
    #[serde(default)]
    pub sidebar_width: Option<u16>,
    #[serde(default)]
    pub sidebar_section_split: Option<f32>,
    #[serde(default)]
    pub collapsed_space_keys: std::collections::HashSet<String>,
    /// Agents taken out of active rotation (issue #173, "archive"). Paneless:
    /// each record freezes the resume identity of an agent whose pane was
    /// released, so it can be resumed later without recreating the session.
    /// Additive — a v3 snapshot lacking this field restores to an empty list.
    #[serde(default)]
    pub archived_agents: Vec<ArchivedAgentSnapshot>,
}

#[derive(Serialize, Deserialize)]
pub struct SessionHistorySnapshot {
    /// Format version follows the matching session snapshot version.
    #[serde(default)]
    pub version: u32,
    pub workspaces: Vec<WorkspaceHistorySnapshot>,
}

#[derive(Serialize, Deserialize)]
pub struct WorkspaceHistorySnapshot {
    pub tabs: Vec<TabHistorySnapshot>,
}

#[derive(Serialize, Deserialize)]
pub struct TabHistorySnapshot {
    pub panes: HashMap<u32, PaneHistorySnapshot>,
}

#[derive(Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub custom_name: Option<String>,
    pub identity_cwd: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree_space: Option<crate::workspace::WorktreeSpaceMembership>,
    #[serde(default)]
    pub public_pane_numbers: HashMap<u32, usize>,
    #[serde(default)]
    pub next_public_pane_number: usize,
    #[serde(default)]
    pub public_tab_numbers: Vec<usize>,
    #[serde(default)]
    pub next_public_tab_number: usize,
    pub tabs: Vec<TabSnapshot>,
    #[serde(default)]
    pub active_tab: usize,
}

#[derive(Deserialize)]
struct LegacyWorkspaceSnapshot {
    #[serde(default)]
    custom_name: Option<String>,
    layout: LayoutSnapshot,
    panes: HashMap<u32, PaneSnapshot>,
    zoomed: bool,
    #[serde(default)]
    focused: Option<u32>,
    #[serde(default)]
    root_pane: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct TabSnapshot {
    #[serde(default)]
    pub custom_name: Option<String>,
    pub layout: LayoutSnapshot,
    pub panes: HashMap<u32, PaneSnapshot>,
    pub zoomed: bool,
    #[serde(default)]
    pub focused: Option<u32>,
    #[serde(default)]
    pub root_pane: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct PaneSnapshot {
    pub cwd: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_agent_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session: Option<PaneAgentSessionSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_argv: Option<Vec<String>>,
    /// Persisted terminal identity, so the terminal keeps the same
    /// [`crate::terminal::TerminalId`] across a daemon restart instead of being
    /// re-minted. Additive + optional: an old snapshot without it restores to a
    /// freshly allocated id (previous behavior).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_id: Option<String>,
    /// Occupant generation at capture time — bumped each time a different agent
    /// seizes the terminal — rehydrated on restore so the global identity
    /// `machine_id / terminal_id / occupant_generation` survives a restart.
    /// Additive: an old snapshot defaults it to 0.
    #[serde(default)]
    pub occupant_generation: u64,
    /// WHICH ACCOUNT THIS PANE RUNS UNDER — the registry id only.
    ///
    /// Account routing was previously not persisted at all, so every restore put every
    /// pane back on the harness default. A fleet that had been switched to a secondary
    /// account came back on the primary and kept writing to the PRIMARY transcript, which
    /// looked exactly like hours of work vanishing — the records were intact the whole
    /// time, in the other account's file.
    ///
    /// An ID, never an environment or a token. The launch env is REBUILT from the account
    /// registry at restore time, so a rotated config-home follows the registry and no
    /// credential material is ever written to the snapshot. An id that no longer resolves
    /// simply restores to the default, which is the old behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_account: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaneAgentSessionSnapshot {
    pub source: String,
    pub agent: String,
    pub kind: crate::agent_resume::AgentSessionRefKind,
    pub value: String,
}

/// A single archived agent (issue #173). Frozen at archive time: the resume
/// identity (`agent_session`), the stable `terminal_id` and `occupant_generation`
/// so an unarchive keeps the same global identity, the launch `cwd`, and the
/// opaque `parked_work` that gitmoot supplies and renders (herdr stores it
/// verbatim). This is both the durable serialized form and the runtime
/// `AppState.archived_agents` element — the two would be byte-identical given
/// `agent_session` already reuses the serializable [`PaneAgentSessionSnapshot`],
/// so they are one type rather than a lock-step-divergent pair.
///
/// `PartialEq` (not `Eq`) because `parked_work` holds arbitrary JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArchivedAgentSnapshot {
    /// The agent's display name (`agent rename`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The agent kind label (e.g. `claude`, `codex`), for display and resume.
    pub kind: String,
    /// The stable terminal identity, preserved across the archive so an
    /// unarchive resumes into the same `machine_id / terminal_id` slot.
    pub terminal_id: String,
    /// The resumable session identity, frozen from the live terminal.
    pub agent_session: PaneAgentSessionSnapshot,
    pub cwd: PathBuf,
    /// Occupant generation at archive time, rehydrated on unarchive.
    #[serde(default)]
    pub occupant_generation: u64,
    /// Who archived it and when, plus an optional reason.
    pub archived: ArchivedAgentMeta,
    /// Opaque open-work list, stored and returned verbatim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parked_work: Vec<serde_json::Value>,
    /// WHERE THE AGENT CAME FROM, so an unarchive can put it back rather than
    /// stranding it somewhere new.
    ///
    /// Without these, unarchive allocated a fresh pane in a brand-new workspace and
    /// the pane LABEL — which lived on the pane that archiving destroyed — could not
    /// come back at all. That is not cosmetic: fleet tooling binds a role to its pane
    /// BY LABEL, so every restored agent silently lost its binding and became
    /// unreachable on that channel while looking perfectly healthy.
    ///
    /// All three are optional and `#[serde(default)]` so snapshots written before this
    /// existed still load (same contract as `archived_agents` itself). `None` means
    /// "origin unknown" and the restore falls back to a new workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_tab_id: Option<String>,
    /// The pane's user-facing label at archive time (what `pane.rename` sets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pane_label: Option<String>,
}

/// The `archived { at, by, reason }` provenance block on an [`ArchivedAgentSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedAgentMeta {
    /// RFC3339 timestamp of when the agent was archived.
    pub at: String,
    /// Who requested the archive (caller-supplied identity).
    pub by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PaneHistorySnapshot {
    pub ansi: String,
    pub lines: usize,
}

/// Serializable BSP tree.
#[derive(Serialize, Deserialize)]
pub enum LayoutSnapshot {
    Pane(u32),
    Split {
        direction: DirectionSnapshot,
        ratio: f32,
        first: Box<LayoutSnapshot>,
        second: Box<LayoutSnapshot>,
    },
}

#[derive(Serialize, Deserialize)]
pub enum DirectionSnapshot {
    Horizontal,
    Vertical,
}

impl From<LegacyWorkspaceSnapshot> for WorkspaceSnapshot {
    fn from(snap: LegacyWorkspaceSnapshot) -> Self {
        let identity_cwd = legacy_identity_cwd(&snap);
        let tab = TabSnapshot {
            custom_name: None,
            layout: snap.layout,
            panes: snap.panes,
            zoomed: snap.zoomed,
            focused: snap.focused,
            root_pane: snap.root_pane,
        };

        Self {
            id: None,
            custom_name: snap.custom_name,
            identity_cwd,
            worktree_space: None,
            public_pane_numbers: HashMap::new(),
            next_public_pane_number: 0,
            public_tab_numbers: Vec::new(),
            next_public_tab_number: 0,
            tabs: vec![tab],
            active_tab: 0,
        }
    }
}

#[derive(Deserialize)]
struct RawSessionSnapshot {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    workspaces: Vec<serde_json::Value>,
    #[serde(default)]
    active: Option<usize>,
    #[serde(default)]
    selected: usize,
    #[serde(default)]
    sidebar_width: Option<u16>,
    #[serde(default)]
    sidebar_section_split: Option<f32>,
    #[serde(default)]
    collapsed_space_keys: std::collections::HashSet<String>,
    #[serde(default)]
    archived_agents: Vec<ArchivedAgentSnapshot>,
}

fn migrate_snapshot(raw: RawSessionSnapshot) -> Result<SessionSnapshot, String> {
    Ok(SessionSnapshot {
        version: raw.version,
        workspaces: raw
            .workspaces
            .into_iter()
            .map(migrate_workspace)
            .collect::<Result<Vec<_>, _>>()?,
        active: raw.active,
        selected: raw.selected,
        sidebar_width: raw.sidebar_width,
        sidebar_section_split: raw.sidebar_section_split,
        collapsed_space_keys: raw.collapsed_space_keys,
        archived_agents: raw.archived_agents,
    })
}

fn migrate_workspace(raw: serde_json::Value) -> Result<WorkspaceSnapshot, String> {
    if raw.get("identity_cwd").is_some() {
        return serde_json::from_value(raw).map_err(|e| e.to_string());
    }

    if raw.get("layout").is_some() {
        let legacy =
            serde_json::from_value::<LegacyWorkspaceSnapshot>(raw).map_err(|e| e.to_string())?;
        return Ok(legacy.into());
    }

    Err("workspace snapshot is neither current nor legacy format".to_string())
}

fn legacy_identity_cwd(snap: &LegacyWorkspaceSnapshot) -> PathBuf {
    let root_pane = snap
        .root_pane
        .or_else(|| first_pane_id_in_layout(&snap.layout));

    root_pane
        .and_then(|pane_id| snap.panes.get(&pane_id))
        .map(|pane| pane.cwd.clone())
        .or_else(|| {
            first_pane_id_in_layout(&snap.layout)
                .and_then(|pane_id| snap.panes.get(&pane_id))
                .map(|pane| pane.cwd.clone())
        })
        .or_else(|| {
            snap.panes
                .keys()
                .min()
                .and_then(|pane_id| snap.panes.get(pane_id))
                .map(|pane| pane.cwd.clone())
        })
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| "/".into()))
}

fn first_pane_id_in_layout(layout: &LayoutSnapshot) -> Option<u32> {
    match layout {
        LayoutSnapshot::Pane(id) => Some(*id),
        LayoutSnapshot::Split { first, second, .. } => {
            first_pane_id_in_layout(first).or_else(|| first_pane_id_in_layout(second))
        }
    }
}

/// Capture the current app state into a serializable snapshot.
pub fn capture(
    workspaces: &[Workspace],
    terminals: &std::collections::HashMap<
        crate::terminal::TerminalId,
        crate::terminal::TerminalState,
    >,
    terminal_runtimes: &TerminalRuntimeRegistry,
    active: Option<usize>,
    selected: usize,
    sidebar_width: u16,
    sidebar_section_split: f32,
    collapsed_space_keys: std::collections::HashSet<String>,
    archived_agents: &[ArchivedAgentSnapshot],
) -> SessionSnapshot {
    SessionSnapshot {
        version: SNAPSHOT_VERSION,
        workspaces: workspaces
            .iter()
            .map(|workspace| capture_workspace(workspace, terminals, terminal_runtimes))
            .collect(),
        active,
        selected,
        sidebar_width: Some(sidebar_width),
        sidebar_section_split: Some(sidebar_section_split),
        collapsed_space_keys,
        archived_agents: archived_agents.to_vec(),
    }
}

fn capture_workspace(
    ws: &Workspace,
    terminals: &std::collections::HashMap<
        crate::terminal::TerminalId,
        crate::terminal::TerminalState,
    >,
    terminal_runtimes: &TerminalRuntimeRegistry,
) -> WorkspaceSnapshot {
    WorkspaceSnapshot {
        id: Some(ws.id.clone()),
        custom_name: ws.custom_name.clone(),
        identity_cwd: ws
            .resolved_identity_cwd_from(terminals, terminal_runtimes)
            .unwrap_or_else(|| ws.identity_cwd.clone()),
        worktree_space: ws.worktree_space.clone(),
        public_pane_numbers: ws
            .public_pane_numbers
            .iter()
            .map(|(pane_id, number)| (pane_id.raw(), *number))
            .collect(),
        next_public_pane_number: ws.next_public_pane_number,
        public_tab_numbers: ws.tabs.iter().map(|tab| tab.number).collect(),
        next_public_tab_number: ws.next_public_tab_number,
        tabs: ws
            .tabs
            .iter()
            .map(|tab| capture_tab(tab, terminals, terminal_runtimes))
            .collect(),
        active_tab: ws.active_tab,
    }
}

fn capture_tab(
    tab: &crate::workspace::Tab,
    terminals: &std::collections::HashMap<
        crate::terminal::TerminalId,
        crate::terminal::TerminalState,
    >,
    terminal_runtimes: &TerminalRuntimeRegistry,
) -> TabSnapshot {
    let mut panes = HashMap::new();
    for id in tab.panes.keys() {
        let cwd = tab
            .cwd_for_pane(*id, terminals, terminal_runtimes)
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| "/".into()));
        let terminal = tab
            .panes
            .get(id)
            .and_then(|pane| terminals.get(&pane.attached_terminal_id));
        let label = terminal.and_then(|terminal| terminal.manual_label.clone());
        let (mut agent_name, mut managed_agent_kind) = terminal
            .filter(|terminal| !terminal.managed_agent_launch_pending())
            .map(|terminal| {
                (
                    terminal.agent_name.clone(),
                    terminal
                        .managed_agent_kind()
                        .map(|agent| crate::detect::agent_label(agent).to_string()),
                )
            })
            .unwrap_or_default();
        let guarded_transfer = terminal
            .and_then(|terminal| terminal.session_transfer.as_ref())
            .filter(|transfer| transfer.restart_owns_source());
        if let Some(transfer) = guarded_transfer {
            agent_name = terminal.and_then(|terminal| terminal.agent_name.clone());
            managed_agent_kind = Some(transfer.source_kind.label().to_string());
        }
        let launch_argv = terminal.and_then(|terminal| terminal.launch_argv.clone());
        // Capture the account BEFORE the terminal is gone; without it a restore silently
        // re-homes the pane onto the harness default.
        let agent_account = guarded_transfer
            .map(|transfer| transfer.source_account.clone())
            .unwrap_or_else(|| terminal.and_then(|terminal| terminal.agent_account.clone()));
        let agent_session = guarded_transfer
            .map(|transfer| PaneAgentSessionSnapshot {
                source: transfer.source_session.source.clone(),
                agent: transfer.source_session.agent.clone(),
                kind: transfer.source_session.session_ref.kind,
                value: transfer.source_session.session_ref.value.clone(),
            })
            .or_else(|| {
                terminal.and_then(|terminal| {
                    if let Some(authority) = terminal.hook_authority.as_ref() {
                        if let Some(session_ref) = authority.session_ref.as_ref() {
                            return Some(PaneAgentSessionSnapshot {
                                source: authority.source.clone(),
                                agent: authority.agent_label.clone(),
                                kind: session_ref.kind,
                                value: session_ref.value.clone(),
                            });
                        }
                    }
                    terminal.persisted_agent_session.as_ref().map(|session| {
                        PaneAgentSessionSnapshot {
                            source: session.source.clone(),
                            agent: session.agent.clone(),
                            kind: session.session_ref.kind,
                            value: session.session_ref.value.clone(),
                        }
                    })
                })
            });
        panes.insert(
            id.raw(),
            PaneSnapshot {
                cwd,
                label,
                agent_name,
                managed_agent_kind,
                agent_session,
                launch_argv,
                terminal_id: terminal.map(|terminal| terminal.id.to_string()),
                occupant_generation: terminal
                    .map(|terminal| terminal.occupant_generation)
                    .unwrap_or(0),
                agent_account,
            },
        );
    }
    TabSnapshot {
        custom_name: tab.custom_name.clone(),
        layout: capture_node(tab.layout.root()),
        panes,
        zoomed: tab.zoomed,
        focused: Some(tab.layout.focused().raw()),
        root_pane: Some(tab.root_pane.raw()),
    }
}

/// Capture pane screen history separately from the structural session snapshot.
pub fn capture_history(
    workspaces: &[Workspace],
    terminal_runtimes: &TerminalRuntimeRegistry,
) -> SessionHistorySnapshot {
    SessionHistorySnapshot {
        version: SNAPSHOT_VERSION,
        workspaces: workspaces
            .iter()
            .map(|workspace| WorkspaceHistorySnapshot {
                tabs: workspace
                    .tabs
                    .iter()
                    .map(|tab| TabHistorySnapshot {
                        panes: capture_tab_history(tab, terminal_runtimes),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn capture_tab_history(
    tab: &crate::workspace::Tab,
    terminal_runtimes: &TerminalRuntimeRegistry,
) -> HashMap<u32, PaneHistorySnapshot> {
    let mut panes = HashMap::new();
    for (id, pane) in &tab.panes {
        if let Some(history) = capture_pane_history(Some(pane), terminal_runtimes) {
            panes.insert(id.raw(), history);
        }
    }
    panes
}

fn capture_pane_history(
    pane: Option<&crate::pane::PaneState>,
    terminal_runtimes: &TerminalRuntimeRegistry,
) -> Option<PaneHistorySnapshot> {
    let ansi = terminal_runtimes
        .get(&pane?.attached_terminal_id)?
        .snapshot_history()?;
    let lines = ansi.lines().count();
    Some(PaneHistorySnapshot { ansi, lines })
}

pub(super) fn capture_node(node: &Node) -> LayoutSnapshot {
    match node {
        Node::Pane(id) => LayoutSnapshot::Pane(id.raw()),
        Node::Split {
            direction,
            ratio,
            first,
            second,
        } => LayoutSnapshot::Split {
            direction: match direction {
                Direction::Horizontal => DirectionSnapshot::Horizontal,
                Direction::Vertical => DirectionSnapshot::Vertical,
            },
            ratio: *ratio,
            first: Box::new(capture_node(first)),
            second: Box::new(capture_node(second)),
        },
    }
}

pub(super) fn parse_snapshot(content: &str) -> Result<SessionSnapshot, String> {
    let raw = serde_json::from_str::<RawSessionSnapshot>(content).map_err(|e| e.to_string())?;
    if raw.version > SNAPSHOT_VERSION {
        return Err(format!(
            "snapshot version {} is newer than supported {}",
            raw.version, SNAPSHOT_VERSION
        ));
    }
    migrate_snapshot(raw)
}

pub(super) fn parse_history_snapshot(content: &str) -> Result<SessionHistorySnapshot, String> {
    let snapshot =
        serde_json::from_str::<SessionHistorySnapshot>(content).map_err(|e| e.to_string())?;
    if snapshot.version > SNAPSHOT_VERSION {
        return Err(format!(
            "history snapshot version {} is newer than supported {}",
            snapshot.version, SNAPSHOT_VERSION
        ));
    }
    Ok(snapshot)
}

pub(super) fn snapshot_file_version(content: &str) -> Option<u32> {
    serde_json::from_str::<RawSessionSnapshot>(content)
        .ok()
        .map(|raw| raw.version)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use ratatui::layout::{Direction, Rect};

    use super::*;
    use crate::app::{AppState, Mode};
    use crate::layout::NavDirection;
    use crate::workspace::Workspace;

    fn session_fixture(name: &str) -> &'static str {
        match name {
            "current-herdr" => {
                include_str!("../../tests/fixtures/session/current-herdr-session.json")
            }
            "current-herdr-dev" => {
                include_str!("../../tests/fixtures/session/current-herdr-dev-session.json")
            }
            "legacy-pre-tabs-v2" => {
                include_str!("../../tests/fixtures/session/legacy-pre-tabs-v2.json")
            }
            other => panic!("unknown session fixture: {other}"),
        }
    }

    fn test_session_path(name: &str) -> String {
        std::env::current_dir()
            .unwrap()
            .join(name)
            .display()
            .to_string()
    }

    fn state_with_workspaces(names: &[&str]) -> AppState {
        let mut state = AppState::test_new();
        state.workspaces = names.iter().map(|name| Workspace::test_new(name)).collect();
        state.ensure_test_terminals();
        if !state.workspaces.is_empty() {
            state.active = Some(0);
            state.selected = 0;
            state.mode = Mode::Terminal;
        }
        state
    }

    fn capture_from_state(state: &AppState) -> SessionSnapshot {
        let terminal_runtimes = TerminalRuntimeRegistry::new();
        capture_from_state_with_runtimes(state, &terminal_runtimes)
    }

    fn capture_from_state_with_runtimes(
        state: &AppState,
        terminal_runtimes: &TerminalRuntimeRegistry,
    ) -> SessionSnapshot {
        capture(
            &state.workspaces,
            &state.terminals,
            terminal_runtimes,
            state.active,
            state.selected,
            state.sidebar_width,
            state.sidebar_section_split,
            state.collapsed_space_keys.clone(),
            &state.archived_agents,
        )
    }

    fn capture_history_from_state_with_runtimes(
        state: &AppState,
        terminal_runtimes: &TerminalRuntimeRegistry,
    ) -> SessionHistorySnapshot {
        capture_history(&state.workspaces, terminal_runtimes)
    }

    fn root_split_ratio(tab: &TabSnapshot) -> Option<f32> {
        match &tab.layout {
            LayoutSnapshot::Split { ratio, .. } => Some(*ratio),
            LayoutSnapshot::Pane(_) => None,
        }
    }

    #[test]
    fn managed_agent_snapshot_omits_pending_and_persists_active_ownership() {
        let mut state = state_with_workspaces(&["managed-snapshot"]);
        let root = state.workspaces[0].tabs[0].root_pane;
        let terminal_id = state.workspaces[0].tabs[0].panes[&root]
            .attached_terminal_id
            .clone();
        let now = std::time::Instant::now();
        state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .begin_managed_agent(
                "reviewer".into(),
                crate::detect::Agent::Pi,
                now,
                std::time::Duration::ZERO,
                std::time::Duration::from_secs(1),
            );

        let pending = capture_from_state(&state);
        let pending_pane = &pending.workspaces[0].tabs[0].panes[&root.raw()];
        assert_eq!(pending_pane.agent_name, None);
        assert_eq!(pending_pane.managed_agent_kind, None);

        let terminal = state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_detected_state(
            Some(crate::detect::Agent::Pi),
            crate::detect::AgentState::Idle,
        );
        assert!(terminal.reconcile_managed_agent_at(now, false));
        let active = capture_from_state(&state);
        let active_pane = &active.workspaces[0].tabs[0].panes[&root.raw()];
        assert_eq!(active_pane.agent_name.as_deref(), Some("reviewer"));
        assert_eq!(active_pane.managed_agent_kind.as_deref(), Some("pi"));
    }

    #[test]
    fn round_trip_empty_session() {
        let snap = SessionSnapshot {
            version: SNAPSHOT_VERSION,
            workspaces: vec![],
            active: None,
            selected: 0,
            sidebar_width: Some(26),
            sidebar_section_split: Some(0.5),
            collapsed_space_keys: std::collections::HashSet::new(),
            archived_agents: Vec::new(),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let restored = parse_snapshot(&json).unwrap();
        assert!(restored.workspaces.is_empty());
        assert_eq!(restored.active, None);
        assert_eq!(restored.sidebar_width, Some(26));
        assert_eq!(restored.sidebar_section_split, Some(0.5));
    }

    #[test]
    fn v3_snapshot_without_archived_agents_still_parses() {
        // A pre-#173 (v3) session.json has no `archived_agents` key. Serde default
        // must fill it with an empty list so an old session still loads.
        let v3 = serde_json::json!({
            "version": 3,
            "workspaces": [],
            "active": null,
            "selected": 0,
            "sidebar_width": 26,
            "sidebar_section_split": 0.5,
            "collapsed_space_keys": [],
        })
        .to_string();
        let restored = parse_snapshot(&v3).expect("v3 snapshot parses");
        assert_eq!(restored.version, 3);
        assert!(restored.archived_agents.is_empty());
    }

    /// An archived record written BEFORE the origin fields existed must still load,
    /// with the origin simply absent — that record then restores into a new workspace,
    /// exactly as it did before.
    ///
    /// Built from raw JSON rather than the struct, because the struct cannot express
    /// "these keys were never written": constructing it with `None` would test the
    /// defaults, not the parser.
    #[test]
    fn archived_record_without_origin_fields_still_parses() {
        let raw = serde_json::json!({
            "name": "reviewer",
            "kind": "claude",
            "terminal_id": "term-1",
            "agent_session": {
                "source": "herdr:claude",
                "agent": "claude",
                "kind": "id",
                "value": "sess-123"
            },
            "cwd": "/work",
            "occupant_generation": 7,
            "archived": { "at": "2026-08-26T00:00:00Z", "by": "tester" }
        });
        let record: ArchivedAgentSnapshot =
            serde_json::from_value(raw).expect("an old archived record must still load");
        assert_eq!(record.name.as_deref(), Some("reviewer"));
        assert!(record.origin_workspace_id.is_none());
        assert!(record.origin_tab_id.is_none());
        assert!(record.pane_label.is_none());
    }

    /// Account routing is CAPTURED FROM LIVE STATE and survives the round trip.
    ///
    /// It previously was not persisted at all, so every restore re-homed every pane onto
    /// the harness default. A fleet switched to a secondary account came back on the
    /// primary and appended to the PRIMARY transcript — which looked exactly like hours of
    /// work disappearing, while the records sat intact in the other account's file.
    ///
    /// This drives the real `capture` path rather than building a `PaneSnapshot` literal:
    /// a literal-based test passes even when the capture drops the field, which makes it a
    /// test of serde and not of the behaviour.
    #[test]
    fn pane_account_routing_is_captured_and_round_trips() {
        let mut state = AppState::test_new();
        state.workspaces = vec![Workspace::test_new("agent")];
        state.ensure_test_terminals();
        let pane_id = state.workspaces[0].tabs[0].root_pane;
        let terminal_id = state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        state
            .terminals
            .get_mut(&terminal_id)
            .expect("terminal")
            .agent_account = Some("claudecrazy".to_string());

        let snapshot = capture_from_state(&state);
        let pane = snapshot.workspaces[0].tabs[0]
            .panes
            .get(&pane_id.raw())
            .expect("pane captured");
        assert_eq!(
            pane.agent_account.as_deref(),
            Some("claudecrazy"),
            "the pane's account must be captured, or a restore silently re-homes it"
        );

        // And it survives the wire, carrying an ID and nothing credential-shaped.
        let json = serde_json::to_string(&snapshot).expect("serialize");
        assert!(json.contains("claudecrazy"));
        assert!(
            !json.to_lowercase().contains("oauth_token"),
            "the snapshot must never carry credential material"
        );
        let back: SessionSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            back.workspaces[0].tabs[0].panes[&pane_id.raw()]
                .agent_account
                .as_deref(),
            Some("claudecrazy")
        );
    }

    /// A pane written before routing was persisted must still load, with no account — which
    /// restores to the default, i.e. exactly the old behaviour.
    #[test]
    fn a_pane_without_account_routing_still_parses() {
        let raw = serde_json::json!({
            "cwd": "/work",
            "label": "reviewer",
            "terminal_id": "term-1",
            "occupant_generation": 0
        });
        let pane: PaneSnapshot =
            serde_json::from_value(raw).expect("an old pane record must still load");
        assert!(pane.agent_account.is_none());
        assert_eq!(pane.label.as_deref(), Some("reviewer"));
    }

    #[test]
    fn archived_agents_round_trip_through_the_snapshot() {
        let snap = SessionSnapshot {
            version: SNAPSHOT_VERSION,
            workspaces: vec![],
            active: None,
            selected: 0,
            sidebar_width: Some(26),
            sidebar_section_split: Some(0.5),
            collapsed_space_keys: std::collections::HashSet::new(),
            archived_agents: vec![ArchivedAgentSnapshot {
                name: Some("reviewer".into()),
                kind: "claude".into(),
                terminal_id: "term-1".into(),
                agent_session: PaneAgentSessionSnapshot {
                    source: "herdr:claude".into(),
                    agent: "claude".into(),
                    kind: crate::agent_resume::AgentSessionRefKind::Id,
                    value: "sess-123".into(),
                },
                cwd: PathBuf::from("/work"),
                occupant_generation: 7,
                archived: ArchivedAgentMeta {
                    at: "2026-08-26T00:00:00Z".into(),
                    by: "tester".into(),
                    reason: Some("parked".into()),
                },
                parked_work: vec![serde_json::json!({"pr": 42})],
                origin_workspace_id: Some("w1".into()),
                origin_tab_id: Some("w1:t2".into()),
                pane_label: Some("reviewer".into()),
            }],
        };
        let json = serde_json::to_string(&snap).unwrap();
        let restored = parse_snapshot(&json).unwrap();
        assert_eq!(restored.archived_agents.len(), 1);
        let record = &restored.archived_agents[0];
        assert_eq!(record.terminal_id, "term-1");
        assert_eq!(record.occupant_generation, 7);
        assert_eq!(record.agent_session.value, "sess-123");
        assert_eq!(record.archived.by, "tester");
        assert_eq!(record.parked_work, vec![serde_json::json!({"pr": 42})]);
    }

    #[test]
    fn round_trip_layout_snapshot() {
        let layout = LayoutSnapshot::Split {
            direction: DirectionSnapshot::Horizontal,
            ratio: 0.6,
            first: Box::new(LayoutSnapshot::Pane(0)),
            second: Box::new(LayoutSnapshot::Split {
                direction: DirectionSnapshot::Vertical,
                ratio: 0.5,
                first: Box::new(LayoutSnapshot::Pane(1)),
                second: Box::new(LayoutSnapshot::Pane(2)),
            }),
        };
        let json = serde_json::to_string(&layout).unwrap();
        let restored: LayoutSnapshot = serde_json::from_str(&json).unwrap();

        match restored {
            LayoutSnapshot::Split { ratio, .. } => assert!((ratio - 0.6).abs() < 0.01),
            _ => panic!("expected split"),
        }
    }

    #[test]
    fn round_trip_full_workspace_snapshot() {
        let mut panes = HashMap::new();
        panes.insert(
            0,
            PaneSnapshot {
                cwd: PathBuf::from("/home/can/Projects/herdr"),
                label: None,
                agent_name: None,
                managed_agent_kind: None,
                agent_session: None,
                launch_argv: None,
                terminal_id: None,
                occupant_generation: 0,
                agent_account: None,
            },
        );
        panes.insert(
            1,
            PaneSnapshot {
                cwd: PathBuf::from("/home/can/Projects/website"),
                label: Some("website".into()),
                agent_name: None,
                managed_agent_kind: None,
                agent_session: None,
                launch_argv: None,
                terminal_id: None,
                occupant_generation: 0,
                agent_account: None,
            },
        );

        let snap = SessionSnapshot {
            workspaces: vec![WorkspaceSnapshot {
                id: Some("wproj".to_string()),
                custom_name: Some("pi-mono".to_string()),
                identity_cwd: PathBuf::from("/home/can/Projects/herdr"),
                worktree_space: None,
                public_pane_numbers: HashMap::from([(0, 1), (1, 2)]),
                next_public_pane_number: 3,
                public_tab_numbers: vec![1],
                next_public_tab_number: 2,
                tabs: vec![TabSnapshot {
                    custom_name: Some("api".to_string()),
                    layout: LayoutSnapshot::Split {
                        direction: DirectionSnapshot::Horizontal,
                        ratio: 0.5,
                        first: Box::new(LayoutSnapshot::Pane(0)),
                        second: Box::new(LayoutSnapshot::Pane(1)),
                    },
                    panes,
                    zoomed: false,
                    focused: Some(0),
                    root_pane: Some(0),
                }],
                active_tab: 0,
            }],
            active: Some(0),
            selected: 0,
            sidebar_width: Some(26),
            sidebar_section_split: Some(0.5),
            collapsed_space_keys: std::collections::HashSet::new(),
            archived_agents: Vec::new(),
            version: SNAPSHOT_VERSION,
        };

        let json = serde_json::to_string_pretty(&snap).unwrap();
        let restored = parse_snapshot(&json).unwrap();

        assert_eq!(restored.workspaces.len(), 1);
        assert_eq!(restored.workspaces[0].id.as_deref(), Some("wproj"));
        assert_eq!(
            restored.workspaces[0].custom_name.as_deref(),
            Some("pi-mono")
        );
        assert_eq!(restored.workspaces[0].tabs.len(), 1);
        assert_eq!(restored.workspaces[0].tabs[0].panes.len(), 2);
        assert_eq!(
            restored.workspaces[0].tabs[0].panes[&0].cwd,
            PathBuf::from("/home/can/Projects/herdr")
        );
        assert_eq!(
            restored.workspaces[0].tabs[0].panes[&1].label.as_deref(),
            Some("website")
        );
        assert_eq!(restored.sidebar_width, Some(26));
        assert_eq!(restored.sidebar_section_split, Some(0.5));
    }

    #[test]
    fn current_session_fixture_parses() {
        let snap = parse_snapshot(session_fixture("current-herdr")).unwrap();

        assert_eq!(snap.version, 3);
        assert_eq!(snap.workspaces.len(), 2);
        assert_eq!(snap.active, Some(0));
        assert_eq!(snap.selected, 0);
        assert_eq!(snap.sidebar_width, None);
        assert_eq!(snap.sidebar_section_split, None);
        assert_eq!(snap.workspaces[0].tabs.len(), 2);
        assert_eq!(
            snap.workspaces[1].identity_cwd,
            PathBuf::from("/home/test/projects/project-b")
        );
    }

    #[test]
    fn current_dev_session_fixture_parses_additive_fields() {
        let snap = parse_snapshot(session_fixture("current-herdr-dev")).unwrap();

        assert_eq!(snap.version, 3);
        assert_eq!(snap.workspaces.len(), 2);
        assert_eq!(snap.sidebar_section_split, Some(0.4));
        assert_eq!(snap.workspaces[0].active_tab, 1);
        assert_eq!(snap.workspaces[1].tabs[0].panes.len(), 2);
    }

    #[test]
    fn old_snapshot_defaults_sidebar_fields() {
        let json = serde_json::json!({
            "version": SNAPSHOT_VERSION,
            "workspaces": [],
            "active": null,
            "selected": 0
        })
        .to_string();

        let restored = parse_snapshot(&json).unwrap();

        assert_eq!(restored.sidebar_width, None);
        assert_eq!(restored.sidebar_section_split, None);
    }

    #[test]
    fn old_pane_snapshot_with_embedded_history_is_ignored() {
        let json = serde_json::json!({
            "version": SNAPSHOT_VERSION,
            "workspaces": [{
                "id": "wtest",
                "identity_cwd": "/tmp",
                "tabs": [{
                    "layout": { "Pane": 0 },
                    "panes": {
                        "0": {
                            "cwd": "/tmp",
                            "history": {
                                "ansi": "legacy-secret",
                                "lines": 1
                            }
                        }
                    },
                    "zoomed": false,
                    "focused": 0,
                    "root_pane": 0
                }],
                "active_tab": 0
            }],
            "active": 0,
            "selected": 0
        })
        .to_string();

        let restored = parse_snapshot(&json).unwrap();

        let encoded = serde_json::to_string(&restored).unwrap();
        assert!(!encoded.contains("legacy-secret"));
        assert!(!encoded.contains("\"history\""));
    }

    #[test]
    fn legacy_workspace_snapshot_migrates_to_single_tab() {
        let snap = parse_snapshot(session_fixture("legacy-pre-tabs-v2")).unwrap();
        let ws = &snap.workspaces[0];

        assert_eq!(snap.version, 2);
        assert_eq!(snap.workspaces.len(), 1);
        assert_eq!(ws.custom_name.as_deref(), Some("legacy"));
        assert_eq!(ws.identity_cwd, PathBuf::from("/tmp/pion"));
        assert_eq!(ws.active_tab, 0);
        assert_eq!(ws.tabs.len(), 1);
        assert_eq!(ws.tabs[0].focused, Some(1));
        assert_eq!(ws.tabs[0].root_pane, Some(0));
        assert_eq!(ws.tabs[0].panes[&0].cwd, PathBuf::from("/tmp/pion"));
        assert_eq!(ws.tabs[0].panes[&1].cwd, PathBuf::from("/tmp/herdr"));
    }

    #[test]
    fn capture_contract_tracks_workspace_order_active_and_selected() {
        let mut state = state_with_workspaces(&["a", "b", "c"]);
        state.active = Some(1);
        state.selected = 2;

        state.move_workspace(1, 0);

        let snapshot = capture_from_state(&state);
        let ids: Vec<_> = state.workspaces.iter().map(|ws| ws.id.clone()).collect();
        let captured_ids: Vec<_> = snapshot
            .workspaces
            .iter()
            .map(|ws| ws.id.clone().unwrap())
            .collect();
        assert_eq!(captured_ids, ids);
        assert_eq!(snapshot.active, state.active);
        assert_eq!(snapshot.selected, state.selected);
    }

    #[test]
    fn capture_contract_tracks_workspace_and_tab_names_and_active_tab() {
        let mut state = state_with_workspaces(&["one"]);
        state.workspaces[0].set_custom_name("renamed-workspace".into());
        let second_tab = state.workspaces[0].test_add_tab(Some("logs"));
        state.workspaces[0].switch_tab(second_tab);
        state.workspaces[0].tabs[0].set_custom_name("main".into());

        let snapshot = capture_from_state(&state);
        let workspace = &snapshot.workspaces[0];
        assert_eq!(workspace.custom_name.as_deref(), Some("renamed-workspace"));
        assert_eq!(workspace.active_tab, second_tab);
        assert_eq!(workspace.tabs[0].custom_name.as_deref(), Some("main"));
        assert_eq!(workspace.tabs[1].custom_name.as_deref(), Some("logs"));
    }

    #[test]
    fn capture_contract_tracks_workspace_closure() {
        let mut state = state_with_workspaces(&["one", "two"]);
        state.selected = 1;
        state.active = Some(1);

        state.close_selected_workspace();

        let snapshot = capture_from_state(&state);
        assert_eq!(snapshot.workspaces.len(), 1);
        assert_eq!(snapshot.workspaces[0].custom_name.as_deref(), Some("one"));
        assert_eq!(snapshot.active, Some(0));
        assert_eq!(snapshot.selected, 0);
    }

    #[test]
    fn capture_contract_tracks_sidebar_state() {
        let mut state = state_with_workspaces(&["one"]);
        state.sidebar_width = 31;
        state.sidebar_section_split = 0.4;
        state.collapsed_space_keys.insert("repo-key".into());

        let snapshot = capture_from_state(&state);
        assert_eq!(snapshot.sidebar_width, Some(31));
        assert_eq!(snapshot.sidebar_section_split, Some(0.4));
        assert!(snapshot.collapsed_space_keys.contains("repo-key"));
    }

    #[test]
    fn capture_contract_tracks_worktree_space_membership() {
        let mut state = state_with_workspaces(&["main"]);
        state.workspaces[0].worktree_space = Some(crate::workspace::WorktreeSpaceMembership {
            key: "repo-key".into(),
            label: "herdr".into(),
            repo_root: PathBuf::from("/repo/herdr"),
            checkout_path: PathBuf::from("/repo/herdr/worktree-a"),
            is_linked_worktree: true,
        });

        let snapshot = capture_from_state(&state);

        assert_eq!(
            snapshot.workspaces[0].worktree_space,
            state.workspaces[0].worktree_space
        );
    }

    #[test]
    fn capture_contract_tracks_layout_focus_zoom_and_root_pane() {
        let mut state = state_with_workspaces(&["one"]);
        let root = state.workspaces[0].tabs[0].root_pane;
        let second = state.workspaces[0].test_split(Direction::Horizontal);
        state.workspaces[0].tabs[0].layout.focus_pane(second);
        state.toggle_zoom();

        let snapshot = capture_from_state(&state);
        let tab = &snapshot.workspaces[0].tabs[0];
        assert!(matches!(tab.layout, LayoutSnapshot::Split { .. }));
        assert_eq!(tab.focused, Some(second.raw()));
        assert_eq!(tab.root_pane, Some(root.raw()));
        assert!(tab.zoomed);
        assert_eq!(tab.panes.len(), 2);
    }

    #[test]
    fn capture_contract_tracks_focus_navigation() {
        let mut state = state_with_workspaces(&["one"]);
        let root = state.workspaces[0].tabs[0].root_pane;
        let second = state.workspaces[0].test_split(Direction::Horizontal);
        crate::ui::compute_view(&mut state, Rect::new(0, 0, 106, 20));

        state.navigate_pane(NavDirection::Right);

        let snapshot = capture_from_state(&state);
        assert_eq!(snapshot.workspaces[0].tabs[0].focused, Some(second.raw()));
        assert_ne!(snapshot.workspaces[0].tabs[0].focused, Some(root.raw()));
    }

    #[test]
    fn capture_contract_tracks_resize_ratio_changes() {
        let mut state = state_with_workspaces(&["one"]);
        let root = state.workspaces[0].tabs[0].root_pane;
        state.workspaces[0].test_split(Direction::Horizontal);
        state.workspaces[0].layout.focus_pane(root);
        crate::ui::compute_view(&mut state, Rect::new(0, 0, 106, 20));
        let before = capture_from_state(&state);

        state.resize_pane(NavDirection::Right);

        let after = capture_from_state(&state);
        let before_ratio = root_split_ratio(&before.workspaces[0].tabs[0]).unwrap();
        let after_ratio = root_split_ratio(&after.workspaces[0].tabs[0]).unwrap();
        assert_ne!(before_ratio, after_ratio);
    }

    #[test]
    fn capture_contract_tracks_tab_closure() {
        let mut state = state_with_workspaces(&["one"]);
        let second_tab = state.workspaces[0].test_add_tab(Some("logs"));
        state.switch_tab(second_tab);

        state.close_tab();

        let snapshot = capture_from_state(&state);
        let workspace = &snapshot.workspaces[0];
        assert_eq!(workspace.tabs.len(), 1);
        assert_eq!(workspace.active_tab, 0);
        assert!(workspace.tabs[0].custom_name.is_none());
    }

    #[test]
    fn capture_contract_tracks_pane_closure() {
        let mut state = state_with_workspaces(&["one"]);
        state.workspaces[0].test_split(Direction::Horizontal);

        state.close_pane();

        let snapshot = capture_from_state(&state);
        let tab = &snapshot.workspaces[0].tabs[0];
        assert_eq!(tab.panes.len(), 1);
        assert!(matches!(tab.layout, LayoutSnapshot::Pane(_)));
        assert!(!tab.zoomed);
    }

    #[test]
    fn capture_contract_tracks_public_id_counters() {
        let mut state = state_with_workspaces(&["one"]);
        let second = state.workspaces[0].test_split(Direction::Horizontal);
        let third = state.workspaces[0].test_split(Direction::Vertical);
        let second_tab = state.workspaces[0].test_add_tab(None);

        state.workspaces[0].close_pane(second);

        let snapshot = capture_from_state(&state);
        let workspace = &snapshot.workspaces[0];
        assert_eq!(
            workspace.public_pane_numbers,
            HashMap::from([
                (state.workspaces[0].tabs[0].root_pane.raw(), 1),
                (third.raw(), 3),
                (state.workspaces[0].tabs[second_tab].root_pane.raw(), 4),
            ])
        );
        assert_eq!(workspace.next_public_pane_number, 5);
        assert_eq!(workspace.public_tab_numbers, vec![1, 2]);
        assert_eq!(workspace.next_public_tab_number, 3);
    }

    #[test]
    fn capture_contract_tracks_workspace_identity_and_pane_cwds() {
        let mut state = state_with_workspaces(&["one"]);
        let root = state.workspaces[0].tabs[0].root_pane;
        state.workspaces[0].identity_cwd = PathBuf::from("/tmp/pion");
        let second = state.workspaces[0].test_split(Direction::Horizontal);
        state.ensure_test_terminals();
        let root_terminal_id = state.workspaces[0].tabs[0].panes[&root]
            .attached_terminal_id
            .clone();
        state.terminals.get_mut(&root_terminal_id).unwrap().cwd = PathBuf::from("/tmp/pion");
        let second_terminal_id = state.workspaces[0].tabs[0].panes[&second]
            .attached_terminal_id
            .clone();
        state.terminals.get_mut(&second_terminal_id).unwrap().cwd = PathBuf::from("/tmp/herdr");

        let snapshot = capture_from_state(&state);
        let workspace = &snapshot.workspaces[0];
        let tab = &workspace.tabs[0];
        assert_eq!(workspace.identity_cwd, PathBuf::from("/tmp/pion"));
        assert_eq!(tab.panes[&root.raw()].cwd, PathBuf::from("/tmp/pion"));
        assert_eq!(tab.panes[&second.raw()].cwd, PathBuf::from("/tmp/herdr"));
    }

    #[tokio::test]
    async fn capture_contract_tracks_pane_history_from_runtime() {
        let state = state_with_workspaces(&["one"]);
        let root = state.workspaces[0].tabs[0].root_pane;
        let terminal_id = state.workspaces[0].tabs[0].panes[&root]
            .attached_terminal_id
            .clone();
        let mut terminal_runtimes = TerminalRuntimeRegistry::new();
        terminal_runtimes.insert(
            terminal_id,
            crate::terminal::TerminalRuntime::test_with_scrollback_bytes(
                20,
                3,
                4096,
                b"alpha\r\nbeta\r\ngamma\r\n",
            ),
        );

        let snapshot = capture_from_state_with_runtimes(&state, &terminal_runtimes);
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(!encoded.contains("alpha"));
        assert!(!encoded.contains("\"history\""));

        let history_snapshot = capture_history_from_state_with_runtimes(&state, &terminal_runtimes);
        let history = &history_snapshot.workspaces[0].tabs[0].panes[&root.raw()];

        assert!(history.ansi.contains("alpha"));
        assert!(history.ansi.contains("gamma"));
        assert!(history.lines >= 3);
    }

    #[tokio::test]
    async fn capture_contract_tracks_history_for_each_pane() {
        let mut state = state_with_workspaces(&["one"]);
        let first = state.workspaces[0].tabs[0].root_pane;
        let second = state.workspaces[0].test_split(Direction::Horizontal);
        let first_terminal_id = state.workspaces[0].tabs[0].panes[&first]
            .attached_terminal_id
            .clone();
        let second_terminal_id = state.workspaces[0].tabs[0].panes[&second]
            .attached_terminal_id
            .clone();
        let mut terminal_runtimes = TerminalRuntimeRegistry::new();
        terminal_runtimes.insert(
            first_terminal_id,
            crate::terminal::TerminalRuntime::test_with_scrollback_bytes(
                20,
                3,
                4096,
                b"first-pane-history\r\n",
            ),
        );
        terminal_runtimes.insert(
            second_terminal_id,
            crate::terminal::TerminalRuntime::test_with_scrollback_bytes(
                20,
                3,
                4096,
                b"second-pane-history\r\n",
            ),
        );

        let snapshot = capture_from_state_with_runtimes(&state, &terminal_runtimes);
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(!encoded.contains("first-pane-history"));
        assert!(!encoded.contains("second-pane-history"));

        let history_snapshot = capture_history_from_state_with_runtimes(&state, &terminal_runtimes);
        let tab = &history_snapshot.workspaces[0].tabs[0];
        let first_history = &tab.panes[&first.raw()];
        let second_history = &tab.panes[&second.raw()];

        assert!(first_history.ansi.contains("first-pane-history"));
        assert!(second_history.ansi.contains("second-pane-history"));
    }

    #[test]
    fn capture_persists_terminal_id_and_occupant_generation() {
        let mut state = state_with_workspaces(&["one"]);
        let root = state.workspaces[0].tabs[0].root_pane;
        state.ensure_test_terminals();
        let terminal_id = state.workspaces[0].tabs[0].panes[&root]
            .attached_terminal_id
            .clone();
        state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .occupant_generation = 5;

        let snapshot = capture_from_state(&state);
        let pane = &snapshot.workspaces[0].tabs[0].panes[&root.raw()];
        assert_eq!(
            pane.terminal_id.as_deref(),
            Some(terminal_id.to_string().as_str()),
            "captured pane must carry the terminal's persisted id"
        );
        assert_eq!(
            pane.occupant_generation, 5,
            "captured pane must carry the terminal's occupant generation"
        );
    }

    #[test]
    fn capture_defaults_occupant_generation_and_terminal_id_are_additive() {
        // A snapshot written before W6 has neither field; both decode to their
        // additive defaults (terminal_id: None, occupant_generation: 0) without
        // failing the load, and re-serializing omits the absent optional.
        let json = serde_json::json!({
            "version": SNAPSHOT_VERSION,
            "workspaces": [{
                "id": "wtest",
                "identity_cwd": "/tmp",
                "tabs": [{
                    "layout": { "Pane": 0 },
                    "panes": { "0": { "cwd": "/tmp" } },
                    "zoomed": false,
                    "focused": 0,
                    "root_pane": 0
                }],
                "active_tab": 0
            }],
            "active": 0,
            "selected": 0
        })
        .to_string();

        let restored = parse_snapshot(&json).unwrap();
        let pane = &restored.workspaces[0].tabs[0].panes[&0];
        assert_eq!(pane.terminal_id, None);
        assert_eq!(pane.occupant_generation, 0);

        let encoded = serde_json::to_string(&restored).unwrap();
        assert!(!encoded.contains("terminal_id"));
    }

    #[test]
    fn capture_contract_tracks_hook_authority_agent_session() {
        let mut state = state_with_workspaces(&["one"]);
        let session_path = test_session_path("pi-session.jsonl");
        let root = state.workspaces[0].tabs[0].root_pane;
        state.ensure_test_terminals();
        let terminal_id = state.workspaces[0].tabs[0].panes[&root]
            .attached_terminal_id
            .clone();
        let terminal = state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_detected_state(
            Some(crate::detect::Agent::Pi),
            crate::detect::AgentState::Idle,
        );
        terminal.set_persisted_agent_session(crate::agent_resume::PersistedAgentSession {
            source: "herdr:pi".into(),
            agent: "pi".into(),
            session_ref: crate::agent_resume::AgentSessionRef::path(session_path.clone()).unwrap(),
        });
        terminal.set_hook_authority_with_session_ref(
            "herdr:pi".into(),
            "pi".into(),
            crate::detect::AgentState::Working,
            None,
            crate::agent_resume::AgentSessionRef::path(session_path.clone()),
            Some(20),
        );

        let snapshot = capture_from_state(&state);
        let agent_session = snapshot.workspaces[0].tabs[0].panes[&root.raw()]
            .agent_session
            .as_ref()
            .expect("agent session should be captured");

        assert_eq!(agent_session.source, "herdr:pi");
        assert_eq!(agent_session.agent, "pi");
        assert_eq!(
            agent_session.kind,
            crate::agent_resume::AgentSessionRefKind::Path
        );
        assert_eq!(agent_session.value, session_path);
    }

    #[test]
    fn capture_contract_preserves_restored_agent_session() {
        let mut state = state_with_workspaces(&["one"]);
        let root = state.workspaces[0].tabs[0].root_pane;
        state.ensure_test_terminals();
        let terminal_id = state.workspaces[0].tabs[0].panes[&root]
            .attached_terminal_id
            .clone();
        state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .set_persisted_agent_session(crate::agent_resume::PersistedAgentSession {
                source: "herdr:opencode".into(),
                agent: "opencode".into(),
                session_ref: crate::agent_resume::AgentSessionRef::id("opencode-session").unwrap(),
            });

        let snapshot = capture_from_state(&state);
        let agent_session = snapshot.workspaces[0].tabs[0].panes[&root.raw()]
            .agent_session
            .as_ref()
            .expect("persisted agent session should be captured");

        assert_eq!(agent_session.source, "herdr:opencode");
        assert_eq!(agent_session.agent, "opencode");
        assert_eq!(
            agent_session.kind,
            crate::agent_resume::AgentSessionRefKind::Id
        );
        assert_eq!(agent_session.value, "opencode-session");
    }

    #[test]
    fn transfer_snapshot_keeps_source_ownership_until_target_is_verified() {
        let mut state = state_with_workspaces(&["one"]);
        let root = state.workspaces[0].tabs[0].root_pane;
        let terminal_id = state.workspaces[0].tabs[0].panes[&root]
            .attached_terminal_id
            .clone();
        let terminal = state.terminals.get_mut(&terminal_id).unwrap();
        terminal.agent_account = Some("codex-work".into());
        terminal.set_hook_authority_with_session_ref(
            "herdr:codex".into(),
            "codex".into(),
            crate::detect::AgentState::Idle,
            None,
            Some(crate::agent_resume::AgentSessionRef::id("codex-target").unwrap()),
            Some(20),
        );
        terminal.begin_managed_agent(
            "jarvis".into(),
            crate::detect::Agent::Codex,
            std::time::Instant::now(),
            std::time::Duration::from_secs(3),
            std::time::Duration::from_secs(30),
        );
        terminal.session_transfer = Some(crate::session_transfer::RuntimeSessionTransfer {
            id: "transfer-1".into(),
            source_kind: crate::session_transfer::HarnessKind::Claude,
            source_session: crate::agent_resume::PersistedAgentSession {
                source: "herdr:claude".into(),
                agent: "claude".into(),
                session_ref: crate::agent_resume::AgentSessionRef::id("claude-source").unwrap(),
            },
            source_account: Some("claude-work".into()),
            source_config_home: PathBuf::from("/tmp/claude-home"),
            target_kind: crate::session_transfer::HarnessKind::Codex,
            target_account: Some("codex-work".into()),
            target_config_home: PathBuf::from("/tmp/codex-home"),
            phase: crate::api::schema::AgentSessionTransferPhase::AwaitingTarget,
            message_count: 3,
            omissions: Default::default(),
            error: None,
            source_path: None,
            source_fingerprint: None,
            target_session_id: Some("codex-target".into()),
            target_transcript_path: None,
            target_fingerprint: None,
            target_deadline: None,
            target_process: None,
            source_rollback_process: None,
            verification_in_flight: None,
            verification_observation_deadline: None,
            awaiting_deferred_target_report: false,
        });

        let guarded = capture_from_state(&state);
        let pane = &guarded.workspaces[0].tabs[0].panes[&root.raw()];
        let session = pane.agent_session.as_ref().expect("source session");
        assert_eq!(session.source, "herdr:claude");
        assert_eq!(session.agent, "claude");
        assert_eq!(session.value, "claude-source");
        assert_eq!(pane.agent_account.as_deref(), Some("claude-work"));
        assert_eq!(pane.managed_agent_kind.as_deref(), Some("claude"));
        assert_eq!(
            pane.agent_name.as_deref(),
            Some("jarvis"),
            "a guarded transfer snapshot must retain the durable name even while the target launch is pending"
        );

        #[cfg(unix)]
        {
            let (events, _event_rx) = tokio::sync::mpsc::channel(4);
            let (_workspaces, restored_terminals, restored_runtimes) =
                crate::persist::restore::restore(
                    &guarded,
                    None,
                    24,
                    80,
                    0,
                    "/bin/sh",
                    crate::config::ShellModeConfig::NonLogin,
                    true,
                    events,
                    std::sync::Arc::new(tokio::sync::Notify::new()),
                    std::sync::Arc::new(crate::render_signal::RenderSignal::new()),
                );
            assert!(restored_runtimes.is_empty());
            let restored = restored_terminals.values().next().unwrap();
            assert_eq!(restored.agent_name.as_deref(), Some("jarvis"));
            assert_eq!(
                restored.managed_agent_kind(),
                Some(crate::detect::Agent::Claude)
            );
        }

        state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .restore_managed_agent("jarvis".into(), crate::detect::Agent::Codex);

        state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .session_transfer
            .as_mut()
            .unwrap()
            .phase = crate::api::schema::AgentSessionTransferPhase::Completed;
        let completed = capture_from_state(&state);
        let pane = &completed.workspaces[0].tabs[0].panes[&root.raw()];
        let session = pane.agent_session.as_ref().expect("target session");
        assert_eq!(session.source, "herdr:codex");
        assert_eq!(session.agent, "codex");
        assert_eq!(session.value, "codex-target");
        assert_eq!(pane.agent_account.as_deref(), Some("codex-work"));

        state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .session_transfer
            .as_mut()
            .unwrap()
            .awaiting_deferred_target_report = true;
        let deferred = capture_from_state(&state);
        let pane = &deferred.workspaces[0].tabs[0].panes[&root.raw()];
        let session = pane.agent_session.as_ref().expect("source session");
        assert_eq!(session.source, "herdr:claude");
        assert_eq!(session.agent, "claude");
        assert_eq!(session.value, "claude-source");
        assert_eq!(pane.agent_account.as_deref(), Some("claude-work"));
        assert_eq!(pane.agent_name.as_deref(), Some("jarvis"));
    }

    #[test]
    fn old_unversioned_snapshot_loads_as_version_0() {
        let json = r#"{"workspaces":[],"active":null,"selected":0}"#;
        let snap = parse_snapshot(json).unwrap();
        assert_eq!(snap.version, 0);
    }

    #[test]
    fn future_version_is_rejected() {
        let json = r#"{"version":999,"workspaces":[],"active":null,"selected":0}"#;
        assert!(parse_snapshot(json).is_err());
    }

    #[test]
    fn active_tab_default_is_zero() {
        let json = r#"{"custom_name":"test","identity_cwd":"/tmp","tabs":[]}"#;
        let ws: WorkspaceSnapshot = serde_json::from_str(json).unwrap();
        assert_eq!(ws.active_tab, 0);
    }

    #[test]
    fn restore_falls_back_to_home_when_cwd_missing() {
        let mut panes = HashMap::new();
        panes.insert(
            0,
            PaneSnapshot {
                cwd: PathBuf::from("/tmp/this-directory-does-not-exist-for-herdr-test"),
                label: None,
                agent_name: None,
                managed_agent_kind: None,
                agent_session: None,
                launch_argv: None,
                terminal_id: None,
                occupant_generation: 0,
                agent_account: None,
            },
        );
        panes.insert(
            1,
            PaneSnapshot {
                cwd: std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("/tmp")),
                label: None,
                agent_name: None,
                managed_agent_kind: None,
                agent_session: None,
                launch_argv: None,
                terminal_id: None,
                occupant_generation: 0,
                agent_account: None,
            },
        );

        let snap = SessionSnapshot {
            version: SNAPSHOT_VERSION,
            workspaces: vec![WorkspaceSnapshot {
                id: Some("test-ws".to_string()),
                custom_name: Some("fallback test".to_string()),
                identity_cwd: PathBuf::from("/tmp"),
                worktree_space: None,
                public_pane_numbers: HashMap::new(),
                next_public_pane_number: 0,
                public_tab_numbers: Vec::new(),
                next_public_tab_number: 0,
                tabs: vec![TabSnapshot {
                    custom_name: None,
                    layout: LayoutSnapshot::Split {
                        direction: DirectionSnapshot::Horizontal,
                        ratio: 0.5,
                        first: Box::new(LayoutSnapshot::Pane(0)),
                        second: Box::new(LayoutSnapshot::Pane(1)),
                    },
                    panes,
                    zoomed: false,
                    focused: Some(0),
                    root_pane: Some(0),
                }],
                active_tab: 0,
            }],
            active: Some(0),
            selected: 0,
            sidebar_width: Some(26),
            sidebar_section_split: Some(0.5),
            collapsed_space_keys: std::collections::HashSet::new(),
            archived_agents: Vec::new(),
        };

        let json = serde_json::to_string(&snap).unwrap();
        let restored = parse_snapshot(&json).unwrap();
        assert_eq!(restored.workspaces.len(), 1);
        assert_eq!(
            restored.workspaces[0].tabs[0].panes[&0].cwd,
            PathBuf::from("/tmp/this-directory-does-not-exist-for-herdr-test")
        );
    }
}
