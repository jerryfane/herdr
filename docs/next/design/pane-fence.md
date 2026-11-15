# Pane fence: design and threat model

Status: design for review (jerryfane/herdr#417, epic #416). Linux only. Nothing here is implemented yet.

## 1. Summary

When `[fence] enabled = true`, the herdr server starts every pane process inside a **fence**: a private
mount namespace in which a shared deny list of paths is read-only, sockets that run work outside the fence
are masked, a Landlock domain isolates the pane from other processes, and dangerous capabilities are gone
from every capability set including the bounding set. The pane keeps running as root and everything else
stays writable, so ordinary work does not change. Per-agent profiles relax the fence for the few seats that
need more. The server itself stays unfenced and refuses API requests from fenced callers that would act
outside their fence (section 8).

The fence is set up by a small re-exec helper, `herdr fence-exec`, that the server puts in front of the
pane's command. The helper fails closed: if any step fails, the pane shows the error and the command never
starts.

## 2. Threat model

**Fenced:** every process a fenced pane starts, and everything those processes start: agents, shells,
tests, scripts, build tools, test binaries. The kernel enforces the fence on the whole process tree.

**Not fenced:** the herdr server, the owner's own shells and ssh sessions, systemd services, cron, and panes
whose agent profile disables the fence.

**Attacker model:** a well-meaning agent, or a test or script it runs, that executes a destructive command
by mistake. Both incidents of 2026-11-15 are the reference cases:

| Incident | What happened | Fence answer |
|---|---|---|
| Storage Box worktrees | `rm -rf` on a computed path deleted ~213 worktrees of 16 seats under `/mnt/storagebox-workspaces/worktrees` | Storage Box top level read-only; per-seat writable carve-out (section 10) |
| herdr settings | contents of `/root/.config/herdr` deleted, including the live server's sockets | `/root/.config/herdr` read-only in every fenced pane |

A hostile actor is out of scope, but a fence that an agent can step around with one ordinary command is
worthless, so every known way around it (section 7) is either closed or listed as a residual risk with a
reason (section 13).

**Goals**

1. A fenced process cannot write, delete or rename anything under a denied path.
2. It cannot undo the fence: no remount, unmount, namespace switch, capability regain, or access to another
   process's view of the filesystem.
3. It cannot ask something unfenced to do the work instead: systemd, D-Bus, Docker/containerd, cron, the
   herdr API acting on other panes or on config, ssh to the host itself (companion change, section 13).
4. Nothing done inside a pane changes the host mount table or another pane's mounts.
5. With `enabled = false` behavior is exactly today's.

**Non-goals for v1:** confidentiality (fenced panes can still read everything they read today), network
policy, resource limits (disk, memory, fork bombs), macOS and Windows.

## 3. Mechanism

### 3.1 Where it runs: `herdr fence-exec`, not `pre_exec`

Every Unix pane process is created in one place: `PaneRuntime::spawn_command_builder` (`src/pane.rs`) calls
`crate::pty::backend::spawn_with_portable_pty`, which hands a `portable_pty::CommandBuilder` to the
vendored `portable-pty` crate. Its `spawn_command` (`vendor/portable-pty/src/unix.rs`) installs its own
`pre_exec` (reset signals, `setsid`, `TIOCSCTTY`, close inherited fds) and does not expose a hook.

When a pane is fenced, the server rewrites the command it is about to spawn:

```
program: /proc/self/exe            (the running server binary, even if replaced on disk)
args:    fence-exec -- <original program> <original args...>
env:     original env + HERDR_FENCE_PLAN=<resolved plan as JSON>
```

The helper runs as the pane's child after portable-pty's `pre_exec`, applies the plan (section 3.2),
removes `HERDR_FENCE_PLAN` from its environment, prints one line (`herdr: fenced, profile <name>; see
herdr fence explain`), and `execvp`s the original command. Its pid is the pane's child pid, so the
server's child watcher, signals and exit handling are unchanged.

Why a helper instead of setting up the namespace in `pre_exec`:

| | `pre_exec` in the server | `herdr fence-exec` helper |
|---|---|---|
| Safety | Runs after `fork` of a multi-threaded tokio process: only async-signal-safe calls, no allocation, no logging, no path resolution or directory listing (needed for globs, `/dev` scan, existence checks) | An ordinary single-threaded process: normal Rust, normal error handling |
| Code change | Needs a new hook in vendored `portable-pty` (a new local patch to carry) | No change to `portable-pty` |
| Errors | Only an errno through `spawn` failure | Full message on the pane's terminal, distinct exit status, server log line |
| Tests | Only through a running server | `herdr fence-exec -- sh -c ...` runs the exact production code in a throwaway container without a server (section 11) |
| Cost | none | one extra `exec` per pane start (milliseconds) |

The plan is resolved by the server (config + agent profile + path existence) so that `herdr fence
explain` and the helper use the same resolution code. The helper re-checks each path when it mounts it
and treats a path that disappeared in between as "missing" (skip and report), never creates it.

An environment variable is visible to the helper only; it is removed before `exec`. A fenced process that
runs `herdr fence-exec` itself cannot loosen anything: the helper needs `CAP_SYS_ADMIN`, which the fence
has removed.

### 3.2 Setup order inside the helper

Order matters: propagation must be fixed before the first mount, mounts need `CAP_SYS_ADMIN`, a fresh
`/proc` must be mounted by a process inside the new PID namespace, Landlock needs `CAP_SYS_ADMIN` or
`no_new_privs`, and capabilities go last.

1. `unshare(CLONE_NEWNS | CLONE_NEWPID)`, then step 2, then `fork`. The parent stays outside as the
   server's direct child: it forwards `SIGHUP`, `SIGTERM`, `SIGINT` and `SIGQUIT` to the child and exits
   with the child's status. The child is pid 1 of the pane's PID namespace and runs steps 3 to 12 (section
   3.5). With `pid_namespace = false` in the profile, only `CLONE_NEWNS` is unshared and there is no fork.
2. `mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL)` **before any other mount.** Slave, never shared:
   mount events cannot travel from the pane to the host or to other panes (the 2026-11-15 hetzner2 `/tmp`
   tmpfs leak was a mount created in a shared namespace). Slave rather than private so that host mount
   changes still reach the pane in areas no fence mount covers (for example a new mount under `/mnt`).
   Every fence mount itself is made **private** before it is attached (steps 4 to 8), so host mounts
   that appear later below a denied or carved-out path never reach the pane (probes P-59 to P-62; the
   #425 review found the hole). See open question Q2.
3. **Anchors:** for every ancestor directory of a deny or allow path, from the top down and excluding `/`,
   bind the directory onto itself, read-write and recursive. A mount point cannot be renamed or removed
   (`EBUSY`), so `mv /root/.config elsewhere` or `mv /mnt/storagebox-workspaces x` fails instead of moving a
   protected tree out from under the host. Probe P-11 shows the hole without an anchor and P-12 the fix.
4. **Deny:** for each deny path (realpath, shortest first), clone it recursively (`open_tree(...,
   OPEN_TREE_CLONE | AT_RECURSIVE)`), set the whole cloned subtree read-only and private in one call
   (`mount_setattr(..., AT_RECURSIVE, {attr_set = MOUNT_ATTR_RDONLY, propagation = MS_PRIVATE})`) and move
   it onto the path. Recursive matters: a plain `remount,bind,ro` leaves submounts writable (probes P-22,
   P-23); `/sys` has a dozen submounts. Private matters: a slave clone keeps receiving host mounts, and a
   tmpfs the host mounts below the denied path later would be writable in the pane (P-59, P-60).
5. **Allow (carve-outs):** for each allow path below a deny path, clone it, make it private, clear
   `MOUNT_ATTR_RDONLY` on the top mount only (submounts stay as they are), and move it back. The carve-out
   is writable, and because it is a mount point the directory or file itself cannot be deleted or renamed
   (section 5).
6. **Mask:** bind an empty read-only file, private, over each socket in `mask_sockets` that exists.
   `connect()` then fails with `ECONNREFUSED`; nothing is created on the host.
7. **Devices:** bind each block device node in `/dev` and `/dev/mem`, `/dev/kmem`, `/dev/port` onto itself,
   private, with `MOUNT_ATTR_NODEV | MOUNT_ATTR_RDONLY`. A read-only mount does not stop writes to a device
   node; only `nodev` does (`may_open` in `fs/namei.c`). Opens then fail with `EACCES`.
8. **/proc:** `/proc/sys`, `/proc/sysrq-trigger`, `/proc/irq`, `/proc/bus`, `/proc/fs` read-only and private
   (same list as Docker's default). `/sys` is in the default deny list.
9. **Landlock:** create a ruleset that handles `LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_BLOCK
   | LANDLOCK_ACCESS_FS_REFER`, add one rule granting `REFER` beneath `/`, and `landlock_restrict_self`.
   `REFER` must be handled and granted explicitly: Landlock denies cross-directory `rename` and `link` in
   any domain that does not grant it, even when the ruleset never names it (probe P-63; the #425 review
   found it, #427). With the rule those work as before (P-64, P-65). Requires Landlock ABI 2 (Linux 5.19).
   This gives every pane its own Landlock domain, which
   - denies `ptrace` and every `PTRACE_MODE_READ` access (`/proc/<pid>/root`, `/proc/<pid>/mem`,
     `/proc/<pid>/environ`, `pidfd_getfd`, `process_vm_writev`) to any process outside the pane, including
     other fenced panes with the same capabilities (probes P-38, P-39, P-41; controls P-37, P-40).
     Capabilities alone do not cover that case: the kernel lets a process reach another of the same uid
     whose permitted set is a subset of its own, so a default-profile pane could otherwise write through
     `/proc/<installer-pane>/root/etc`;
   - denies creating device nodes anywhere, even if `CAP_MKNOD` came back (P-42 with control P-43; P-66
     with the `REFER` rule in place).
   `CAP_SYS_ADMIN` is still held here, so `no_new_privs` is not needed. When the kernel offers Landlock ABI
   6 or later (Linux 6.12+), the ruleset also sets `LANDLOCK_SCOPE_SIGNAL` (see Q4). Landlock missing,
   disabled or below ABI 2: setup fails closed.
10. **Capabilities:** drop the fence's capability list from the bounding set (`PR_CAPBSET_DROP`), clear the
    ambient set, and `capset` effective, permitted and inheritable to the current sets minus the list. The
    process stays uid 0; it cannot regain a dropped capability through setuid binaries or file capabilities
    because both are capped by the bounding set.
11. **Working directory:** `chdir` to the pane's intended cwd by its absolute path, so the cwd is looked up
    again in the finished mount view. The helper inherited its cwd from before step 4, and that cwd still
    points at the original writable mount: `./file` would write into a denied directory the pane was
    started in (probes P-56 to P-58; the #425 review found it). Restoring a directory fd saved before the
    mounts would keep the hole. If the path no longer resolves, setup fails closed. No other descriptor
    crosses the fence: portable-pty closes everything above stderr before the helper starts.
12. Remove `HERDR_FENCE_PLAN`, set `HERDR_FENCE=<profile>`, print the one-line notice. With a PID
    namespace, pid 1 forks the pane command (which `execvp`s) and stays as its init (section 3.5); without
    one, the helper `execvp`s directly.

Any failure in steps 1 to 11 prints `herdr fence: <step> failed for <path>: <error>; not starting the pane
command (fence enabled, failing closed)` to the pane and exits with status 126 before `exec`. Missing deny,
allow or mask paths are not failures: they are skipped and listed in the start notice and in `herdr fence
explain`.

### 3.3 Capabilities removed by default

| Capability | Why it goes |
|---|---|
| `CAP_SYS_ADMIN` | mount, umount, remount, `setns`, `unshare` of new namespaces in the init user namespace, `pivot_root`, `open_tree`/`move_mount`, most of `bpf`, many device ioctls |
| `CAP_SYS_MODULE` | load or unload kernel modules |
| `CAP_SYS_BOOT` | `reboot`, `kexec_load` |
| `CAP_SYS_RAWIO` | `/dev/mem`, `/dev/port`, `iopl`, raw SCSI ioctls |
| `CAP_SYS_PTRACE` | ptrace and `/proc/<pid>/{root,mem}` of processes with more capabilities |
| `CAP_MKNOD` | creating device nodes (a block device node in `/tmp` would bypass step 7) |
| `CAP_DAC_READ_SEARCH` | `open_by_handle_at`: opens any inode by handle through a writable mount of the same filesystem, bypassing the read-only binds (the "shocker" container escape). Reading is still covered by `CAP_DAC_OVERRIDE` |
| `CAP_BPF`, `CAP_PERFMON` | BPF tracing programs can write into other processes' memory |
| `CAP_SYS_TIME` | changing the host clock |
| `CAP_NET_ADMIN` | the pane shares the host network namespace: flushing firewall rules or taking interfaces down breaks the host |
| `CAP_AUDIT_CONTROL`, `CAP_AUDIT_WRITE`, `CAP_AUDIT_READ` | auditd rules on protected paths (fleetup) must not be switched off from inside |
| `CAP_MAC_ADMIN`, `CAP_MAC_OVERRIDE` | changing or bypassing AppArmor policy |
| `CAP_LINUX_IMMUTABLE` | `chattr -i` on protected files (the Storage Box mount point relies on `+i`) |
| `CAP_SYSLOG` | kernel log control |
| `CAP_WAKE_ALARM`, `CAP_BLOCK_SUSPEND` | power management of the host |

Kept: `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`, `CAP_KILL`, `CAP_SETUID`, `CAP_SETGID`,
`CAP_SETPCAP`, `CAP_SETFCAP`, `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_NET_BROADCAST`, `CAP_IPC_LOCK`,
`CAP_IPC_OWNER`, `CAP_SYS_CHROOT`, `CAP_SYS_NICE`, `CAP_SYS_RESOURCE`, `CAP_SYS_PACCT`, `CAP_SYS_TTY_CONFIG`,
`CAP_LEASE`, `CAP_CHECKPOINT_RESTORE`. These are what root needs for ordinary file and process work.
`CAP_DAC_OVERRIDE` stays because agents write files they do not own; the deny list, not DAC, protects paths.
Profiles may keep a removed capability (`keep_caps`), never add one.

### 3.4 What `no_new_privs` and namespaces are not used for

- **`no_new_privs` is not set.** It would change AppArmor exec transitions and setuid behavior for no gain:
  the bounding set already caps what any exec can gain.
- **No user namespace.** The pane stays uid 0 in the init user namespace so file ownership, git, ssh keys and
  every tool behave as today.
- **A PID namespace is built but off by default** (section 3.5); `pid_namespace` turns it on.
- **No network namespace.** Not a v1 goal.

### 3.5 PID namespace and signal isolation

A fenced root process could otherwise `kill` any root process: `pkill -f herdr` or `killall` in a cleanup
script would take down the server and every agent. Landlock can scope signals per domain only from ABI 6
(Linux 6.12); dev2306 runs 6.8 (ABI 4). So #418 builds a PID namespace per fenced pane (jarvis, gitmoot
message 487780). When a kernel with Landlock ABI 6 is available the fence also sets
`LANDLOCK_SCOPE_SIGNAL`, which keeps signals in even without a PID namespace.

**It ships off** (`[fence] pid_namespace = false`; jarvis, gitmoot message 487804). Agents run the gitmoot
CLI all day, and a namespace pid written as a lock owner, or a host pid judged dead from inside a pane, can
make gitmoot reap a live lock or keep a dead one (table below). The pilot runs in two steps: first the fence
without a PID namespace, then with one, after the gitmoot seat confirms its pid paths are namespace-safe.
Until then signals stay a residual risk (section 13).

- **Mounts:** before the fresh `/proc` is mounted, pid 1 binds the host `/proc` read-only at
  `/run/herdr-host-proc`, so checks that need host processes (`grep -l cargo /run/herdr-host-proc/*/comm`)
  still work. It can read `cmdline`, `status` and the rest but cannot send signals through it
  (`pidfd_send_signal` with a `/proc` directory fd from another namespace gives `EINVAL`, probe P-50).
  The server creates the empty mount-point directory `/run/herdr-host-proc` once at startup; it is the only
  host-side path the fence creates.
- **pid 1 is the helper itself**, not the shell. It reaps orphans, forwards `SIGHUP`/`SIGTERM`/`SIGINT`/
  `SIGQUIT` to the pane command, and exits with the command's status. The kernel does not deliver signals
  without a handler to a namespace's pid 1 from inside the namespace, so `kill -9 -1` inside the pane cannot
  remove it (probe P-48).
- **What the server tracks:** the pane's child pid is the outer helper. Cwd and process reporting
  (`/proc/<pid>/cwd`, `pane.process_info`) must follow the pane command's host pid. That command has a
  fixed identity: it is the first and only process pid 1 forks, so it is pid **2** inside the pane's PID
  namespace for its whole life (the namespace ends when it exits, so pid 2 is never reused). The server
  finds pid 1 as the outer helper's child (`/proc/<outer helper>/task/<tid>/children`) and then, among
  pid 1's children, the one whose `NSpid` line in `/proc/<pid>/status` ends in `2`. Adopted orphans (a
  double-forked daemon) are also children of pid 1 but never pid 2, so they cannot become the pane's
  reporting root (#426 review). No descriptor is passed, because portable-pty closes inherited descriptors
  before the helper runs (#428). The foreground process group read from the PTY master is already
  translated by the kernel into the server's PID namespace.
- **PIDs that cross the boundary:** `pane.report_agent*` carries an `agent_process_pid`, which may name a
  process other than the caller (`--agent-process-pid`). The server compares the caller's PID namespace
  (`/proc/<peer>/ns/pid`) with its own:
  - **Same namespace** (unfenced callers, and fenced panes with `pid_namespace = false`, the default): the
    reported pid is already a server pid and is stored as today.
  - **A pane's PID namespace:** the server translates the reported pid, not the caller's. It looks among
    the descendants of that pane's pid 1 for the process whose `NSpid` line ends in the reported value and
    stores its host pid (the first `NSpid` field).
  - **Not found, or another namespace no pane owns:** the field is dropped with a diagnostic, never stored
    untranslated (#426 review).

Effects on agents (sent to jarvis, gitmoot message 487802; the pilot decides on further changes):

| Effect | Probe | Mitigation |
|---|---|---|
| `ps`, `pgrep`, `top` show only the pane's own processes; a host-wide "is cargo already running" check sees nothing | P-44, P-45 | read `/run/herdr-host-proc` (jarvis: ship it) |
| A host pid read from a file or database (`daemon.pid`, lock-owner pids in `gitmoot.db`) gives `ESRCH`, so "is it alive" checks report dead | P-46 | **blocker for turning it on**: gitmoot `processRunning`, `lockOwnerPIDLive`, `probeRuntimePID` must be namespace-safe first; the gitmoot seat checks (jarvis) |
| Pids a fenced process records (`os.Getpid()` in lock rows) are namespace-local and name other host processes | — | same list |
| Every process in the pane dies when the pane's command exits, including `setsid`/`nohup` background jobs (an agent restart ends them) | P-53, control P-54 | accepted (jarvis 487804): long-running services belong in systemd units; documented in the #421 user docs |

## 4. Config schema

```toml
[fence]
# Kill switch. false = today's behavior exactly. Takes effect on the next pane start.
enabled = false

# Read-only inside every fenced pane. Absolute paths; "~" is the server's HOME; a trailing "*" in the
# last component matches siblings at pane start (e.g. "/var/lib/sandboxd*"). Missing paths are skipped.
deny = ["/usr", "/etc", "~/.config/herdr", "/mnt/storagebox-workspaces"]   # full default list: section 6

# Writable again inside a denied parent. Each entry must lie below a deny entry.
allow = ["/mnt/storagebox-workspaces/worktrees/{agent}"]

# Sockets masked in every fenced pane (connect fails).
mask_sockets = ["/run/systemd/private", "/run/dbus/system_bus_socket", "/run/docker.sock"]

# PID namespace per fenced pane (section 3.5). Off until gitmoot's pid handling is namespace-safe.
pid_namespace = false

[fence.profiles.installer]
reason = "fleetup installs packages and writes system config"
allow = ["/etc", "/usr", "/var/lib/dpkg", "/var/lib/apt", "/var/cache/apt"]
unmask_sockets = ["/run/systemd/private", "/run/dbus/system_bus_socket"]
keep_caps = []
pid_namespace = false        # per-profile override of [fence] pid_namespace, either value (section 3.5)

[fence.profiles.coordinator]
reason = "jarvis restarts agents and drives other panes"
api = "coordinator"          # cross-pane API rights (section 8)

[fence.agents.fleetup]
profile = "installer"
reason = "fleet installer seat"

[fence.agents.some-seat]
profile = "unfenced"         # built-in: no fence at all for this agent
reason = "..."
```

Rules:

- **Deny-list model (owner decision).** Everything not denied is writable. Profiles relax the paths and
  rights: `allow`, `unmask_sockets`, `keep_caps`, `api`. There are no per-agent allow lists for the base and
  no way for a profile to add capabilities beyond root's. `pid_namespace` is the one switch a profile may
  set either way, so the pilot can turn it on for one agent.
- **`reason` is required** on every profile and every agent entry; a missing reason is a config error.
- **Agent identity** is the herdr agent name the pane runs (`[fence.agents.<name>]`). Panes without an
  agent, and agents without an entry, get the base fence (profile `default`). Built-in profile names:
  `default` (the base) and `unfenced`. `{agent}` in a path expands to the agent name; a pane without an
  agent gets no `{agent}` carve-out.
- **The name is not known when a pane's shell spawns.** `agent.start` types the agent command into a shell
  that already exists (`App::start_agent` in `src/app/agents.rs`). So when the agent's resolved plan
  differs from the plan the pane's shell is running under, `agent.start` first respawns the pane's shell
  with the agent's plan through the existing launch-pane respawn path (`respawn_shell_for_launch_pane`,
  `src/app/api.rs`), keeping pane id, cwd and launch env, then types the command. Paths that rebuild a
  known agent (session restore, `agent.unarchive`, `agent.restart`) hold the agent name in the terminal
  state before the pane is placed (for example `restore_managed_agent` in `agent.unarchive`,
  `src/app/agents.rs`), so they build the plan up front; #418 confirms each path. The plan travels to the
  spawn site in `PaneLaunchEnv`.
- **Paths** are resolved with `realpath` when the plan is built. On merged-/usr systems `/bin`, `/sbin`,
  `/lib`, `/lib64` resolve into `/usr` and are deduplicated. A deny of `/` is a config error.
- **Validation is all-or-nothing.** `[fence]` is loaded as one live section (`load_live_section`,
  `src/config/io.rs`): any error (unknown profile name in an agent entry, bad path syntax, allow outside any
  deny, missing reason, unknown capability name) puts the whole section in `invalid_sections`, keeps the
  previous fence config in force, and appears in the `server reload-config` diagnostics. A profile no agent
  uses is a warning, not an error.
- **When changes apply:** at the next start of each pane (new pane, `agent start`, `agent restart`, session
  restore). Running panes keep the fence they started with. `herdr fence explain` shows both the running
  pane's plan and what the current config would give.

## 5. Carve-outs, anchors and their limits

A bind-mounted file or directory is a mount point in the pane's namespace, so inside that namespace it
cannot be unlinked, renamed or removed (`EBUSY`), but its contents can be written (probes P-05 to P-10).
Outside the namespace (the host), nothing changes: the host can still delete or replace it.

Two consequences shape the default list:

1. **A bind follows the inode, not the path.** If the host replaces a bound file or directory (delete and
   recreate, `mv new old`, restore from backup), fenced panes keep the old inode until they restart.
   For a read-only config file that means a stale view; for a writable database it means split writes.
   After a host-side restore of anything bound, restart the fenced panes. `herdr fence explain` flags binds
   whose host path now points at a different inode (Q6). Likewise, because fence mounts are private (step
   4), a mount the host adds below a denied or carved-out path after the pane started is not visible in
   that pane until it restarts.
2. **Never bind SQLite `-wal` or `-shm` files.** SQLite deletes and recreates them when the last connection
   closes; a pane that kept an old `-wal` inode would write transactions nobody reads. The directory that
   holds a SQLite database must be a writable carve-out (or not denied), and the main database file may be
   anchored with a file bind because SQLite never replaces it.

For gitmoot this gives: `~/.gitmoot` anchored (cannot be deleted or renamed) and writable;
`~/.gitmoot/gitmoot.db` anchored; the subdirectories and files the gitmoot CLI does not write (config,
`runtime-auth.env`, `runtimes/`, `worktrees/`, `scripts/`, `plugins/` and others) denied individually.
#419 measures the CLI's write set with `strace` and fixes the list. The `-wal`/`-shm` files stay deletable
from a fenced pane; moving the database into its own directory in gitmoot would remove that residual risk
(Q7).

Anchors also have a cost: a rename between two different mounts fails with `EXDEV` (probe P-13). Tools
fall back to copy (`mv`) or fail (raw `rename(2)`), but only across an anchor boundary such as from
`/tmp` into `/root`. `/tmp` and `/root` are on the same filesystem on dev2306 today, so this is new
behavior there; the pilot will show whether it matters.

## 6. Default deny list (proposal; #419 finalizes it with a reason per entry in code)

| Path | Why |
|---|---|
| `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/boot`, `/opt` | OS binaries and libraries, boot files |
| `/etc` | system config, including cron, sudoers, sshd, systemd units, `/etc/keyring` |
| `/var/lib/dpkg`, `/var/lib/apt`, `/var/lib/systemd` | package and service state |
| `/var/spool/cron` | `crontab -e` and `at` would run commands outside the fence |
| `/var/log/audit` | the auditd trail of attempts on protected paths |
| `/var/lib/docker`, `/var/lib/containerd` | container data of every service on the host |
| `/var/lib/fleet-snapshots` | the hourly snapshots of herdr and gitmoot data (fleetup `fleet-state-snapshot`) |
| `/var/lib/sandboxd*` | sandboxd state |
| `/sys` | kernel and device settings (recursive: cgroup, bpf, efivars, debugfs) |
| `/root/.local/bin` | the herdr and gitmoot binaries the server and services execute |
| `~/.config/herdr` | herdr settings, sockets (still connectable, probe P-04), update binaries |
| `~/.config/systemd` | user units would start outside the fence on next login or boot |
| `~/.gitmoot` | gitmoot data, with the carve-outs of section 5 |
| `~/.ssh` | ssh keys and `authorized_keys` |
| `/mnt/storagebox-workspaces` | shared workspaces; added only together with the per-seat carve-outs of section 10 (Q10) |

`/usr/local` is under `/usr`. `/proc/sys` and the other `/proc` entries are handled by step 8.

Deliberately writable: `/tmp`, `/root/fleet-tools/state`, `~/.omp`, `~/.claude`, `~/.cache`, `~/.cargo`,
each seat's own repositories.

Default `mask_sockets`: `/run/systemd/private`, `/run/dbus/system_bus_socket`, `/run/user/*/bus`,
`/run/user/*/systemd/private`, `/run/docker.sock`, `/var/run/docker.sock`,
`/run/containerd/containerd.sock`, `/run/podman/podman.sock`, `/run/snapd.socket`, and herdr's private
TUI client socket `~/.config/herdr/herdr-client.sock` (section 8). Masking the system bus also stops
`systemd-run`, `machinectl shell`, `timedatectl` and `loginctl`; `systemctl` uses the private socket or the
bus and stops working too (by design; the `systemd` profile unmasks both). Masking is a bind over the path
at pane start: a socket recreated later on the host (daemon restart) is visible to panes started before
that. The server-side refusal in section 8 covers herdr's own sockets regardless.

## 7. Back doors and how each is closed

| # | Way around the fence | Closed by | Probe / test |
|---|---|---|---|
| B1 | `mount -o remount,rw` a denied path | no `CAP_SYS_ADMIN` | P-24 (control P-14) |
| B2 | `umount` / `umount -l` a deny bind | no `CAP_SYS_ADMIN` | P-25, P-26 |
| B3 | `nsenter -t 1 -m` / `setns` into the host namespace | no `CAP_SYS_ADMIN` | P-27 |
| B4 | write through `/proc/<unfenced pid>/root/...` | capability subset rule (target holds more caps) and the Landlock domain | P-28, P-38 |
| B5 | write through `/proc/<other fenced pane>/root/...` (same or other profile) | Landlock domain | P-39 |
| B6 | new user + mount namespace (`unshare -Urm`) then remount or umount | copied mounts are locked: remount `EPERM`, umount `EINVAL`, a tmpfs on top only changes the caller's own view; and on this host `apparmor_restrict_unprivileged_userns=1` already refuses the uid map to callers without `CAP_SYS_ADMIN` | P-16 to P-21, P-31 to P-33 |
| B7 | `open_by_handle_at` through a writable mount of the same filesystem | no `CAP_DAC_READ_SEARCH` | #418 test |
| B8 | `rename` an ancestor of a denied path (`mv /root/.config x`) | anchors (step 3) | P-11, P-12 |
| B9 | hard link or rename a protected file into a writable place | `EXDEV` across mounts (link and rename require the same mount) | #418 test |
| B10 | write raw block devices, `/dev/mem`, `/dev/port` | `nodev` binds (step 7), no `CAP_SYS_RAWIO` | #418 test |
| B11 | `mknod` a device node somewhere writable | no `CAP_MKNOD`, Landlock `MAKE_BLOCK`/`MAKE_CHAR` | P-29, P-42 |
| B12 | `insmod`, `modprobe`, `kexec`, `reboot`, `/proc/sysrq-trigger` | no `CAP_SYS_MODULE`/`CAP_SYS_BOOT`; sysrq-trigger read-only | #418 test |
| B13 | `sysctl -w`, `/proc/sys` | `/proc/sys` read-only | #418 test |
| B14 | `systemctl start`, `systemd-run`, user manager | masked `/run/systemd/private`, system and user buses | #418 test |
| B15 | `docker run -v /:/host`, containerd, podman | masked sockets | #418 test |
| B16 | `crontab`, `at`, user units, `/etc/cron*` | `/var/spool/cron`, `~/.config/systemd`, `/etc` denied | #418 test |
| B17 | `herdr pane send-text` / `send-keys` / `pane run` into an unfenced pane | API fence (section 8) | #420 tests |
| B18 | API methods that make the server spawn or exec: `pane.split`/`layout.apply` with a command, `plugin.link` + `plugin.action.invoke`, `command.invoke`, `server.live_handoff` with `import_exe`, `worktree.create` (git hooks), `agent.transfer_session` | API fence: refused, or the new process inherits the caller's fence | #420 tests |
| B19 | `agent start/restart` with a looser profile, `server reload-config`, `update`, `server stop`, `accounts.create`, `server.ssh_agent.register` | API fence | #420 tests |
| B20 | the private TUI client socket `herdr-client.sock` (attach to any pane, raw input, client-shell API requests) | masked in fenced panes; server also refuses fenced peers on it | #420 tests |
| B21 | federation TCP listener on loopback with a peer token read from `~/.config/herdr` | server refuses loopback federation peers whose peer process is fenced (Q11) | #420 tests |
| B22 | racing the importer for `herdr-handoff-<pid>.sock` (its token is in the importer's argv, readable in `/proc/<pid>/cmdline`) | handoff server accepts only the peer pid it spawned | #420 test |
| B23 | `ssh root@localhost` | companion: fleetup makes sshd refuse root logins from the host itself | outside this repo |
| B24 | BPF programs, perf | no `CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN` | #418 test |
| B25 | replace the herdr binary the server re-executes on update | `/root/.local/bin` and `~/.config/herdr` denied | #418 test |
| B26 | `chattr -i` on the Storage Box mount point | no `CAP_LINUX_IMMUTABLE` | #418 test |

## 8. The herdr API inside the fence (#420)

Today every connection to `herdr.sock` or `herdr-client.sock` is the owner: `ConnectionPrincipal::Owner`
(`src/api/server.rs`), no method filtering, protection by file mode 0600 only. A fenced pane runs as root
and can connect to both, so without this section the fence is one `herdr pane split --command ...` away
from useless. The survey behind this section is in appendix B.

**Caller identity.** Every local Unix listener resolves the peer with `SO_PEERCRED`
(`platform::unix_stream_peer_pid`) and classifies the peer process:

1. Read `/proc/<pid>/ns/mnt`. If it equals the server's own mount namespace and the peer's bounding set
   still contains `CAP_SYS_ADMIN`, the caller is **unfenced** (owner shell, ssh session, systemd unit, cron).
2. Otherwise it is **fenced**, and its mount-namespace inode is its identity. Each spawn creates a new
   namespace, so the inode names one spawn of one pane, never a pane ID that may be reused.
3. **Own pane** is resolved on every request, not cached: the caller's pane is the pane whose current
   child process is in that same mount namespace (`/proc/<pane child pid>/ns/mnt`; one `readlink` per
   candidate, with a namespace-to-pane cache that is re-validated by that one `readlink` before use). If
   the pane was respawned (for example `agent.start` changing the plan) or its process exited, the old
   namespace matches no pane. A daemonized descendant left over from the earlier spawn therefore loses
   own-pane rights over the replacement (the #425 review found that a cached pane ID would keep them).
   Streamed input (`pane.input.stream`) re-checks this for every frame. No readiness message from the
   helper is needed (#428).
4. Fenced but no matching pane (a leftover process, another namespace it made, a stale inode after a
   server restart): **fenced with profile `default` and no own pane**, the strictest class. Unknown never
   means owner.
5. The peer pid cannot be read (process already gone): refuse the request.

Process ancestry was rejected because a `setsid`/double-forked child is reparented to init and would look
unfenced; a per-pane cgroup needs systemd delegation (Q3). A connection caches only facts that cannot
change for its peer: the namespace inode and the bounding set. Pane and profile come from step 3 on each
request.

The result becomes a new principal, `ConnectionPrincipal::Fenced { mnt_ns }`, next to `Owner`,
`Federation` and `Guest`, so every method passes through one policy function, the same way federation tiers
work today (`src/api/federation.rs`).

**Policy for fenced callers: allow-list of methods.** The API has around 200 methods and new ones appear
every week, so a deny list of dangerous methods would silently open new back doors. Methods not on the list
are refused with: `refused by pane fence (profile default): <method> acts outside this pane; profile
coordinator allows it; see herdr fence explain`.

| Class | Methods | Fenced (`default`) | `coordinator` profile |
|---|---|---|---|
| Read | lists, gets, `pane.read`, `agent.read/transcript/explain`, `events.subscribe`, `*.wait`, `session.snapshot`, `fs.list_dir` | allowed | allowed |
| Own pane | input, resize, rename, `report_agent*`/`report_metadata`, `agent.focus` on the caller's own pane and agent; `pane.close` of the own pane only when closing it closes nothing else (not the last pane of a tab or workspace whose closing cascades to other panes or linked workspaces) | allowed | allowed |
| Talk to agents | `agent.prompt`, `agent.answer`, `agent.wait` on any agent (that agent has its own fence) | allowed | allowed |
| Gram, avatar, groups | `gram.*` (data in the server's store), `agent.avatar.set`, `agent.groups.set` for the own agent | allowed | allowed |
| New panes | `pane.split`, `tab.create`, `workspace.create`, popups, and `layout.apply` only when it creates a new tab or workspace (never when it replaces an existing tab, which closes that tab's panes) | allowed; **the new pane inherits the caller's plan**, whatever command or cwd it names | allowed, including replacing layouts; same inheritance unless the call names an agent, which gets its own plan |
| Other panes' input and life | `pane.send_text/send_keys/send_input`, `agent.send_keys`, `pane.close`/`tab.close`/`workspace.close`, `layout.apply` replacing a tab, `agent.restart/start/archive/forget/rename` on panes or agents that are not the caller's. Every destructive call is checked against its **complete** target set (all panes it would close or replace), not only the named target (#429) | refused | allowed; `agent.start/restart` always apply the target agent's own plan, never the caller's |
| Server runs a program | `plugin.link`, `plugin.action.invoke`, `plugin.pane.open`, `pane.link.activate`, `command.invoke`, `agent.transfer_session`, `integration.install`, `worktree.create/remove` | refused in v1 (Q12) | allowed |
| Server config and lifecycle | `server.reload_config`, `server.reload_agent_manifests`, `server.update_*`, `server.apply_staged_update`, `server.live_handoff`, `server.stop`, `server.ssh_agent.register`, `accounts.create/remove`, `plugin.enable/disable/unlink` | refused | refused (owner only) |
| Remote | targets with a `<machine>/...` alias | reads allowed; **every mutation of a remote target refused**. A remote pane is never the caller's own pane, even when its local part (`w1:p1`) matches the caller's local pane ID, and the receiving server sees only this server's federation identity, not the fenced caller | allowed |

The coordinator does not get server lifecycle methods: an agent restarting the server is exactly the
2026-11-15 failure mode. Deploys stay with the owner or the herdr seat's unfenced tooling.

**Private TUI client socket.** `herdr-client.sock` gives raw keyboard input, writable attach to any pane,
and client-shell API requests (`src/protocol/wire.rs`). Agents have no use for it, so it is in the default
`mask_sockets` list (masked inside fenced panes) and the client accept loop also refuses fenced peers, so a
socket reached some other way (a hard link made before the fence, a bind in a looser profile) is still
refused.

**Other listeners.** The handoff socket accepts only the pid it spawned (B20c). The reverse-agent and gram
gateways and the federation listener apply the same classification to local peers (B20b, Q11).

**Events.** `events.subscribe` stays open to fenced callers; events carry no capability.

## 9. Visibility (#421)

- `herdr agent get`, `agent list --json`, `pane get`: field `fence`: `{enabled, profile, deny_count,
  exceptions, missing}` (all optional fields, for API compatibility).
- `herdr fence explain <agent|pane> <path>`: `writable` or `read-only` and the rule that decides it
  (`deny /etc`, `allow ... (profile installer)`, `anchor`, `mask`, `not denied`), using the same resolver
  as the plan. For a running pane it reads the pane's actual mount table (`/proc/<pid>/mountinfo`), so it
  reports what the kernel enforces, not only what the config says.
- The one-line notice at pane start (step 12).
- Config errors come from `server reload-config` diagnostics (section 4).
- Docs: a `docs/next` page and a config-reference section ship with #418/#421.

## 10. Other seats' Storage Box worktrees (#422)

Recommendation: **option 1, per-seat subdirectories** `worktrees/<seat>/...`, with
`/mnt/storagebox-workspaces` denied and `worktrees/{agent}` (and `checkouts/{agent}`,
`reviews/{agent}`) allowed. It is the only option that protects worktrees created after the pane starts.
Option 2 (prefix match at pane start) misses later worktrees; option 3 leaves the 2026-11-15 failure
open. Option 1 needs a one-time migration with `git worktree move`, agreed with workspace-janitor and each
seat, and a change to the machine guide's workspace table. The decision is recorded with jarvis; the
migration runs only after the pilot proves the core. Until then the Storage Box stays outside the default
deny list (an empty carve-out would block every seat's worktree work).

The anchor on `/mnt/storagebox-workspaces` also needs care: the mount is `fuse.sshfs`. If it reconnects on
the host, fenced panes keep the old (dead) connection until they restart (section 5, point 1).

## 11. Tests that cannot damage the host (#423)

- Fence tests that create namespaces or mounts never run as root in the host namespace of a live server.
  They run inside a throwaway container whose own mount namespace is private, started with
  `--cap-add SYS_ADMIN` and AppArmor/seccomp relaxed for the container only, or in a VM. The probes for this
  document ran that way (appendix A).
- The suite drives the production helper directly: `herdr fence-exec -- sh -c '<action>'` with a test
  plan, plus end-to-end runs through a server inside the same container for the spawn paths.
- Every "blocked" case has a positive control: the same command succeeds without the fence (or in the
  host-analogue namespace).
- Every test asserts the container's outer mount table is unchanged afterwards. On the live host the
  whole-table diff is noisy (other seats' containers and probes change it; appendix A saw both), so the
  host check filters to the paths the plan touches.
- New tests are proven red with the fence disabled (`test-check prove`).
- CI: the hetzner2 runner's rootless container (label `h2-ci`) if it can grant `CAP_SYS_ADMIN` inside a
  user namespace; otherwise the suite is a documented `just fence-test` recipe that refuses to run outside a
  container.

## 12. What must keep working (pilot acceptance)

| Work | Why it keeps working |
|---|---|
| git and gh in the seat's own repositories, push to GitHub and hetzner2 | repos writable; `~/.ssh` readable; network unchanged |
| cargo, go, npm builds in own dirs and `/tmp` | writable; `~/.cargo`, `~/.cache` writable |
| `herdr` CLI against its own pane | `herdr.sock` connectable on a read-only bind (P-04); API fence allows own pane |
| `gitmoot` CLI (writes `gitmoot.db`) | section 5 carve-outs; verified with `strace` in #419 |
| omp sessions under `~/.omp` | writable |
| `sudo`, setuid tools | uid stays 0; no `no_new_privs` |
| `ps`, `kill` of own processes | unchanged while `pid_namespace = false`; with it on, only the pane's own processes (section 3.5) |

Known breakage by design: `systemctl`, `docker`, `crontab`, `apt`, `mount`, writes to `/etc` and other
denied paths, `bwrap`/rootless containers that need a user namespace with capabilities (already blocked for
capability-less callers by this host's AppArmor sysctl). The matching profiles restore them per agent.

## 13. Residual risks (accepted for v1)

- **Signals while `pid_namespace = false`** (the v1 default, section 3.5). A fenced root process can still
  `kill` any root process, including the herdr server (`pkill -f herdr` in a test), unless the kernel has
  Landlock ABI 6. Closed when the PID namespace is turned on after pilot step 2.
- **Indirect execution.** Files that unfenced processes later execute or source stay writable when they are
  outside the deny list: shell rc files, scripts under `/root/fleet-tools/state` run by systemd units (for
  example `phobos-openrouter-credit.service`), omp hooks under `~/.omp`, git hooks in shared repos. Out of
  scope for a mistake-oriented fence; the deny list can grow from the pilot.
- **Confused deputy.** `agent prompt` to a coordinator-profile agent can ask it to do what the caller
  cannot. Agents apply judgement; prompts are logged.
- **Stale binds** after host-side replacement (section 5).
- **SQLite `-wal`/`-shm`** deletable inside the gitmoot carve-out (section 5, Q7).
- **Devices** added after the pane starts (hotplug, new loop devices) are not `nodev`-bound; raw access to
  them still needs a node the pane cannot create.
- **Loopback services.** Fenced panes share the host network: anything on `127.0.0.1` that runs commands
  (the gitmoot daemon on behalf of the CLI, `ssh` to localhost) is reachable. sshd is the companion change;
  the others are listed in the pilot log as found.
- **Resource exhaustion** (filling a disk, fork bombs) is not a fence goal.

## 14. Kill switch and rollback

- `[fence] enabled = false` + `herdr server reload-config` + restart the affected agents (identity-preserving)
  returns them to today's behavior. Running panes keep their fence until restarted; nothing persists on the
  host because every fence mount lives only in the pane's namespace and disappears with its last process.
- Per agent: `[fence.agents.<name>] profile = "unfenced"` with a reason.
- Fenced panes cannot change any of this: config is denied and the API fence refuses `reload-config`.
- No host state to clean up: the fence never writes outside the pane's namespace.

## 15. Other platforms

macOS and Windows: out of scope for v1. `[fence] enabled = true` logs one warning at config load and
reload (`fence is Linux-only; panes start unfenced on <os>`) and changes nothing. The platform-specific code
lives in `src/platform/linux/fence.rs`; `src/platform/mod.rs` gets the shared plan types and a no-op for
other targets.

## 16. Open questions and recommendations

| # | Question | Recommendation |
|---|---|---|
| Q1 | Agents run as uid 0; should fenced panes use a different uid instead? | No. A uid change breaks file ownership, git, ssh keys and every seat's tooling; the fence keeps uid 0 and removes capabilities instead. |
| Q2 | Mount propagation: `private` (as #418 says) or `slave`? | Both: the namespace root is `slave` (`MS_REC` plus `MS_SLAVE`), so nothing travels from pane to host and host mounts still reach uncovered paths; every fence mount is made `private` before it is attached, so no host mount can appear writable below a denied path (#425 review, probes P-59 to P-62). The #423 suite asserts no pane mount reaches the outer namespace and adds the incoming-mount positive control. |
| Q3 | API caller identity: process ancestry, mount-namespace inode, or cgroup? | Mount-namespace inode plus a bounding-set check (section 8). Ancestry breaks for `setsid`/double-forked processes reparented to init, which would make a daemonized child look unfenced; a cgroup needs systemd delegation. |
| Q4 | Signals: fenced panes can kill the server and other agents. | **Decided (jarvis, 487780/487804):** #418 builds a PID namespace per fenced pane (dev2306's 6.8 kernel has no Landlock signal scoping) and ships it **off** until the gitmoot seat confirms its pid paths are namespace-safe; pilot step 2 turns it on. Landlock signal scoping is added when the kernel has ABI 6. |
| Q5 | Landlock unavailable on a host? | Fail closed (pane does not start) with a clear error, since without it B4/B5 are open. The fence needs ABI 2 or later (`REFER`, step 9). Both fleet hosts have it (dev2306: ABI 4). |
| Q6 | Stale binds after host-side replacement | `herdr fence explain` and the `fence` field report binds whose host path now resolves to a different inode, so restarts can be targeted. No live re-binding in v1. |
| Q7 | gitmoot `-wal`/`-shm` stay deletable | Ask the gitmoot seat to move `gitmoot.db` into its own directory (e.g. `~/.gitmoot/db/`), so only that directory is a carve-out. Until then accept the residual. |
| Q8 | Where should denials be logged? | The kernel does not report `EROFS` to anyone but the caller. auditd watches (fleetup) record attempts; the pilot reviews the agent's session log for `Read-only file system` / `Operation not permitted`. No herdr-side logging in v1. |
| Q9 | Should `/root/fleet-tools` (not only `state/`) be denied? | Not in the default list for v1: seats edit fleet-tools on purpose. Revisit after the pilot with jarvis. |
| Q10 | Storage Box in the default deny list before #422's migration? | No: add it only together with the per-seat carve-outs (section 10). |
| Q11 | Loopback federation: a fenced pane can read peer tokens (read-only is still readable) and connect to the federation listener as a peer | When the listener is on loopback, find the TCP peer's pid (`SO_PEERCRED` does not work for TCP: look the socket inode up in `/proc/net/tcp` and `/proc/*/fd`) and apply section 8. The listener is off on dev2306 today (`federation.listen_addr` is an `Option` with no default, `src/config/model.rs`, and the live `[federation]` table does not set it), so this can follow #420. |
| Q12 | Plugins and worktrees for fenced agents | Refused in v1 because the server runs the program unfenced. Follow-up: run server-side helpers for a fenced caller through `fence-exec` with the caller's plan, then allow them. |
| Q13 | One namespace per pane or per agent? | Per pane process tree (each spawn makes its own). Splits of a fenced pane get their own namespace with the same plan. Cost per pane: a few dozen mounts; measured in #418 with 15+ panes. |

## Appendix A: probes run for this design

Script, Landlock helper and full output: `/root/fleet-tools/state/herdr-pane-fence-20261115/design-probes/`
(`probe.sh`, `landlock_probe.c`, `probe-run-2.txt`). Environment: dev2306, kernel 6.8.0-90-generic,
LSMs `lockdown,capability,landlock,yama,apparmor`, Landlock ABI 4, inside a throwaway `debian:trixie`
container (`--cap-add SYS_ADMIN`, AppArmor and seccomp unconfined for that container, util-linux 2.41).
The script refuses to run outside Docker. Host `findmnt -R /` before and after: no change from the probes
(the only differences were other seats' Docker network namespaces and a `fuse.portal` mount another seat's
probe removed under `/tmp`).

The probes used `mount(8)` (`remount,bind,ro`, `ro=recursive`) and `setpriv` rather than the
`open_tree`/`mount_setattr` calls planned for the helper; the kernel behavior they test is the same.
Stage 1 runs with `CAP_SYS_ADMIN` in a fresh mount namespace (`--propagation slave`), stage 2 after
dropping the capability list of section 3.3 from the bounding and effective sets, stage 3 in the outer
namespace, stage 4 with a Landlock domain only.

| # | Probe | Result | Means |
|---|---|---|---|
| P-01 | write a new file in a read-only bind | `EROFS` | deny works |
| P-02 | overwrite a file in a read-only bind | `EROFS` | |
| P-03 | `rm -rf` the read-only dir | `EROFS` | 2026-11-15 herdr-config wipe blocked |
| P-04 | connect to a Unix socket on a read-only bind | connects, reply received | `herdr.sock` keeps working |
| P-05 | write a bound file (`gitmoot.db`) in a writable carve-out | ok | |
| P-06 | create a file in the carve-out dir | ok | |
| P-07 | unlink the bound `gitmoot.db` | `EBUSY` | bound file cannot be deleted |
| P-08 | rename the bound `gitmoot.db` | `EBUSY` | |
| P-09 | unlink an unbound file in the carve-out | ok | only binds are protected (section 5) |
| P-10 | `rmdir` the carve-out mount point | refused (`EROFS` from the read-only parent) | |
| P-11 | rename the unanchored ancestor of a bind | **succeeds** | hole without anchors |
| P-12 | rename an anchored ancestor | `EBUSY` | anchors close it |
| P-13 | `rename(2)` a file across an anchor | `EXDEV` | anchor side effect |
| P-14 | control: remount rw while `CAP_SYS_ADMIN` is held | ok | the stage-2 refusal is the capability, not the test |
| P-15 | control restored | `EROFS` | |
| P-16 | new userns + mount ns: remount rw | `EPERM` | copied mounts are locked |
| P-17 | new userns: umount the read-only bind | `EINVAL` | |
| P-18 | new userns: `umount -l` | `EINVAL` | |
| P-19 | new userns: write the denied path | `EROFS` | |
| P-20 | new userns: tmpfs over the denied path | ok, in the caller's own view | |
| P-21 | after P-20, the real denied dir is untouched | ok | P-20 is harmless |
| P-22 | plain `remount,bind,ro`: write in a submount | **succeeds** | non-recursive read-only is a hole |
| P-23 | `ro=recursive`: write in the submount | `EROFS` | use `mount_setattr(AT_RECURSIVE)` |
| P-24 | capabilities dropped: remount rw | `EPERM` | B1 |
| P-25 | umount | `EPERM` | B2 |
| P-26 | `umount -l` | `EPERM` | B2 |
| P-27 | `nsenter -t 1 -m` | `EPERM` | B3 |
| P-28 | write via `/proc/1/root` (pid 1 holds more caps) | `EACCES` | B4 |
| P-29 | `mknod` a block device | `EPERM` | B11 |
| P-30 | write outside the deny list | ok | everything else stays writable |
| P-31 | `unshare -Urm` without `CAP_SYS_ADMIN` | uid map write `EPERM` (AppArmor userns restriction) | B6, host setting |
| P-32 | as P-31, umount attempt | same | |
| P-33 | as P-31, write attempt | same | |
| P-34 | outer namespace: denied path writable | ok | nothing leaked out |
| P-35 | outer namespace: unlink `gitmoot.db` | ok | binds are per namespace |
| P-36 | outer namespace: no fence mounts in its mount table | none | propagation contained |
| P-37 | control: unfenced process reads `/proc/<pane>/root` | ok | |
| P-38 | pane reads `/proc/<unfenced>/root` (same caps) | `EACCES` | B4 via Landlock |
| P-39 | pane reads `/proc/<other pane>/root` (same caps) | `EACCES` | B5 |
| P-40 | control: pane reads `/proc/<own child>/root` | ok | own tree unaffected |
| P-41 | pane reads `/proc/<unfenced>/environ` | `EACCES` | |
| P-42 | pane `mknod` a char device while holding `CAP_MKNOD` | `EACCES` | Landlock device-node rule |
| P-43 | control: same `mknod` without Landlock | ok | |

PID-namespace probes (`pidns-probe.sh`, `pidns-run-1.txt` in the same directory; same container setup,
`procps` added): the pane runs `unshare -m --propagation slave --pid --fork`, binds the host `/proc`
read-only at `/run/host-proc`, and mounts a fresh `/proc`. A `sleep` started outside stands in for the
herdr server. Host mount table unchanged before and after.

| # | Probe | Result | Means |
|---|---|---|---|
| P-44 | `pgrep` for the outside process | not found | host processes are invisible |
| P-45 | `ps -e` inside the pane | 4 processes, all the pane's own | |
| P-46 | `kill -0 <outside pid>` | `ESRCH` | pid-file checks report "dead" |
| P-47 | `pkill -f` the outside process | not found | `pkill -f herdr` cannot reach the server |
| P-48 | `kill -9 -1` inside the pane | only the pane's processes; outside process alive (P-52) | |
| P-49 | read the outside process's `cmdline` through the read-only host `/proc`, and scan it like `pgrep` | ok | host checks still possible |
| P-50 | `pidfd_send_signal` with a host `/proc/<pid>` dir fd | `EINVAL` | the host view cannot signal |
| P-51 | write `/proc/sys` through the host view | `EROFS` | |
| P-52 | outside process after the pane exited | alive | |
| P-53 | `setsid nohup` job started in the pane, after the pane's pid 1 exits | killed | background jobs end with the pane |
| P-54 | control: same job without a PID namespace | survives | |
| P-55 | control: `pidfd_send_signal` from the outer namespace | ok | P-50's refusal is the namespace |

Probes for the #425 review findings (`review-fix-probe.sh`, `review-fix-run-1.txt`, rebuilt
`landlock_probe.c` with a `refer` mode; same container setup). The outer tree is made `rshared` first so it
behaves like a systemd host root. Host mount table unchanged before and after.

| # | Probe | Result | Means |
|---|---|---|---|
| P-56 | started inside a denied dir: absolute write after the deny mount | `EROFS` | |
| P-57 | same process, `./rel` through the inherited cwd | **succeeds**, file lands in the real dir | hole: stale cwd (step 11) |
| P-58 | after `chdir` to the absolute path: `./rel2` | `EROFS` | fix |
| P-59 | slave deny clone; host mounts a tmpfs below the denied dir afterwards; pane writes there | **succeeds**, file reaches the host tmpfs | hole: incoming propagation (step 4) |
| P-60 | outer namespace sees the pane's file on that tmpfs | yes | confirms P-59 |
| P-61 | private deny clone, same host mount; pane writes there | `EROFS` | fix |
| P-62 | outer namespace: the pane's file is absent | absent | confirms P-61. The incoming mount still shows in the pane's `mountinfo`, attached to the shadowed original mount below the clone, unreachable by path |
| P-63 | Landlock ruleset handling only `MAKE_CHAR`/`MAKE_BLOCK`: `rename(2)` between two writable dirs | `EXDEV` | `REFER` is denied implicitly (#427); control without Landlock: ok |
| P-64 | ruleset handling `REFER` too, with `REFER` granted beneath `/`: same rename | ok | fix |
| P-65 | same ruleset: hard link across dirs | ok | |
| P-66 | same ruleset: `mknod` a char device | `EACCES` | device rule kept |
| P-67 | same ruleset: `/proc/<outside>/root` | `EACCES` | domain isolation kept |

Not probed yet (covered by #418 tests): `open_by_handle_at` without `CAP_DAC_READ_SEARCH`, `nodev` binds
on block devices, `/proc/sys` and `sysrq-trigger`, masked sockets, `insmod`/`reboot`, and the combination
of mount namespace, PID namespace, Landlock and capability drop in one process.

## Appendix B: herdr surfaces reviewed (source tree `bcc7b71a`)

| Surface | Where | Today |
|---|---|---|
| Pane process creation | `PaneRuntime::spawn_command_builder` → `pty::backend::spawn_with_portable_pty` (`src/pane.rs`, `src/pty/backend/unix.rs`), the only caller; covers new pane, split, tab, workspace, popup, plugin pane, layout, restore, resume | one hook point |
| `agent.start` | `App::start_agent` (`src/app/agents.rs`) types into an existing shell | no spawn; plan decided earlier (section 4) |
| Live handoff | PTY master fds move to `herdr server --handoff-import` over `SCM_RIGHTS` (`src/server/handoff.rs`); pane processes untouched | fences survive handoff unchanged |
| `herdr.sock` | `src/api/server.rs`; `ConnectionPrincipal::Owner` for every local caller | no caller identity |
| `herdr-client.sock` | `src/server/headless.rs`, `src/server/client_accept.rs`; attach, raw input, client-shell requests | mode 0600 only |
| Federation TCP | `src/api/server.rs`, tiers in `src/api/federation.rs` | token + tier policy |
| Handoff socket | `src/server/handoff.rs`, token from `src/server/headless/lifecycle.rs` | one-time token |
| Server-run programs | plugins (`src/app/api/plugins/runtime.rs`), custom commands (`src/app/custom_commands.rs`), git for worktrees (`src/worktree.rs`), session transfer (`src/session_transfer.rs`), update guard (`src/update/apply.rs`) | run unfenced by design; reachable only through methods section 8 refuses |
| Config reload | `server.reload_config` → `apply_config_from_disk` (`src/app/mod.rs`), sections via `load_live_section` (`src/config/io.rs`) | per-section reject without half-apply |
