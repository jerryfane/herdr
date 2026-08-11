---
name: herdrup-gram-skill
description: Message the owner with push notifications through the Herdr app, send and receive files, pick up work the owner queued, and delete a message (and its file) — all via the local `herdr gram` command. Use when you need to send the owner a summary, update, question, or file; to check for and claim tasks the owner posted; or to clean up a short-lived secret after use.
metadata:
  channel: gram
  transport: herdr
---

# Herdrup gram

Gram is the owner↔agent message channel surfaced in the owner's Herdr mobile
app. Use it to **send the owner a push-notified message or file** and to **pick
up work the owner queued** for the fleet. It is the in-app counterpart to
Agentgram (Telegram); both work — prefer gram when the owner asked for app
messages or when picking up owner-queued tasks.

All commands go through the installed `herdr` binary. Your identity (`from` /
`grabbed by`) is resolved automatically from `HERDR_PANE_ID`, which every Herdr
pane sets — you do not pass it yourself. If you are not running inside a Herdr
pane, pass `--from <label>` on send and `--as <label>` on grab.

## Send the owner a message (push-notified)

Use for summaries, status updates, a question that needs the owner, or anything
you would otherwise send via Agentgram to reach the owner's phone.

```sh
herdr gram send "digest ready: 7 items, 2 need your call"
```

Send only what the owner actually needs to see on their phone — this fires a
push. One clear message beats several fragments.

## Send the owner a file

Attach a file with `--file`; the text becomes an optional caption (omit it to
send the file alone). The file is uploaded in chunks automatically, so images,
logs, and small docs all work. Keep files to a few MB.

```sh
herdr gram send --file ./out/report.pdf "the report you asked for"
herdr gram send --file ./screenshot.png            # no caption
```

## Pick up work the owner queued

The owner posts tasks either to a **shared queue** (any agent may claim) or
**directly to one agent**. Check the shared queue, then claim an item so no one
else takes it. A claim is **first-wins**: exactly one agent gets each shared
item; a second claim fails with `already_grabbed`.

```sh
# See unclaimed shared work waiting for the fleet
herdr gram list --queue

# Claim one by id (marks it "grabbed by <you>", locks others out)
herdr gram grab gram-<id>

# See everything addressed to or grabbed by you (not just the queue)
herdr gram list
```

Grab **before** you start the work, not after — the grab is what stops another
agent from duplicating it. If `grab` returns `already_grabbed`, pick a different
item. After finishing a grabbed task, report back with `herdr gram send`.

## Download a file the owner sent you

A message may carry a file (its `file` field has `name`/`size`/`mime`/`sha256`).
Fetch the bytes by the message id:

```sh
herdr gram get-file gram-<id> -o ./downloaded-file
```

The file is written owner-only (mode 0600), so a downloaded secret is not left
world-readable.

## Delete a message (and its file), for good

`delete` removes a message and any attached file bytes permanently. You can
delete a message you sent, grabbed, or that is addressed to you.

```sh
herdr gram delete gram-<id>
```

This is the safe way to handle a **short-lived secret**: if the owner sends you
a temporary API key (as a message or a file), use it, then delete it — the bytes
are purged from the store and disk. Note this is cooperative cleanup within a
flat local trust domain, not an authenticated boundary; delete promptly rather
than relying on the audience filter to hide a secret from a co-resident process.

## List output

`herdr gram list` prints JSON: a `messages` array, newest first. Each message
has `id`, `direction` (`agent_to_owner` | `owner_to_agent`), `from`, optional
`to` (present only for a direct message), `text`, optional `file`
(`{name,size,mime,sha256}`), optional `grabbed_by` / `grabbed_unix_ms`,
`created_unix_ms`, and `read_by_owner`. A shared, still-open queue item is
`direction: owner_to_agent`, no `to`, no `grabbed_by`.

## Owner-side commands (rarely needed by agents)

These act as the owner and are normally driven from the app, not by agents:

```sh
herdr gram post "please review the deploy plan" --to trend-scout  # direct
herdr gram post "anyone free to triage #482?"                     # shared queue
herdr gram mark-read gram-<id>
herdr gram delete gram-<id> --owner                               # delete any message
```

## Notes

- Errors are returned as JSON `{"error": {...}}` with a non-zero exit code:
  `already_grabbed` (someone claimed it first), `not_grabbable` (a direct
  message or already claimed), `not_found`, `forbidden` (you may only delete a
  message you sent, grabbed, or that is addressed to you), `no_file` (that
  message has no attached file), `unknown_caller` (no resolvable identity — pass
  `--as <label>`), `gram_unavailable` (not connected to the shared Herdr
  server).
- Gram does not replace Agentgram. If the owner asked specifically for a
  Telegram message, use the `agentgram` skill instead.
