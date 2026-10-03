// installed by herdr
// managed by herdr; reinstalling or updating the integration overwrites this file.
// add custom hooks/plugins beside this file instead of editing it.
// HERDR_INTEGRATION_ID=omp
// HERDR_INTEGRATION_VERSION=11
// @ts-nocheck

import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const HERDR_ENV = process.env.HERDR_ENV;
const socketPath = process.env.HERDR_SOCKET_PATH;
const socketEndpoint =
  process.platform === "win32" && socketPath ? `\\\\.\\pipe\\${socketPath}` : socketPath;
const paneId = process.env.HERDR_PANE_ID;
const source = "herdr:omp";

let notificationContext: ExtensionContext | undefined;
let notificationListener: { server: net.Server; directory: string; endpoint?: string } | undefined;

function closeNotificationListener() {
  const listener = notificationListener;
  notificationListener = undefined;
  if (!listener) return;
  listener.server.close(() => {
    fs.rmSync(listener.directory, { recursive: true, force: true });
  });
}

function startNotificationListener(ctx: ExtensionContext) {
  notificationContext = ctx;
  if (!ctx.notification || notificationListener) return;
  let directory: string | undefined;
  try {
    const base = path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "herdr", "notification-runtimes");
    fs.mkdirSync(base, { recursive: true, mode: 0o700 });
    directory = fs.mkdtempSync(path.join(base, "omp-"));
    const endpoint = process.platform === "win32"
      ? `\\\\.\\pipe\\herdr-notify-${ctx.notification.target().runtimeId}`
      : path.join(directory, "notify.sock");
    const server = net.createServer(socket => {
      let body = "";
      let bytes = 0;
      let handled = false;
      socket.setEncoding("utf8");
      socket.setTimeout(2000, () => socket.destroy());
      socket.on("error", () => socket.destroy());
      socket.on("data", chunk => {
        if (handled) return;
        bytes += Buffer.byteLength(chunk);
        if (bytes > 6 * 32768 + 4096) {
          handled = true;
          socket.destroy();
          return;
        }
        body += chunk;
        const newline = body.indexOf("\n");
        if (newline < 0) return;
        handled = true;
        try {
          const request: unknown = JSON.parse(body.slice(0, newline));
          if (typeof request !== "object" || request === null ||
              !("method" in request) || request.method !== "agent.prompt_safe" ||
              !("id" in request) || typeof request.id !== "string" || request.id.length > 256 ||
              !("params" in request) || typeof request.params !== "object" || request.params === null ||
              body.slice(newline + 1).trim() !== "") {
            socket.destroy();
            return;
          }
          const params = request.params;
          if (!("content" in params) || typeof params.content !== "string" ||
              !("target" in params) || typeof params.target !== "object" || params.target === null) {
            socket.destroy();
            return;
          }
          const target = params.target;
          if (!("runtimeId" in target) || typeof target.runtimeId !== "string" ||
              !("sessionId" in target) || typeof target.sessionId !== "string" ||
              !("generation" in target) || typeof target.generation !== "number" ||
              !Number.isSafeInteger(target.generation) || target.generation < 0) {
            socket.destroy();
            return;
          }
          // Check and admission execute in one JS turn inside OMP, never through the PTY.
          const result = notificationContext?.notification?.submit({
            content: params.content,
            target: { runtimeId: target.runtimeId, sessionId: target.sessionId, generation: target.generation },
          })
            ?? { status: "deferred", reason: "unavailable" };
          socket.end(`${JSON.stringify({ id: request.id, result })}\n`);
        } catch {
          // An exception might follow admission. No refusal receipt means unknown, not retryable.
          socket.destroy();
        }
      });
    });
    const listener = { server, directory, endpoint: undefined as string | undefined };
    notificationListener = listener;
    server.on("error", () => {
      if (notificationListener === listener) closeNotificationListener();
    });
    server.listen(endpoint, () => {
      if (notificationListener !== listener) return;
      try {
        if (process.platform !== "win32") fs.chmodSync(endpoint, 0o600);
      } catch {
        closeNotificationListener();
        return;
      }
      listener.endpoint = endpoint;
      void reportSession();
    });
    server.unref();
  } catch {
    notificationListener = undefined;
    if (directory) fs.rmSync(directory, { recursive: true, force: true });
  }
}
// OMP marks every shell it spawns with OMPCODE=1. A nested `omp` launched from
// a parent session's shell inherits it, so that process is not the pane's root
// agent and must not report its short-lived session over the parent's.
const nestedOmpSession = process.env.OMPCODE === "1";

function enabled() {
  return HERDR_ENV === "1" && !!socketPath && !!paneId && !nestedOmpSession;
}

let requestQueue = Promise.resolve();

function sendRequestAttempt(request: unknown, timeoutMs: number): Promise<boolean> {
  if (!enabled()) {
    return Promise.resolve(true);
  }

  return new Promise((resolve) => {
    let done = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const finish = (delivered: boolean) => {
      if (done) return;
      done = true;
      if (timeout) {
        clearTimeout(timeout);
      }
      socket.destroy();
      resolve(delivered);
    };

    const socket = net.createConnection(socketEndpoint!);
    socket.on("error", () => finish(false));
    socket.on("connect", () => socket.write(`${JSON.stringify(request)}\n`));
    socket.on("data", () => finish(true));
    socket.on("end", () => finish(false));
    timeout = setTimeout(() => finish(false), timeoutMs);
    timeout.unref?.();
  });
}

async function sendRequestNow(request: unknown): Promise<void> {
  if (await sendRequestAttempt(request, 500)) {
    return;
  }
  await sendRequestAttempt(request, 1500);
}

function sendRequest(request: unknown): Promise<void> {
  requestQueue = requestQueue.then(
    () => sendRequestNow(request),
    () => sendRequestNow(request),
  );
  return requestQueue;
}

type AgentState = "working" | "blocked" | "idle";

type QueuedState = {
  state: AgentState;
  message?: string;
  seq: number;
};

const idleDebounceMs = parseDurationEnv("HERDR_OMP_IDLE_DEBOUNCE_MS", 250);
const retryGraceMs = parseDurationEnv("HERDR_OMP_RETRY_GRACE_MS", 2500);
const retryableErrorPattern =
  /overloaded|provider.?returned.?error|rate.?limit|too many requests|429|500|502|503|504|service.?unavailable|server.?error|internal.?error|network.?error|connection.?error|connection.?refused|connection.?lost|websocket.?closed|websocket.?error|other side closed|fetch failed|upstream.?connect|reset before headers|socket hang up|ended without|http2 request did not get a response|timed? out|timeout|terminated|retry delay/i;
let reportSeq = Date.now() * 1000;
let currentAgentSessionId: string | undefined;
let currentAgentSessionPath: string | undefined;
let currentAgentSessionCursor: string | undefined;

function nextReportSeq(): number {
  reportSeq += 1;
  return reportSeq;
}

export function isAbsoluteSessionPath(file: unknown): file is string {
  return (
    typeof file === "string" &&
    (path.posix.isAbsolute(file) || path.win32.isAbsolute(file))
  );
}

function updateSessionRef(ctx: any): void {
  try {
    const file = ctx?.sessionManager?.getSessionFile?.();
    currentAgentSessionPath = isAbsoluteSessionPath(file) ? file : undefined;
  } catch {
    currentAgentSessionPath = undefined;
  }

  try {
    const id = ctx?.sessionManager?.getSessionId?.();
    currentAgentSessionId = typeof id === "string" && id.length > 0 ? id : undefined;
  } catch {
    currentAgentSessionId = undefined;
  }

  try {
    const cursor = ctx?.sessionManager?.getLeafId?.();
    currentAgentSessionCursor =
      typeof cursor === "string" && cursor.length > 0 ? cursor : undefined;
  } catch {
    currentAgentSessionCursor = undefined;
  }
}

function withSessionRef(params: Record<string, unknown>): Record<string, unknown> {
  const runtime = {
    agent_session_cursor: currentAgentSessionCursor,
    agent_process_pid: process.pid,
  };
  if (currentAgentSessionPath) {
    return { ...params, agent_session_path: currentAgentSessionPath, ...runtime };
  }
  if (currentAgentSessionId) {
    return { ...params, agent_session_id: currentAgentSessionId, ...runtime };
  }
  return params;
}

function parseDurationEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return parsed;
}

function currentSessionRef(): Record<string, unknown> | undefined {
  if (currentAgentSessionPath) {
    return {
      agent_session_path: currentAgentSessionPath,
      agent_session_cursor: currentAgentSessionCursor,
      agent_process_pid: process.pid,
    };
  }
  if (currentAgentSessionId) {
    return {
      agent_session_id: currentAgentSessionId,
      agent_session_cursor: currentAgentSessionCursor,
      agent_process_pid: process.pid,
    };
  }
  return undefined;
}

function reportSession(sessionStartSource = "startup"): Promise<void> {
  const sessionRef = currentSessionRef();
  if (!sessionRef) {
    return Promise.resolve();
  }

  return sendRequest({
    id: `${source}:session:${Date.now()}:${Math.random().toString(36).slice(2)}`,
    method: "pane.report_agent_session",
    params: {
      pane_id: paneId,
      source,
      agent: "omp",
      seq: nextReportSeq(),
      session_start_source: sessionStartSource,
      agent_notification: notificationListener?.endpoint && notificationContext?.notification
        ? { endpoint: notificationListener.endpoint, target: notificationContext.notification.target() }
        : undefined,
      ...sessionRef,
    },
  });
}

function sendState(state: AgentState, message?: string, seq = nextReportSeq()): Promise<void> {
  return sendRequest({
    id: `${source}:${Date.now()}:${Math.random().toString(36).slice(2)}`,
    method: "pane.report_agent",
    params: withSessionRef({
      pane_id: paneId,
      source,
      agent: "omp",
      state,
      message,
      seq,
    }),
  });
}

let sendInFlight = false;
let queuedState: QueuedState | undefined;

function queueState(state: AgentState, message?: string): void {
  queuedState = { state, message, seq: nextReportSeq() };
  if (!sendInFlight) {
    void drainStateQueue();
  }
}

async function drainStateQueue(): Promise<void> {
  if (sendInFlight) {
    return;
  }

  sendInFlight = true;
  try {
    while (queuedState) {
      const next = queuedState;
      queuedState = undefined;
      await sendState(next.state, next.message, next.seq);
    }
  } finally {
    sendInFlight = false;
    if (queuedState) {
      void drainStateQueue();
    }
  }
}

function lastAssistantMessage(messages: unknown[]): any | undefined {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i] as any;
    if (message?.role === "assistant") {
      return message;
    }
  }
  return undefined;
}

function retryableErrorMessage(event: any): string | undefined {
  const messages = Array.isArray(event?.messages) ? event.messages : [];
  const assistant = lastAssistantMessage(messages);
  if (assistant?.stopReason !== "error") {
    return undefined;
  }

  const errorMessage = String(assistant.errorMessage ?? "");
  if (!retryableErrorPattern.test(errorMessage)) {
    return undefined;
  }
  return errorMessage || "retryable provider error";
}

function askBlockedMessage(args: any): string {
  const questions = Array.isArray(args?.questions) ? args.questions : [];
  const firstQuestion = questions.find((question: any) => typeof question?.question === "string");
  if (firstQuestion?.question) {
    return firstQuestion.question;
  }
  return "waiting for user input";
}

export default function (pi) {
  if (!enabled()) {
    return;
  }

  let agentActive = false;
  let retryHoldActive = false;
  let failureBlocked = false;
  let failureMessage: string | undefined;
  let blockedCount = 0;
  let blockedMessage: string | undefined;
  let lastState: AgentState | undefined;
  let lastMessage: string | undefined;
  let idleTimer: ReturnType<typeof setTimeout> | undefined;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let rootSession = false;

  function clearTimer(timer: ReturnType<typeof setTimeout> | undefined) {
    if (timer) {
      clearTimeout(timer);
    }
  }

  function clearPendingTimers() {
    clearTimer(idleTimer);
    clearTimer(retryTimer);
    idleTimer = undefined;
    retryTimer = undefined;
  }

  function clearFailureState() {
    retryHoldActive = false;
    failureBlocked = false;
    failureMessage = undefined;
  }

  function desiredState() {
    if (blockedCount > 0) {
      return { state: "blocked" as const, message: blockedMessage };
    }
    if (failureBlocked) {
      return { state: "blocked" as const, message: failureMessage };
    }
    if (agentActive || retryHoldActive) {
      return { state: "working" as const, message: undefined };
    }
    return { state: "idle" as const, message: undefined };
  }

  function publishState(force = false) {
    const next = desiredState();
    if (!force && next.state === lastState && next.message === lastMessage) {
      return;
    }
    lastState = next.state;
    lastMessage = next.message;
    queueState(next.state, next.message);
  }

  function scheduleIdle() {
    clearPendingTimers();
    clearFailureState();
    idleTimer = setTimeout(() => {
      idleTimer = undefined;
      publishState();
    }, idleDebounceMs);
    idleTimer.unref?.();
  }

  function holdForRetry(message: string) {
    clearPendingTimers();
    retryHoldActive = true;
    failureBlocked = false;
    failureMessage = message;
    publishState();

    retryTimer = setTimeout(() => {
      retryTimer = undefined;
      retryHoldActive = false;
      failureBlocked = true;
      publishState();
    }, retryGraceMs);
    retryTimer.unref?.();
  }

  function activateRootSession(ctx: any, sessionStartSource = "startup"): boolean {
    if (ctx?.hasUI !== true) {
      return false;
    }
    rootSession = true;
    startNotificationListener(ctx);
    updateSessionRef(ctx);
    void reportSession(sessionStartSource);
    return true;
  }

  function resetSessionState() {
    clearPendingTimers();
    clearFailureState();
    agentActive = false;
    blockedCount = 0;
    blockedMessage = undefined;
  }

  function activateBlocked(message: string | undefined) {
    clearPendingTimers();
    blockedCount += 1;
    blockedMessage = message;
    publishState();
  }

  function deactivateBlocked() {
    blockedCount = Math.max(0, blockedCount - 1);
    if (blockedCount === 0) {
      blockedMessage = undefined;
    }
    publishState();
  }

  pi.events.on("herdr:blocked", (data) => {
    if (!rootSession) {
      return;
    }
    if (!data?.active) {
      deactivateBlocked();
      return;
    }

    activateBlocked(data.label);
  });

  pi.on("session_start", (_event, ctx) => {
    if (!activateRootSession(ctx)) {
      return;
    }
    // A reload can replace this extension mid-run without emitting another agent_start.
    agentActive = ctx?.isIdle?.() === false;
    publishState(true);
  });

  pi.on("session_switch", (event, ctx) => {
    if (!activateRootSession(ctx, event?.reason || "resume")) {
      return;
    }
    resetSessionState();
    publishState(true);
  });

  for (const eventName of ["session_branch", "session_tree", "session_compact", "auto_compaction_end"]) {
    pi.on(eventName, (_event, ctx) => {
      if (!rootSession && !activateRootSession(ctx)) {
        return;
      }
      updateSessionRef(ctx);
      void reportSession(eventName === "session_branch" ? "branch" : eventName === "session_tree" ? "select" : "compact");
    });
  }

  pi.on("agent_start", (_event, ctx) => {
    if (!rootSession && !activateRootSession(ctx)) {
      return;
    }
    updateSessionRef(ctx);
    void reportSession();
    clearPendingTimers();
    clearFailureState();
    agentActive = true;
    publishState();
  });

  pi.on("tool_approval_requested", (event, ctx) => {
    if (!rootSession && !activateRootSession(ctx)) {
      return;
    }
    const label = event?.reason || `${event?.toolName || "Tool"} approval`;
    activateBlocked(label);
  });

  pi.on("tool_approval_resolved", (_event, ctx) => {
    if (!rootSession && !activateRootSession(ctx)) {
      return;
    }
    deactivateBlocked();
  });

  pi.on("tool_execution_start", (event, ctx) => {
    if (event?.toolName !== "ask") {
      return;
    }
    if (!rootSession && !activateRootSession(ctx)) {
      return;
    }
    activateBlocked(askBlockedMessage(event.args));
  });

  pi.on("tool_execution_end", (event, ctx) => {
    if (event?.toolName !== "ask") {
      return;
    }
    if (!rootSession && !activateRootSession(ctx)) {
      return;
    }
    deactivateBlocked();
  });

  pi.on("agent_end", (event, ctx) => {
    if (!rootSession) {
      return;
    }
    if (!agentActive) {
      // OMP can emit duplicate/late end events while auto-retry is already
      // holding the pane in Working. Do not let an unqualified duplicate end
      // cancel the retry hold and publish a false Idle.
      return;
    }
    if (event?.willContinue === true) {
      // A continuation is already scheduled, so this end is not a settle.
      // Older builds omit the field and fall through as before.
      return;
    }

    updateSessionRef(ctx);
    void reportSession();

    agentActive = false;

    const retryableMessage = retryableErrorMessage(event);
    if (retryableMessage) {
      holdForRetry(retryableMessage);
      return;
    }

    scheduleIdle();
  });

  pi.on("session_shutdown", () => {
    if (rootSession) {
      clearPendingTimers();
      notificationContext = undefined;
      closeNotificationListener();
    }
  });
}
