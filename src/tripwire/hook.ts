/**
 * The Tripwire as a Claude Code or Codex hook (ADR-0044 decision 3): the same two tiers as the pi
 * extension, from the same `inspect`, answered in each agent's hook dialect.
 *
 * Interface: one pure-ish function, `runHook(agent, payload, deps)`, returning the hook's stdout.
 * The hook always exits 0, because both agents ignore a hook's JSON on any other exit code.
 *
 * - Claude: a Halt is a deny plus `continue: false`; a redaction is `updatedToolOutput` in the
 *   tool's own output shape.
 * - Codex 0.162 supports neither: a Halt is a deny plus stopping the codex process (`stopAgent`),
 *   and a result showing a credential is withheld whole (`decision: "block"`).
 *
 * Exposure and the halted flag live in per-session state (neither agent lets a hook write custom
 * transcript entries). Fail closed: an internal error halts a tool call and withholds a result.
 */
import { inspect, type Exposure, type World } from "./core.ts";

export type Agent = "claude" | "codex";

export interface HookState {
  exposure: Exposure;
  halted: boolean;
}

export interface HookDeps {
  /** May throw: a World that cannot load fails closed. */
  world(): World;
  readState(sessionId: string): HookState;
  writeState(sessionId: string, state: HookState): void;
  /** Phone push, the halt log and the launcher's halt marker; never throws. */
  halt(reason: string): void;
  /** Codex only: stop the agent process this hook runs under. */
  stopAgent(): void;
}

export interface HookReply {
  stdout: string;
}

/** Hook tool names whose results are untrusted content, mapped to the name Exposure records. */
const UNTRUSTED_EXACT = new Map([
  ["WebFetch", "web_fetch"],
  ["WebSearch", "web_search"],
]);
const UNTRUSTED_PREFIXES = [
  "mcp__claude-in-chrome__",
  "mcp__chrome_devtools",
  "mcp__plugin_marshal-shim_marshal__",
  "mcp__marshal__",
];

/** The tool name `inspect` sees: an untrusted tool collapses to one name `world` marks untrusted. */
function canonicalTool(tool: string): string {
  const exact = UNTRUSTED_EXACT.get(tool);
  if (exact) return exact;
  const prefix = UNTRUSTED_PREFIXES.find((candidate) => tool.startsWith(candidate));
  return prefix ? prefix.replace(/__$/, "") : tool;
}

function withHookTools(world: World): World {
  const names = [...UNTRUSTED_EXACT.values(), ...UNTRUSTED_PREFIXES.map((prefix) => prefix.replace(/__$/, ""))];
  return { ...world, untrustedTools: new Set([...world.untrustedTools, ...names]) };
}

interface Payload {
  event: string;
  sessionId: string;
  tool: string;
  input: unknown;
  response: unknown;
}

function readPayload(raw: unknown): Payload {
  const value = (raw ?? {}) as Record<string, unknown>;
  const text = (key: string) => (typeof value[key] === "string" ? (value[key] as string) : "");
  const session = text("session_id").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128);
  return { event: text("hook_event_name"), sessionId: session || "unknown", tool: text("tool_name"), input: value.tool_input, response: value.tool_response };
}

function deny(agent: Agent, reason: string, stop: boolean): HookReply {
  const body: Record<string, unknown> = {
    hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason },
  };
  if (stop && agent === "claude") Object.assign(body, { continue: false, stopReason: reason });
  return { stdout: JSON.stringify(body) };
}

const TOLD_HALTED = "Tripwire: this call carried a credential. The session is halted.";

function haltCall(agent: Agent, reason: string, sessionId: string, state: HookState, deps: HookDeps): HookReply {
  deps.writeState(sessionId, { ...state, halted: true });
  deps.halt(reason);
  const reply = deny(agent, TOLD_HALTED, true);
  if (agent === "codex") deps.stopAgent();
  return reply;
}

function preToolUse(agent: Agent, payload: Payload, deps: HookDeps): HookReply {
  const state = deps.readState(payload.sessionId);
  if (state.halted) return deny(agent, "Tripwire: the session is halted.", true);
  let world: World;
  try {
    world = withHookTools(deps.world());
  } catch (error) {
    return haltCall(agent, internal(error), payload.sessionId, state, deps);
  }
  const decision = inspect({ kind: "tool_call", tool: canonicalTool(payload.tool), input: payload.input, round: 0 }, world, state.exposure);
  if (decision.action === "halt") return haltCall(agent, decision.reason, payload.sessionId, state, deps);
  if (decision.action === "refuse") return deny(agent, decision.reason, false);
  return { stdout: "" };
}

function internal(error: unknown): string {
  return `Tripwire internal error (${error instanceof Error ? error.name : "unknown"}), failing closed`;
}

/** String values in document order, then every key: the same strings `stringLeaves` sees, values first. */
function splitLeaves(value: unknown, values: string[] = [], keys: string[] = []): { values: string[]; keys: string[] } {
  if (typeof value === "string") values.push(value);
  else if (Array.isArray(value)) for (const item of value) splitLeaves(item, values, keys);
  else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      keys.push(key);
      splitLeaves(item, values, keys);
    }
  }
  return { values, keys };
}

/** `value` with its string values replaced, in the order `splitLeaves` produced them. */
function replaceValues(value: unknown, next: () => string): unknown {
  if (typeof value === "string") return next();
  if (Array.isArray(value)) return value.map((item) => replaceValues(item, next));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replaceValues(item, next)]));
  }
  return value;
}

const WITHHELD = "[Tripwire: this result was withheld because it showed a credential]";

/** Claude's withhold: Bash's own shape when that is the tool, else stop the session (a wrong shape is ignored). */
function claudeWithhold(tool: string): HookReply {
  if (tool === "Bash") return postOutput({ stdout: WITHHELD, stderr: "", interrupted: false, isImage: false });
  return { stdout: JSON.stringify({ continue: false, stopReason: WITHHELD }) };
}

function postOutput(updatedToolOutput: unknown): HookReply {
  return { stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput } }) };
}

function withhold(agent: Agent, tool: string): HookReply {
  return agent === "claude" ? claudeWithhold(tool) : { stdout: JSON.stringify({ decision: "block", reason: WITHHELD }) };
}

function postToolUse(agent: Agent, payload: Payload, deps: HookDeps): HookReply {
  try {
    const state = deps.readState(payload.sessionId);
    const { values, keys } = splitLeaves(payload.response);
    const event = { kind: "tool_result" as const, tool: canonicalTool(payload.tool), texts: [...values, ...keys], round: 0 };
    const decision = inspect(event, withHookTools(deps.world()), state.exposure);
    if (decision.exposure !== state.exposure) deps.writeState(payload.sessionId, { ...state, exposure: decision.exposure });
    if (decision.action !== "redact") return { stdout: "" };
    const keysChanged = decision.texts.slice(values.length).some((text, index) => text !== keys[index]);
    if (agent === "codex" || keysChanged) return withhold(agent, payload.tool);
    let index = 0;
    return postOutput(replaceValues(payload.response, () => decision.texts[index++]));
  } catch {
    return withhold(agent, payload.tool);
  }
}

export function runHook(agent: Agent, raw: unknown, deps: HookDeps): HookReply {
  const payload = readPayload(raw);
  if (payload.event === "PreToolUse") return preToolUse(agent, payload, deps);
  if (payload.event === "PostToolUse") return postToolUse(agent, payload, deps);
  return { stdout: "" };
}
