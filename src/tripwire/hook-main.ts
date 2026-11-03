/**
 * The real ports behind `runHook`, and the process entry point `bin/tripwire-hook` calls.
 *
 * State: one JSON file per agent session under `$TRIPWIRE_HOOK_STATE_DIR` (default
 * `~/.local/state/forcecage/tripwire/hook-sessions`), 0600 in a 0700 directory, replaced atomically.
 * A state file that exists but cannot be read counts as halted: fail closed.
 *
 * Halt: the phone push and halt log the pi extension uses, plus `$ORC_TRIPWIRE_HALT_FILE` when a
 * launcher set it, so the pane can report exit 3 after the agent stops.
 */
import { readFileSync } from "node:fs";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { processPorts } from "./halt.ts";
import { runHook, type Agent, type HookDeps, type HookState } from "./hook.ts";
import { loadWorld } from "./world.ts";

function stateDir(env: NodeJS.ProcessEnv): string {
  return env.TRIPWIRE_HOOK_STATE_DIR || path.join(os.homedir(), ".local/state/forcecage/tripwire/hook-sessions");
}

function readState(dir: string, sessionId: string): HookState {
  const file = path.join(dir, `${sessionId}.json`);
  let raw: string;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { exposure: { entries: [] }, halted: false };
    return { exposure: { entries: [] }, halted: true };
  }
  try {
    const parsed = JSON.parse(raw) as HookState;
    if (typeof parsed.halted !== "boolean" || !Array.isArray(parsed.exposure?.entries)) throw new Error("shape");
    return parsed;
  } catch {
    return { exposure: { entries: [] }, halted: true };
  }
}

function writeState(dir: string, sessionId: string, state: HookState): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, `${sessionId}.json`);
  const temp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(state), { mode: 0o600 });
  fs.renameSync(temp, file);
}

function attempt(step: () => void): void {
  try {
    step();
  } catch {
    // a failed push, log or marker must never stop the Halt itself
  }
}

/** The nearest ancestor process named `codex`, or undefined. Linux /proc only. */
export function codexAncestor(start: number, procRoot = "/proc"): number | undefined {
  let pid = start;
  for (let depth = 0; depth < 8 && pid > 1; depth++) {
    let stat: string;
    try {
      stat = readFileSync(path.join(procRoot, String(pid), "stat"), "utf8");
    } catch {
      return undefined;
    }
    const close = stat.lastIndexOf(")");
    const name = stat.slice(stat.indexOf("(") + 1, close);
    if (name === "codex") return pid;
    pid = Number(stat.slice(close + 2).split(" ")[1]);
  }
  return undefined;
}

export function realDeps(env: NodeJS.ProcessEnv): HookDeps {
  const dir = stateDir(env);
  const ports = processPorts();
  return {
    world: () => loadWorld({ home: os.homedir(), env }).world,
    readState: (id) => readState(dir, id),
    writeState: (id, state) => writeState(dir, id, state),
    halt: (reason) => {
      attempt(() => ports.push("Tripwire halt", reason));
      attempt(() => ports.log({ time: new Date().toISOString(), mode: "hook", reason, outcome: "halt" }));
      attempt(() => process.stderr.write(`TRIPWIRE HALT: ${reason}\n`));
      const marker = env.ORC_TRIPWIRE_HALT_FILE;
      if (marker) attempt(() => fs.writeFileSync(marker, `${reason}\n`, { mode: 0o600 }));
    },
    stopAgent: () => {
      const pid = codexAncestor(process.ppid);
      if (pid !== undefined) attempt(() => process.kill(pid, "SIGTERM"));
    },
  };
}

/** Malformed input: deny whatever it was. Both agents read a PreToolUse deny; others ignore it. */
const DENY_UNREADABLE = JSON.stringify({
  hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "Tripwire: unreadable hook input, failing closed" },
});

export function main(argv: readonly string[], input: string, env: NodeJS.ProcessEnv): { stdout: string; code: number; stderr?: string } {
  const agent = argv[0];
  if (agent !== "claude" && agent !== "codex") return { stdout: "", code: 2, stderr: "usage: tripwire-hook claude|codex < hook-payload.json\n" };
  let payload: unknown;
  try {
    payload = JSON.parse(input);
  } catch {
    return { stdout: DENY_UNREADABLE, code: 0 };
  }
  return { ...runHook(agent as Agent, payload, realDeps(env)), code: 0 };
}
