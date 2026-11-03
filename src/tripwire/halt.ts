/**
 * Halt delivery (CONTEXT.md *Halt*, ADR-0041): loud, by Driver.
 *
 * Every Halt pushes to the operator's phone first, so an unattended pane still reaches someone,
 * and is logged without values. Then, in the TUI, the operator chooses, with Halt as the default
 * (pi's `confirm` defaults to Yes, so it is `select`); headless, the session stops with exit 3.
 *
 * pi 1.3.0 needs the whole recipe for a non-zero exit (probe 2026-10-24): `ctx.shutdown()` alone
 * is a no-op in print and json mode, and print mode's abort path overwrites `process.exitCode`,
 * hence the exit hook that sets it again last.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export const HALT_EXIT_CODE = 3;
const HALT_CHOICE = "Halt the session";
const BLOCK_CHOICE = "Block this call and keep going";

export interface HaltPorts {
  writeStderr(text: string): void;
  setExitCode(code: number): void;
  onExit(handler: () => void): void;
  push(title: string, body: string): void;
  log(record: Record<string, unknown>): void;
}

export interface HaltContext {
  mode: string;
  abort(): void;
  shutdown(): void;
  ui: { select(title: string, options: string[]): Promise<string | undefined> };
}

/** Runs one delivery step; a step that fails must never stop the steps after it. */
function attempt(step: () => void): void {
  try {
    step();
  } catch {
    // a failed push, log or stderr write cannot be reported anywhere better; the Halt goes on
  }
}

/**
 * "halt": the session is stopping. "block": the operator kept the session; block only this call.
 * Never rejects: a caller that saw a rejection would fail open (pi sends a provider payload
 * unredacted when its handler throws), so every side effect is attempted on its own.
 */
export async function deliverHalt(reason: string, ctx: HaltContext, ports: HaltPorts): Promise<"halt" | "block"> {
  attempt(() => ports.push("Tripwire halt", reason));
  let outcome: "halt" | "block" = "halt";
  if (ctx.mode === "tui") {
    try {
      if ((await ctx.ui.select(`TRIPWIRE: ${reason}`, [HALT_CHOICE, BLOCK_CHOICE])) === BLOCK_CHOICE) outcome = "block";
    } catch {
      outcome = "halt"; // a dialog that cannot be shown is a dismissed dialog
    }
  }
  attempt(() => ports.log({ time: new Date().toISOString(), mode: ctx.mode, reason, outcome }));
  if (outcome === "block") return outcome;
  attempt(() => ports.setExitCode(HALT_EXIT_CODE));
  attempt(() => ports.onExit(() => ports.setExitCode(HALT_EXIT_CODE)));
  attempt(() => ports.writeStderr(`\nTRIPWIRE HALT: ${reason}. The session is stopped (exit ${HALT_EXIT_CODE}).\n`));
  attempt(() => ctx.abort());
  attempt(() => ctx.shutdown());
  return outcome;
}

/** The real ports: this process, moshi-hook for the push, and a JSONL log beside the Canaries. */
export function processPorts(stateDir = path.join(os.homedir(), ".local/state/forcecage/tripwire")): HaltPorts {
  return {
    writeStderr: (text) => void process.stderr.write(text),
    setExitCode: (code) => void (process.exitCode = code),
    onExit: (handler) => void process.on("exit", handler),
    push: (title, body) => {
      const child = spawn("moshi-hook", ["notify", "--error", "--source", "tripwire", "--title", title, body], { stdio: "ignore", detached: true });
      child.on("error", () => undefined); // no moshi-hook on this host: stderr and the log still carry the Halt
      child.unref();
    },
    log: (record) => {
      fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
      fs.appendFileSync(path.join(stateDir, "halts.jsonl"), `${JSON.stringify(record)}\n`, { mode: 0o600 });
    },
  };
}
