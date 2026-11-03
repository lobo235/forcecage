/**
 * Halt delivery by Driver (ADR-0041). The process-level effects go through HaltPorts so a test can
 * observe them; the real ports, and the pi extension's behaviour under them (exit 3 in print, json,
 * rpc and tui), were proven against the real pi binary (see the operator's pi probe notes).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { HALT_EXIT_CODE, deliverHalt, type HaltPorts } from "./halt.ts";

function recorder() {
  const seen = { stderr: "", exitCode: undefined as number | undefined, onExit: 0, pushes: [] as string[], logs: [] as unknown[] };
  const ports: HaltPorts = {
    writeStderr: (text) => void (seen.stderr += text),
    setExitCode: (code) => void (seen.exitCode = code),
    onExit: () => void seen.onExit++,
    push: (title, body) => void seen.pushes.push(`${title}: ${body}`),
    log: (record) => void seen.logs.push(record),
  };
  return { seen, ports };
}

function fakeCtx(mode: string, choice?: string) {
  const calls: string[] = [];
  return {
    calls,
    ctx: {
      mode,
      hasUI: mode !== "print" && mode !== "json",
      abort: () => void calls.push("abort"),
      shutdown: () => void calls.push("shutdown"),
      ui: {
        select: async (_title: string, options: string[]): Promise<string | undefined> => (calls.push(`select ${options[0]}`), choice ?? options[0]),
      },
    },
  };
}

test("headless: a loud stderr line, exit code 3 that survives pi's own exit path, abort, shutdown, a push and a log", async (t) => {
  for (const mode of ["print", "json", "rpc"]) {
    await t.test(mode, async () => {
      const { seen, ports } = recorder();
      const { calls, ctx } = fakeCtx(mode);
      assert.equal(await deliverHalt("bash call carries example token", ctx, ports), "halt");
      assert.match(seen.stderr, /TRIPWIRE HALT.*bash call carries example token/);
      assert.equal(seen.exitCode, HALT_EXIT_CODE);
      assert.equal(seen.onExit, 1);
      assert.deepEqual(calls, ["abort", "shutdown"]);
      assert.equal(seen.pushes.length, 1);
      assert.equal(seen.logs.length, 1);
    });
  }
});

test("tui: the operator is asked with Halt as the default, and Halt stops the session", async () => {
  const { seen, ports } = recorder();
  const { calls, ctx } = fakeCtx("tui");
  assert.equal(await deliverHalt("write call carries canary AWS key", ctx, ports), "halt");
  assert.deepEqual(calls, ["select Halt the session", "abort", "shutdown"]);
  assert.equal(seen.pushes.length, 1, "pushed before asking, so an unattended pane still reaches the operator");
  assert.equal(seen.exitCode, HALT_EXIT_CODE);
});

test("tui: the operator may block only this call and keep the session", async () => {
  const { seen, ports } = recorder();
  const { calls, ctx } = fakeCtx("tui", "Block this call and keep going");
  assert.equal(await deliverHalt("r", ctx, ports), "block");
  assert.deepEqual(calls, ["select Halt the session"]);
  assert.equal(seen.exitCode, undefined);
  assert.equal(seen.logs.length, 1);
});

test("tui: a dismissed dialog halts", async () => {
  const { ports } = recorder();
  const { ctx } = fakeCtx("tui");
  ctx.ui.select = async () => undefined;
  assert.equal(await deliverHalt("r", ctx, ports), "halt");
});

test("a Halt still stops the session when the push, the log, stderr, the exit hook or the dialog fails", async (t) => {
  for (const mode of ["print", "tui"]) {
    await t.test(mode, async () => {
      let exitCode: number | undefined;
      const boom = () => { throw new Error("EIO"); };
      const ports: HaltPorts = { writeStderr: boom, setExitCode: (code) => void (exitCode = code), onExit: boom, push: boom, log: boom };
      const calls: string[] = [];
      const ctx = {
        mode,
        abort: () => { calls.push("abort"); throw new Error("abort failed"); },
        shutdown: () => void calls.push("shutdown"),
        ui: { select: async (): Promise<string | undefined> => { throw new Error("no UI"); } },
      };
      assert.equal(await deliverHalt("r", ctx, ports), "halt");
      assert.equal(exitCode, HALT_EXIT_CODE);
      assert.deepEqual(calls, ["abort", "shutdown"]);
    });
  }
});
