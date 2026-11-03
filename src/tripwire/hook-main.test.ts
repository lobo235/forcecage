/**
 * `bin/tripwire-hook` as a process: a private HOME, a PATH holding only node (so no phone push
 * leaves the test), and the files it leaves behind.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { codexAncestor } from "./hook-main.ts";

const BIN = fileURLToPath(new URL("./bin/tripwire-hook.ts", import.meta.url));
const TOKEN = "FAKE-hook-token-0123456789abcdef";

function home(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "tripwire-hook-"));
}

function run(agent: string, payload: unknown, dir: string, extra: Record<string, string> = {}) {
  const input = typeof payload === "string" ? payload : JSON.stringify(payload);
  const env = { PATH: path.dirname(process.execPath), HOME: dir, FAKE_HOOK_TOKEN: TOKEN, ...extra };
  return spawnSync(BIN, [agent], { input, env, encoding: "utf8" });
}

const pre = (command: string) => ({ hook_event_name: "PreToolUse", session_id: "p1", tool_name: "Bash", tool_input: { command } });

test("a Halt exits 0 with the deny, writes 0600 session state and the launcher's marker", () => {
  const dir = home();
  const marker = path.join(dir, "halt-marker");
  const result = run("claude", pre(`echo ${TOKEN}`), dir, { ORC_TRIPWIRE_HALT_FILE: marker });
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).continue, false);
  assert.match(fs.readFileSync(marker, "utf8"), /env FAKE_HOOK_TOKEN/);
  const state = path.join(dir, ".local/state/forcecage/tripwire/hook-sessions/p1.json");
  assert.equal(fs.statSync(state).mode & 0o777, 0o600);
  assert.equal(JSON.parse(fs.readFileSync(state, "utf8")).halted, true);
  assert.ok(!result.stdout.includes(TOKEN) && !result.stderr.includes(TOKEN));
});

test("unreadable input is denied, and a bad agent name is a usage error", () => {
  const dir = home();
  const denied = run("codex", "{not json", dir);
  assert.equal(denied.status, 0);
  assert.equal(JSON.parse(denied.stdout).hookSpecificOutput.permissionDecision, "deny");
  const usage = run("gemini", pre("ls"), dir);
  assert.equal(usage.status, 2);
  assert.match(usage.stderr, /usage/);
});

test("a state file that cannot be read counts as halted", () => {
  const dir = home();
  const states = path.join(dir, ".local/state/forcecage/tripwire/hook-sessions");
  fs.mkdirSync(states, { recursive: true });
  fs.writeFileSync(path.join(states, "p1.json"), "garbage");
  const result = run("claude", pre("ls"), dir);
  assert.equal(JSON.parse(result.stdout).continue, false);
});

test("codexAncestor finds the nearest codex process through a fake /proc", () => {
  const proc = fs.mkdtempSync(path.join(os.tmpdir(), "fake-proc-"));
  const stat = (pid: number, name: string, ppid: number) => {
    fs.mkdirSync(path.join(proc, String(pid)));
    fs.writeFileSync(path.join(proc, String(pid), "stat"), `${pid} (${name}) S ${ppid} 1 1 0`);
  };
  stat(30, "sh", 20);
  stat(20, "codex", 10);
  stat(10, "tmux: server", 1);
  assert.equal(codexAncestor(30, proc), 20);
  stat(40, "bash) (codex", 10);
  assert.equal(codexAncestor(40, proc), undefined, "a process name holding ') (' cannot fake a codex parent");
});
