/**
 * Where the Tripwire's known values and Canaries come from, through `loadWorld` alone, against a
 * fake home directory. Temp dirs live under the OS temp dir and are left for it to clear.
 */
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { loadWorld } from "./world.ts";

function fakeHome(files: Record<string, string>): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "tripwire-home-"));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(home, rel)), { recursive: true });
    fs.writeFileSync(path.join(home, rel), body, { mode: 0o600 });
  }
  return home;
}

const labelsOf = (home: string, env: NodeJS.ProcessEnv = {}) =>
  new Map(loadWorld({ home, env }).world.secrets.map((secret) => [secret.value, secret.label]));

test("credential-named env vars become known values; short, path-like and unrelated ones do not", () => {
  const labels = labelsOf(fakeHome({}), {
    EXAMPLE_MCP_TOKEN: "hm-0123456789abcdef",
    OLLAMA_API_KEY: "ollama-abcdef0123456789",
    SHORT_TOKEN: "abc",
    TOKEN_FILE: "/home/someone/.config/llm/token",
    EDITOR: "vim-with-a-long-name-here",
  });
  assert.equal(labels.get("hm-0123456789abcdef"), "env EXAMPLE_MCP_TOKEN");
  assert.equal(labels.get("ollama-abcdef0123456789"), "env OLLAMA_API_KEY");
  assert.equal(labels.has("abc"), false);
  assert.equal(labels.has("/home/someone/.config/llm/token"), false);
  assert.equal(labels.has("vim-with-a-long-name-here"), false);
});

test("token files, JSON credential files and key=value files become known values", () => {
  const home = fakeHome({
    ".config/llm/example-token": "sk-litellm-0123456789abcdef\n",
    ".pi-wiki-token": "wiki-0123456789abcdef",
    ".pi/agent/auth.json": JSON.stringify({ "ollama-cloud": { type: "api_key", key: "oc-0123456789abcdef" } }),
    ".claude.json": JSON.stringify({ projects: { "/home/x/dev/a-long-project-path": {} }, mcpServers: { wiki: { headers: { Authorization: "Bearer wk-0123456789abcdef" } } } }),
    ".npmrc": "//registry.npmjs.org/:_authToken=npm-0123456789abcdef\n",
    ".config/gh/hosts.yml": "github.com:\n    oauth_token: gho-0123456789abcdef\n    user: someone\n",
  });
  const labels = labelsOf(home);
  assert.equal(labels.get("sk-litellm-0123456789abcdef"), "file ~/.config/llm/example-token");
  assert.equal(labels.get("wiki-0123456789abcdef"), "file ~/.pi-wiki-token");
  assert.equal(labels.get("oc-0123456789abcdef"), "file ~/.pi/agent/auth.json");
  assert.equal(labels.get("wk-0123456789abcdef"), "file ~/.claude.json");
  assert.equal(labels.get("npm-0123456789abcdef"), "file ~/.npmrc");
  assert.equal(labels.get("gho-0123456789abcdef"), "file ~/.config/gh/hosts.yml");
  assert.equal(labels.has("/home/x/dev/a-long-project-path"), false, "a JSON key that is not credential-named is not a secret");
});

test("the global config adds files and untrusted tools; there is no repo-level config", () => {
  const home = fakeHome({
    ".config/forcecage/tripwire.json": JSON.stringify({ files: ["~/secrets/extra-token"], untrustedTools: ["my_fetch"] }),
    "secrets/extra-token": "extra-0123456789abcdef",
  });
  const { world } = loadWorld({ home, env: {} });
  assert.equal(world.secrets.some((secret) => secret.value === "extra-0123456789abcdef"), true);
  assert.equal(world.untrustedTools.has("my_fetch"), true);
  assert.equal(world.untrustedTools.has("web_fetch"), true, "the defaults stay");
});

test("Canaries are minted once per host into a private state file, then reused", () => {
  const home = fakeHome({});
  const stateDir = path.join(home, "state");
  const first = loadWorld({ home, env: {}, stateDir }).world.secrets.filter((secret) => secret.kind === "canary");
  const second = loadWorld({ home, env: {}, stateDir }).world.secrets.filter((secret) => secret.kind === "canary");
  assert.ok(first.length >= 2);
  assert.deepEqual(second, first);
  assert.equal(fs.statSync(path.join(stateDir, "canaries.json")).mode & 0o077, 0);
});

test("the same value from two sources is one secret, and missing files are not an error", () => {
  const home = fakeHome({ ".pi-wiki-token": "dup-0123456789abcdef" });
  const loaded = loadWorld({ home, env: { WIKI_MCP_TOKEN: "dup-0123456789abcdef" } });
  assert.equal(loaded.world.secrets.filter((secret) => secret.value === "dup-0123456789abcdef").length, 1);
  assert.deepEqual(loaded.problems, []);
});

test("a JSON key that merely contains a credential word, and a date, are not secrets", () => {
  const home = fakeHome({ ".claude.json": JSON.stringify({ claudeCodeFirstTokenDate: "2026-01-02T03:04:05.678Z", tokenDisplayName: "my-display-name-x", oauth: { refreshToken: "rt-0123456789abcdef" } }) });
  const labels = labelsOf(home, { LAST_TOKEN_ROTATION: "2026-01-02T03:04:05Z" });
  assert.deepEqual([...labels.keys()].filter((value) => !value.startsWith("AKIA") && !value.startsWith("ghp_") && !value.startsWith("sk-")), ["rt-0123456789abcdef"]);
});

test("a corrupt Canary file is reported by error kind only, never by its contents", () => {
  const home = fakeHome({ "state/canaries.json": "AKIAQ7SECRETFRAGMENT is not json" });
  const { problems } = loadWorld({ home, env: {}, stateDir: path.join(home, "state") });
  assert.equal(problems.length, 1);
  assert.equal(problems.join(" ").includes("Q7SEC"), false);
});

test("two sessions starting together on a fresh host end up with the same Canaries, and neither fails", async () => {
  const home = fakeHome({});
  const stateDir = path.join(home, "state");
  const { fork } = await import("node:child_process");
  const script = `import { loadWorld } from ${JSON.stringify(path.resolve("world.ts"))};
    const loaded = loadWorld({ home: ${JSON.stringify(home)}, env: {}, stateDir: ${JSON.stringify(stateDir)} });
    process.send(loaded.world.secrets.filter((s) => s.kind === "canary").map((s) => s.value).join(","));`;
  const runs = Array.from({ length: 20 }, () => new Promise<string>((resolve, reject) => {
    const child = fork("--input-type=module", [], { execArgv: ["--input-type=module", "-e", script], stdio: ["ignore", "ignore", "pipe", "ipc"] });
    let stderr = "";
    child.stderr!.on("data", (chunk) => (stderr += chunk));
    child.on("message", (message) => resolve(String(message)));
    child.on("exit", (code) => code !== 0 && reject(new Error(`exit ${code}: ${stderr.split("\n")[0]}`)));
  }));
  const seen = await Promise.all(runs);
  assert.equal(new Set(seen).size, 1, "every session holds the same Canaries");
  assert.ok(seen[0].length > 0);
});

test("a credential path that is not a regular file is reported, not silently skipped", () => {
  const home = fakeHome({});
  fs.mkdirSync(path.join(home, ".netrc"));
  const { problems } = loadWorld({ home, env: {}, stateDir: path.join(home, "state") });
  assert.deepEqual(problems, ["~/.netrc: not a regular file, skipped"]);
});
