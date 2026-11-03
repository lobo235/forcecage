/**
 * Builds the Tripwire's World at session start: known values from this host's env and credential
 * files, Canaries from a private per-host state file, and the untrusted tool list.
 *
 * Configuration is GLOBAL only (`~/.config/forcecage/tripwire.json` by default, overridable per
 * load via `configPath`). There is deliberately no project config: a repo that could switch its
 * own Tripwire off is the self-exemption hole the operator's stack closes everywhere else.
 *
 * The shared core has no opinion about which providers are "local" (the tier 1 exemption for
 * provider requests): each agent adapter supplies `localProviders`, and the default is empty.
 */
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { Secret, World } from "./core.ts";
import { envValues, isCredentialLike, jsonValues, textValues } from "./sources.ts";

export const DEFAULT_UNTRUSTED_TOOLS = ["web_fetch", "web_search", "mcp__chrome_devtools", "marshal_messages"];
/** Relative to $HOME. A `*` matches within one directory level only. */
export const DEFAULT_FILES = [
  ".config/llm/*-token",
  ".pi-wiki-token",
  ".vault-token",
  ".netrc",
  ".npmrc",
  ".config/gh/hosts.yml",
  ".pi/agent/auth.json",
  ".claude.json",
];

export const DEFAULT_CONFIG = "~/.config/forcecage/tripwire.json";
export const DEFAULT_STATE_DIR = "~/.local/state/forcecage/tripwire";

export interface LoadOptions {
  home: string;
  env: NodeJS.ProcessEnv;
  /** Where the per-host Canary file lives; default ~/.local/state/forcecage/tripwire. */
  stateDir?: string;
  /** The global config file; default ~/.config/forcecage/tripwire.json. */
  configPath?: string;
  /** Providers whose requests are never rewritten (tier 1). Adapter-specific; default none. */
  localProviders?: readonly string[];
}

export interface Loaded {
  world: World;
  /** Sources that exist but could not be read; never a value. */
  problems: string[];
}

interface Config {
  files: string[];
  untrustedTools: string[];
}

function readConfig(home: string, configPath: string, problems: string[]): Config {
  const file = configPath.startsWith("~/") ? path.join(home, configPath.slice(2)) : configPath;
  try {
    const raw = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<Config>;
    const strings = (list: unknown) => (Array.isArray(list) ? list.filter((item) => typeof item === "string") : []);
    return { files: strings(raw.files), untrustedTools: strings(raw.untrustedTools) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") problems.push(`${configPath}: ${errorKind(error)}`);
    return { files: [], untrustedTools: [] };
  }
}

/** Absolute paths for one configured entry, expanding `~/` and a single-level `*`. */
function expand(home: string, entry: string): string[] {
  const absolute = entry.startsWith("~/") ? path.join(home, entry.slice(2)) : path.isAbsolute(entry) ? entry : path.join(home, entry);
  const base = path.basename(absolute);
  if (!base.includes("*")) return [absolute];
  const [prefix, suffix] = base.split("*", 2);
  const dir = path.dirname(absolute);
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((name) => name.startsWith(prefix) && name.endsWith(suffix))
    .map((name) => path.join(dir, name));
}

function fileValues(file: string, problems: string[], display: string): string[] {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > 4 * 1024 * 1024) {
      problems.push(`${display}: ${stat.isFile() ? "over 4 MB, skipped" : "not a regular file, skipped"}`);
      return [];
    }
    const text = fs.readFileSync(file, "utf8");
    return file.endsWith(".json") ? jsonValues(text) : textValues(text);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") problems.push(`${display}: ${(error as NodeJS.ErrnoException).code ?? "unreadable"}`);
    return [];
  }
}

function displayPath(home: string, file: string): string {
  return file.startsWith(home + path.sep) ? `~/${path.relative(home, file)}` : file;
}

function mintCanaries(): Secret[] {
  const alnum = (count: number, alphabet: string) =>
    [...randomBytes(count)].map((byte) => alphabet[byte % alphabet.length]).join("");
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const mixed = upper + "abcdefghijklmnopqrstuvwxyz";
  return [
    { label: "canary AWS key", value: `AKIA${alnum(16, upper)}`, kind: "canary" },
    { label: "canary GitHub token", value: `ghp_${alnum(36, mixed)}`, kind: "canary" },
    { label: "canary API key", value: `sk-${alnum(40, mixed)}`, kind: "canary" },
  ];
}

/** An error's kind, never its message: a JSON parse error quotes the text it choked on. */
function errorKind(error: unknown): string {
  const code = (error as NodeJS.ErrnoException).code;
  return code ?? (error instanceof Error ? error.name : "unreadable");
}

function readCanaries(file: string): Secret[] {
  const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as Array<{ label?: unknown; value?: unknown }>;
  return parsed
    .filter((item) => typeof item.label === "string" && typeof item.value === "string")
    .map((item) => ({ label: item.label as string, value: item.value as string, kind: "canary" as const }));
}

/**
 * This host's Canaries, minted on first use into a 0600 file. Minting writes a private temp file
 * and hard-links it into place, so a session starting at the same moment never reads a half-written
 * file, and the one that loses the race reads the winner's Canaries instead of failing.
 */
function loadCanaries(stateDir: string, problems: string[]): Secret[] {
  const file = path.join(stateDir, "canaries.json");
  try {
    return readCanaries(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      problems.push(`canaries: ${errorKind(error)}`);
      return [];
    }
  }
  const canaries = mintCanaries();
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const temp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}`;
  fs.writeFileSync(temp, JSON.stringify(canaries.map(({ label, value }) => ({ label, value }))), { mode: 0o600, flag: "wx" });
  try {
    fs.linkSync(temp, file);
    return canaries;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    return readCanaries(file);
  } finally {
    fs.unlinkSync(temp);
  }
}

export function loadWorld(options: LoadOptions): Loaded {
  const { home, env } = options;
  const problems: string[] = [];
  const config = readConfig(home, options.configPath ?? DEFAULT_CONFIG, problems);
  const byValue = new Map<string, Secret>();
  const add = (value: string, label: string, kind: Secret["kind"]) => {
    if (isCredentialLike(value) && !byValue.has(value)) byValue.set(value, { label, value, kind });
  };
  for (const canary of loadCanaries(options.stateDir ?? path.join(home, DEFAULT_STATE_DIR.slice(2)), problems)) {
    add(canary.value, canary.label, "canary");
  }
  for (const { name, value } of envValues(env)) add(value, `env ${name}`, "known");
  for (const entry of [...DEFAULT_FILES, ...config.files]) {
    for (const file of expand(home, entry)) {
      const display = displayPath(home, file);
      for (const value of fileValues(file, problems, display)) add(value, `file ${display}`, "known");
    }
  }
  const world: World = {
    secrets: [...byValue.values()],
    localProviders: new Set(options.localProviders ?? []),
    untrustedTools: new Set([...DEFAULT_UNTRUSTED_TOOLS, ...config.untrustedTools]),
  };
  return { world, problems };
}
