/**
 * @forcecage/tripwire — the agent-agnostic core of Forcecage's tripwire.
 *
 * The shared detector (CONTEXT.md *Tripwire*): one pure decision per event, two tiers (known
 * values / Canaries halt; generic credential shapes refuse), redaction of tool results and of
 * provider requests that are not a Local provider, and the agent-agnostic Claude Code / Codex
 * hook. Nothing here imports a specific agent runtime: the Claude Code / Codex hook ships in this
 * package, and the pi extension (in the operator's repo) builds on the same core.
 *
 * The two public entry points an agent adapter needs:
 *   - `inspect(event, world, exposure)` — the pure decision, for wiring into any agent's hooks.
 *   - `main(argv, input, env)` — the Claude Code / Codex hook process entry (see bin/tripwire-hook).
 *
 * Everything else (the detection tier, World construction, Exposure persistence, Halt delivery)
 * is exported so an adapter can compose it; a minimal pi-style integration needs
 * `loadWorld`, `inspect`, `readExposure`, `deliverHalt`, `processPorts`.
 */

// The pure decision and its event/decision types.
export {
  EMPTY_EXPOSURE,
  inspect,
  stringLeaves,
  type Action,
  type Decision,
  type Exposure,
  type ExposureEntry,
  type Hit,
  type TripEvent,
  type World,
} from "./core.ts";

// World construction: known values from this host's env + credential files, Canaries, untrusted
// tools. `localProviders` and `configPath` are adapter policy (the shared core has no opinion).
export {
  DEFAULT_CONFIG,
  DEFAULT_FILES,
  DEFAULT_STATE_DIR,
  DEFAULT_UNTRUSTED_TOOLS,
  loadWorld,
  type Loaded,
  type LoadOptions,
} from "./world.ts";

// Exposure's persisted form: the custom-entry reader and the entry-type constant.
export { EXPOSURE_ENTRY_TYPE, readExposure } from "./exposure.ts";

// Halt delivery: the pure-ish `deliverHalt` plus the process-backed ports (push, log, exit code).
export {
  HALT_EXIT_CODE,
  deliverHalt,
  processPorts,
  type HaltContext,
  type HaltPorts,
} from "./halt.ts";

// The agent-agnostic Claude Code / Codex hook: `runHook` for in-process use, `main` for the
// process entry, and the real ports behind it.
export { runHook, type Agent, type HookDeps, type HookReply, type HookState } from "./hook.ts";
export { codexAncestor, main, realDeps } from "./hook-main.ts";

// The detection tier, exported for composition and for tests.
export { PATTERNS, matchFamilies, redactFamilies, type Pattern } from "./patterns.ts";
export { carries, redactSecret, shownLabel, type Secret } from "./secrets.ts";
export { encodedSpellings, hexSpelling } from "./encodings.ts";
export { envValues, isCredentialLike, jsonValues, textValues } from "./sources.ts";
