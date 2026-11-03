/**
 * Tripwire core (CONTEXT.md *Tripwire*, ADR-0041): one pure decision per event.
 *
 * Nothing here touches pi, the filesystem or the clock, so every rule is tested through
 * `inspect` alone. A Decision never carries a matched value: hits name the secret by label.
 */
import { matchFamilies, redactFamilies } from "./patterns.ts";
import { carries, redactSecret, shownLabel, type Secret } from "./secrets.ts";

export type { Secret } from "./secrets.ts";

export interface World {
  secrets: readonly Secret[];
  localProviders: ReadonlySet<string>;
  /** Tools whose results are untrusted content (they add to Exposure). */
  untrustedTools: ReadonlySet<string>;
}

export interface Exposure {
  readonly entries: readonly ExposureEntry[];
}

export interface ExposureEntry {
  source: string;
  round: number;
}

export const EMPTY_EXPOSURE: Exposure = { entries: [] };

export type TripEvent =
  | { kind: "tool_call"; tool: string; input: unknown; round: number }
  | { kind: "tool_result"; tool: string; texts: readonly string[]; round: number }
  /** Untrusted content that did not come from a tool, such as a Marshal message. */
  | { kind: "untrusted"; source: string; round: number }
  | { kind: "provider_request"; provider: string; payload: unknown };

export interface Hit {
  label: string;
  kind: Secret["kind"];
}

export type Action =
  | { action: "allow" }
  | { action: "refuse"; reason: string; families: string[] }
  | { action: "redact"; texts: string[]; labels: string[] }
  | { action: "rewrite"; payload: unknown; labels: string[] }
  | { action: "halt"; reason: string; hits: Hit[] };

/** What to do with one event, and the Exposure after it. */
export type Decision = Action & { exposure: Exposure };

/** Every string in a value, keys included, unescaped: JSON escaping would hide a value holding a quote. */
export function stringLeaves(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const item of value) stringLeaves(item, out);
  else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      out.push(key);
      stringLeaves(item, out);
    }
  }
  return out;
}

/** Each run of `%XX` escapes decoded on its own, so one malformed `%` elsewhere cannot hide the rest. */
function percentDecoded(text: string): string {
  return text.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => Buffer.from(run.replace(/%/g, ""), "hex").toString("utf8"));
}

/** `text` with all whitespace removed: how a wrapped encoding (`base64`, `xxd -p`, hex groups) reads joined up. */
function joined(text: string): string {
  return text.replace(/\s+/g, "");
}

/** The argument strings as sent, plus their percent-decoded and joined-up forms. */
function searchable(input: unknown): string[] {
  const out: string[] = [];
  for (const leaf of stringLeaves(input)) {
    out.push(leaf);
    if (leaf.includes("%")) out.push(percentDecoded(leaf));
    if (/\s/.test(leaf)) out.push(joined(leaf));
  }
  return out;
}

function lastSource(exposure: Exposure): string {
  const last = exposure.entries.at(-1);
  return last ? ` after untrusted content from ${last.source} (round ${last.round})` : "";
}

function inspectCall(tool: string, input: unknown, world: World, exposure: Exposure): Action {
  const texts = searchable(input);
  const hits = world.secrets.filter((secret) => carries(texts, secret)).map(({ label, kind }) => ({ label, kind }));
  if (hits.length > 0) {
    const reason = `${tool} call carries ${hits.map((hit) => hit.label).join(", ")}${lastSource(exposure)}`;
    return { action: "halt", reason, hits };
  }
  const families = matchFamilies(texts);
  if (families.length > 0) {
    const reason = `${tool} call refused: it carries what looks like a ${families.join(", ")}. Credentials are brokered, never passed in a tool call.`;
    return { action: "refuse", reason, families };
  }
  return { action: "allow" };
}

/** `text` with every secret and credential shape replaced; what was replaced goes into `labels`. */
function redactText(text: string, world: World, labels: Set<string>): string {
  let out = text;
  for (const secret of world.secrets) {
    const next = redactSecret(out, secret);
    if (next !== out) labels.add(secret.label);
    out = next;
  }
  const shapes = redactFamilies(out);
  for (const family of shapes.families) labels.add(family);
  return shapes.text;
}

/**
 * A text that still shows a secret once joined up holds it in a wrapped encoding. Positions in the
 * joined copy do not map back, so the whole text is withheld rather than patched.
 */
function withholdWrapped(text: string, world: World, labels: Set<string>): string {
  const hits = world.secrets.filter((secret) => carries([joined(text)], secret));
  if (hits.length === 0) return text;
  for (const secret of hits) labels.add(secret.label);
  return `[Tripwire: withheld; it shows ${[...new Set(hits.map(shownLabel))].join(", ")} in a wrapped encoding]`;
}

function inspectResult(texts: readonly string[], world: World): Action {
  const labels = new Set<string>();
  const redacted = texts.map((text) => withholdWrapped(redactText(text, world, labels), world, labels));
  return labels.size === 0 ? { action: "allow" } : { action: "redact", texts: redacted, labels: [...labels] };
}

/** A deep copy of `value` with every string redacted. */
function redactDeep(value: unknown, world: World, labels: Set<string>): unknown {
  if (typeof value === "string") return redactText(value, world, labels);
  if (Array.isArray(value)) return value.map((item) => redactDeep(item, world, labels));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redactDeep(item, world, labels)]));
  }
  return value;
}

function inspectRequest(provider: string, payload: unknown, world: World): Action {
  if (world.localProviders.has(provider)) return { action: "allow" };
  const labels = new Set<string>();
  const rewritten = redactDeep(payload, world, labels);
  return labels.size === 0 ? { action: "allow" } : { action: "rewrite", payload: rewritten, labels: [...labels] };
}

function exposureAfter(event: TripEvent, world: World, exposure: Exposure): Exposure {
  const add = (source: string, round: number): Exposure => ({ entries: [...exposure.entries, { source, round }] });
  if (event.kind === "untrusted") return add(event.source, event.round);
  if (event.kind === "tool_result" && world.untrustedTools.has(event.tool)) return add(`tool:${event.tool}`, event.round);
  return exposure;
}

export function inspect(event: TripEvent, world: World, exposure: Exposure): Decision {
  const next = exposureAfter(event, world, exposure);
  if (event.kind === "tool_call") return { ...inspectCall(event.tool, event.input, world, exposure), exposure: next };
  if (event.kind === "tool_result") return { ...inspectResult(event.texts, world), exposure: next };
  if (event.kind === "provider_request") return { ...inspectRequest(event.provider, event.payload, world), exposure: next };
  return { action: "allow", exposure: next };
}
