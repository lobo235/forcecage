/**
 * The exact tier: finding a known value or a Canary in text, in any spelling encodings.ts
 * knows, and replacing it. Matching is case-sensitive except for hex.
 */
import { encodedSpellings, hexSpelling } from "./encodings.ts";

export interface Secret {
  /** What the operator calls it ("api token"); the only thing a Decision may show. */
  label: string;
  value: string;
  /** known: a real credential's value. canary: a planted decoy; any use is proof. */
  kind: "known" | "canary";
}

function spellingsOf(secret: Secret): string[] {
  return [secret.value, ...encodedSpellings(secret.value)];
}

export function carries(texts: readonly string[], secret: Secret): boolean {
  const spellings = spellingsOf(secret);
  const hex = hexSpelling(secret.value);
  return texts.some((text) => spellings.some((spelling) => text.includes(spelling)) || text.toLowerCase().includes(hex));
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The name a model may see for `secret`: its label, except that a Canary is never named as one. */
export function shownLabel(secret: Secret): string {
  return secret.kind === "canary" ? "credential" : secret.label;
}

/** `text` with every spelling of `secret` replaced by a marker naming it. */
export function redactSecret(text: string, secret: Secret): string {
  const marker = `[REDACTED ${shownLabel(secret)}]`;
  let out = text;
  for (const spelling of spellingsOf(secret)) out = out.split(spelling).join(marker);
  return out.replace(new RegExp(escapeRegex(hexSpelling(secret.value)), "gi"), marker);
}
