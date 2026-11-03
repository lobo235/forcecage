/**
 * The generic tier: credential SHAPES with no known value behind them. A match refuses only the
 * call that carries it (ADR-0041); it is never proof, so it never halts.
 *
 * Families follow pi-redact 0.1.0 (MIT, reviewed 2026-10-24), extended with Vault, Docker and npm.
 * Deliberately absent: 40-hex tokens (code-hosting PATs look like git SHAs) and UUIDs (orchestrator
 * and service-mesh tokens look like every other id). Their known values are caught by the exact tier.
 *
 * A pattern whose body class holds `-` starts with a lookbehind on that class, not `\b`: `\b`
 * succeeds before every `eyJ` that follows a `-`, so a run of `eyJ-` made each start rescan the run
 * (quadratic; 100 KB took 2.6 s). The lookbehind admits only the run's first position.
 */

export interface Pattern {
  family: string;
  regex: RegExp;
}

export const PATTERNS: readonly Pattern[] = [
  // The whole block, to its END line or the end of the text: redacting only the BEGIN line left the key body.
  { family: "private key", regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)/ },
  { family: "GitHub token", regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})/ },
  { family: "Anthropic key", regex: /(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{32,}/ },
  { family: "OpenAI-style key", regex: /(?<![A-Za-z0-9_-])sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}/ },
  { family: "Slack token", regex: /(?<![A-Za-z0-9_-])xox[abprs]-[A-Za-z0-9-]{20,}/ },
  { family: "Google API key", regex: /\bAIza[A-Za-z0-9_-]{35}\b/ },
  { family: "AWS access key", regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { family: "Vault token", regex: /(?<![A-Za-z0-9_-])hv[sbr]\.[A-Za-z0-9_-]{24,}/ },
  { family: "Docker token", regex: /(?<![A-Za-z0-9_-])dckr_pat_[A-Za-z0-9_-]{24,}/ },
  { family: "npm token", regex: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { family: "JWT", regex: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}/ },
];

/** The families present in `texts`, in PATTERNS order, each once. */
export function matchFamilies(texts: readonly string[]): string[] {
  return PATTERNS.filter((pattern) => texts.some((text) => pattern.regex.test(text))).map((pattern) => pattern.family);
}

/** `text` with every credential shape replaced by a marker naming its family. */
export function redactFamilies(text: string): { text: string; families: string[] } {
  const families: string[] = [];
  let out = text;
  for (const pattern of PATTERNS) {
    const global = new RegExp(pattern.regex.source, "g");
    if (!global.test(out)) continue;
    families.push(pattern.family);
    out = out.replace(global, `[REDACTED ${pattern.family}]`);
  }
  return { text: out, families };
}
