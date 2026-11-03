/**
 * Readers that pull credential VALUES out of the places this host keeps them: env vars, token
 * files, JSON credential files and key=value files. Each returns candidate values only; world.ts
 * labels, filters and de-duplicates them. Nothing here ever prints a value.
 */

const SECRET_ENV_NAME = /TOKEN|SECRET|PASSW(OR)?D|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|(^|_)KEY(_|$)/i;
/** Anchored at the end: `refreshToken` is a credential, `claudeCodeFirstTokenDate` is not. */
const SECRET_JSON_KEY = /(token|secret|passw(or)?d|key|authorization|credentials?)$/i;
const KEY_VALUE_LINE = /[A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|key)[A-Za-z0-9_.-]*\s*[:=]\s*["']?([^\s"']+)/gi;
const NETRC_PASSWORD = /\bpassword\s+(\S+)/g;

/** A value worth matching: long enough to be specific, and not a path, URL or sentence. */
export function isCredentialLike(value: string): boolean {
  if (value.length < 12 || /\s/.test(value)) return false;
  if (/^[/~.]/.test(value) || value.includes("://")) return false;
  if (/^\d{4}-\d{2}-\d{2}/.test(value)) return false;
  return !/^\d+$/.test(value);
}

function stripBearer(value: string): string {
  return value.replace(/^Bearer\s+/i, "");
}

export function envValues(env: NodeJS.ProcessEnv): Array<{ name: string; value: string }> {
  return Object.entries(env)
    .filter(([name, value]) => SECRET_ENV_NAME.test(name) && typeof value === "string")
    .map(([name, value]) => ({ name, value: value as string }));
}

/** String values under credential-named keys, at any depth. */
export function jsonValues(text: string): string[] {
  const out: string[] = [];
  const walk = (node: unknown, underSecretKey: boolean): void => {
    if (typeof node === "string") {
      if (underSecretKey) out.push(stripBearer(node));
    } else if (Array.isArray(node)) {
      for (const item of node) walk(item, underSecretKey);
    } else if (node !== null && typeof node === "object") {
      for (const [key, item] of Object.entries(node)) walk(item, underSecretKey || SECRET_JSON_KEY.test(key));
    }
  };
  walk(JSON.parse(text), false);
  return out;
}

/** The whole file when it is one bare line; otherwise credential-named key=value, key: value and netrc lines. */
export function textValues(text: string): string[] {
  const trimmed = text.trim();
  if (trimmed !== "" && !trimmed.includes("\n") && !/[=:\s]/.test(trimmed)) return [trimmed];
  const out: string[] = [];
  for (const match of trimmed.matchAll(KEY_VALUE_LINE)) out.push(stripBearer(match[1]));
  for (const match of trimmed.matchAll(NETRC_PASSWORD)) out.push(match[1]);
  return out;
}
