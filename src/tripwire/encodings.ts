/**
 * The spellings a secret can take in a tool call without being typed verbatim: base64 and
 * base64url at each of the three byte alignments it can sit at inside a larger blob, and hex
 * (the one case-insensitive spelling, so it is kept apart).
 * Percent-encoding is handled the other way round, by decoding the argument (see core.ts),
 * because %2b and %2B are the same byte.
 */

/** The base64 characters that depend only on `value`'s bytes, when `value` sits `offset` bytes into a blob. */
function alignedBase64(value: Buffer, offset: number): string {
  const encoded = Buffer.concat([Buffer.alloc(offset), value]).toString("base64").replace(/=+$/, "");
  const first = Math.ceil((offset * 8) / 6);
  const last = Math.floor(((offset + value.length) * 8) / 6);
  return encoded.slice(first, last);
}

export function encodedSpellings(value: string): string[] {
  const bytes = Buffer.from(value, "utf8");
  const spellings = new Set<string>();
  for (const offset of [0, 1, 2]) {
    const base64 = alignedBase64(bytes, offset);
    spellings.add(base64);
    spellings.add(base64.replace(/\+/g, "-").replace(/\//g, "_"));
  }
  spellings.delete(value);
  return [...spellings];
}

/** Lower-case hex; compare it against a lower-cased argument. */
export function hexSpelling(value: string): string {
  return Buffer.from(value, "utf8").toString("hex");
}
