/**
 * Exposure's persisted form (CONTEXT.md *Exposure*). The Tripwire appends one custom entry per
 * untrusted arrival with `pi.appendEntry`, which pi keeps out of the model's context, and rebuilds
 * Exposure from the session branch on start. The cues extension reads it the same way.
 */
import type { Exposure, ExposureEntry } from "./core.ts";

export const EXPOSURE_ENTRY_TYPE = "tripwire.exposure";

function asEntry(data: unknown): ExposureEntry | undefined {
  if (data === null || typeof data !== "object") return undefined;
  const { source, round } = data as Record<string, unknown>;
  return typeof source === "string" && typeof round === "number" ? { source, round } : undefined;
}

export function readExposure(entries: Iterable<unknown>): Exposure {
  const out: ExposureEntry[] = [];
  for (const entry of entries) {
    if (entry === null || typeof entry !== "object") continue;
    const { type, customType, data } = entry as Record<string, unknown>;
    if (type !== "custom" || customType !== EXPOSURE_ENTRY_TYPE) continue;
    const parsed = asEntry(data);
    if (parsed) out.push(parsed);
  }
  return { entries: out };
}
