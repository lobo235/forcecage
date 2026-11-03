/** Exposure's persisted form: what the Tripwire appends and what cues (or a resumed session) reads back. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { EXPOSURE_ENTRY_TYPE, readExposure } from "./exposure.ts";

test("readExposure rebuilds Exposure from the Tripwire's own custom entries, in order, ignoring everything else", () => {
  const entries = [
    { type: "message", message: { role: "user" } },
    { type: "custom", customType: EXPOSURE_ENTRY_TYPE, data: { source: "tool:web_fetch", round: 2 } },
    { type: "custom", customType: "compaction-state.event", data: { source: "x", round: 9 } },
    { type: "custom", customType: EXPOSURE_ENTRY_TYPE, data: { source: "marshal-channel", round: 7 } },
  ];
  assert.deepEqual(readExposure(entries).entries, [
    { source: "tool:web_fetch", round: 2 },
    { source: "marshal-channel", round: 7 },
  ]);
});

test("a malformed Tripwire entry is skipped, not trusted", () => {
  const entries = [
    { type: "custom", customType: EXPOSURE_ENTRY_TYPE, data: { source: 42 } },
    { type: "custom", customType: EXPOSURE_ENTRY_TYPE },
    null,
  ];
  assert.deepEqual(readExposure(entries as unknown[]).entries, []);
});
