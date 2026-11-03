#!/usr/bin/env node
// The Forcecage tripwire as a Claude Code / Codex hook (ADR-0044): `tripwire-hook claude|codex`,
// the hook payload on stdin, the hook's answer on stdout. Logic: hook.ts via hook-main.ts.
import { readFileSync } from "node:fs";
import { main } from "../hook-main.ts";

let input = "";
try {
  input = readFileSync(0, "utf8");
} catch {
  input = "";
}
const result = main(process.argv.slice(2), input, process.env);
if (result.stderr) process.stderr.write(result.stderr);
if (result.stdout) process.stdout.write(result.stdout);
process.exitCode = result.code;
