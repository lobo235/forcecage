# Architecture Decision Records

Each ADR records a decision that is hard to reverse, surprising without
context, and the result of a real trade-off. Anything lighter is a design
note in `docs/` or a comment in the code.

## Provenance

Forcecage was extracted from the operator's own agent workstation (a
private deployment that predates this repo) in November 2026. The three
ADRs here are the extracted and generified forms of that deployment's
ADRs 0042, 0043 and 0044:

| Forcecage | origin ADR | Date |
|---|---|---|
| 0001 — secretless Sandbox + credential-injecting Egress gate | ADR-0042 (v2) | 2026-10-24 |
| 0002 — unprivileged Agent user | ADR-0043 (v2) | 2026-10-24 |
| 0003 — sandboxed launches, leased credentials, one approval channel | ADR-0044 (v1) | 2026-10-31 |

The original ADRs (with their deployment-specific consequences — the
pane-script layout, the provisioning ownership split, the specific
launchers) stay in the source deployment's own wiki; the full decision
history lives there.
New forcecage-native decisions are numbered from 0004.

The pi tripwire **extension** (the in-process detector for the `pi` agent)
was deliberately left in the source deployment during the extraction;
forcecage owns the detector **core** and the Claude/Codex **hook** forms
(see the README).
