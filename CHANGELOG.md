# Changelog

All notable changes to forcecage are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com),
and this project adheres to [Semantic Versioning](https://semver.org).

## [v0.1.0] - 2026-11-04

The first release: the whole force field, extracted from a private
deployment and genericized as a standalone open-source project. An agent
command — `pi`, `claude`, `codex`, or anything else — is run inside a
**secretless bwrap sandbox** whose only network route is a
**credential-injecting egress gate**, with an **approval service** for new
destinations and a **tripwire hook** that halts the session when a known
credential value or a planted canary is seen leaving. The agent never holds
a real credential; the gate swaps the real value in, per destination.

### Added

- **The cage** — the `forcecage` Python package (`src/cage`, stdlib-only,
  Python 3.9+) and its `forcecage` console script:
  - `forcecage run` — the operator-side orchestrator: starts the gate, hops
    to the unprivileged Agent user, builds the sandbox, runs the grant
    service, wires the tripwire, and maps a Halt to exit 3. The agent
    command after `--` is opaque to forcecage. `--bindings` and
    `--state-dir` (isolates the gate for concurrent runs) override the
    config.
  - `forcecage check` — verifies the host prerequisites (bwrap, user
    namespaces, iron-proxy presence + pinned sha256) and fails hard;
    `--bindings` also validates a bindings file.
  - `forcecage sandbox` — the bwrap Sandbox builder: allow-list `$HOME`, the
    clone the only writable tree, network only through the gate.
  - `forcecage gate` — the credential-injecting Egress gate: per-destination
    MITM placeholder→real swap (wraps iron-proxy 0.53.0), JSON audit,
    inert catch-all.
  - `forcecage grant` — the Grant lease service: minted/leased credentials
    through one approval channel (a file-based request/reply queue); applies,
    expires and alerts, never asks the operator itself.
  - `forcecage tripwire-hook claude|codex` — a thin process-boundary exec of
    the tripwire hook; the detector logic has one owner.
  - **Minter interface** — static file/env minter (no server, the zero-
    dependency quickstart) and a pluggable Vault AppRole minter (dynamic
    leases).
  - `forcecage.toml` config (a stdlib-only TOML-subset parser) for stable
    install settings, with per-session bindings as a separate file.

- **The tripwire** — the agent-agnostic detector core plus the Claude Code /
  Codex hook, published as the `@forcecage/tripwire` npm package
  (`src/tripwire`, TypeScript, Node 23.6+, no agent runtime imported):
  - The two-tier credential detector: a known credential value or a planted
    Canary halts the session (exit 3); a generic secret pattern refuses only
    that one call. Matching covers percent, base64, base64url and hex
    spellings, wrapped or not.
  - The `tripwire-hook` bin (the `tripwire-hook` npm executable) reads a hook
    payload on stdin in the agent's own dialect.
  - `index.ts` re-exports the decision (`inspect`), the World builder
    (`loadWorld`), Exposure persistence (`readExposure`) and Halt delivery
    (`deliverHalt`), so a host's in-process extension builds on the same
    core.
  - A 98-test suite (`node --test` + `tsc`) running in CI on Node 24.

- **Config examples** — `config/forcecage.toml.example` and
  `config/bindings.example.json`.

- **Tests** — Python unit + integration suites (integration skips gracefully
  when iron-proxy / Vault are absent) and a **native host e2e**
  (`tests/forcecage-e2e.test.sh`): a fake agent runs unprivileged inside
  bwrap, all egress goes through the gate, and the real credential never
  reaches agent-side output.

- **CI** — a Python 3.9+ matrix plus the Node tripwire suite
  (`.github/workflows/ci.yml`, pinned to `ubuntu-24.04` so the 3.9 artifact
  resolves).

- **Docs** — the domain glossary (`CONTEXT.md`) and the design decisions
  (`docs/adr/` 0001-0003), rewritten generic from their source-deployment
  provenance with a provenance note.

- **License** — MIT. The egress gate depends on iron-proxy (Apache-2.0).
