# Forcecage

*An invisible, impenetrable cube of force around your AI agent. Nothing
physical or magical gets in or out, and the creature inside can't teleport
its way free.* (Named after the D&D 5e spell.)

Forcecage is an AI safety layer for coding agents: it runs any agent
command — `pi`, `claude`, `codex`, or anything else — inside a
**secretless sandbox** whose only network route is a **credential-injecting
egress gate**, with an **approval service** for anything new the agent
wants to reach and a **tripwire hook** that halts the session when a known
credential value or a planted canary is seen leaving.

The agent works in a clone it owns, as an unprivileged user, holding only
**placeholders** where its credentials would be. The real values live in one
place the agent can't reach — a secret store or a file only the gate reads —
and are swapped in, per destination, by the gate. When the agent needs a
credential for something it can't name, it asks; the operator approves or
refuses. The agent never holds the real thing.

## Why

A coding agent that has read untrusted input (a web page, an issue, a tool
result) can exfiltrate anything it knows — its own API keys, your SSH keys,
the token file sitting in `$HOME` — by putting that value in an outbound
request. A *detector* (a tripwire) catches the values you told it about. The
structural answer is the force field:

1. **Nothing to leak.** The sandbox's filesystem is an allow list; the
   credential files are not in it. The agent's config holds stable
   placeholders, worthless anywhere.
2. **One door.** All egress goes through the gate, which is default-deny and
   swaps in real values only for the destinations each credential is bound
   to. A placeholder heading anywhere else halts the session.
3. **Asking, not taking.** New destinations and leased credentials need an
   operator approval through one channel. The agent never approves itself.
4. **A detector on the door too.** The tripwire hook inspects every outbound
   tool call for known values and canaries, in each agent's own hook
   dialect.

The design history and trade-offs are in [`docs/adr/`](docs/adr/).

## How a launch works

```
operator
   │  forcecage run pi <clone> pi --model … -p "…"
   ▼
forcecage (operator user)
   ├─ gate:     iron-proxy under its own uid, default-deny,
   │            per-binding credential swap, JSON audit
   ├─ hop:      one sudoers rule → the Agent user, one fixed pane script
   ├─ sandbox:  bwrap — allow-list $HOME, the clone the only writable tree,
   │            network only through the gate
   ├─ grant:    the approval service (applies/expires/alerts, never asks)
   └─ tripwire: the agent's hook form (claude/codex dialects)
      ▼
   the agent, as the Agent user, inside the Sandbox
      - sends Bearer Placeholder-<name>; the gate swaps the real value
      - asks for a lease → one approval channel → operator decides
      - leaks a known value or a canary → Halt → exit 3
```

`forcecage` knows only the **agent type** (which tripwire form to wire) and
the **cage config**. Everything else — the agent's own flags, model,
prompts, tools — rides in the command you hand it and is treated as opaque.

## Requirements

- Linux (x86-64; ARM64 not yet tested) with usable **unprivileged user
  namespaces** (check `bwrap --ro-bind / / true` first)
- **bubblewrap**, **socat**, **setfacl**
- **Python 3.9+** (stdlib only — no pip dependencies for the cage)
- **iron-proxy 0.53.0** (Apache-2.0) on `PATH` or at a configured path; the
  pinned sha256 is checked at startup
- optional: **Vault** (dynamic credential minting) — a file/env minter
  covers static values with no server
- Node.js 23.6+, for the tripwire hook (the npm package ships TypeScript
  and runs it directly; no build step)

## Status

**Shipped.** The force field is complete. The Python `cage` package
(`src/cage`, stdlib-only) is the `forcecage` binary — the bwrap sandbox, the
credential-injecting Egress gate, the Grant service, the Minter interface and
the `forcecage run` orchestrator — and the TypeScript tripwire (`src/tripwire`)
is published as the `@forcecage/tripwire` npm package: the agent-agnostic
detector core plus the Claude Code / Codex hook. The project was extracted
from the operator's own agent workstation (a private deployment that predates
this repo, where it ran as `orc-sandbox` / `orc-gate` / `orc-grant` /
`agent-pane`), proven end-to-end across three launchers, and genericized
(see `docs/adr/README.md` for provenance). A native host e2e and a Python +
Node CI gate the package; start with the Quickstart below.

## Repository layout

- `src/cage/` — the Python cage package (`forcecage` console script, stdlib
  only).
- `src/tripwire/` — the TypeScript tripwire core and the agent-agnostic hook
  (the `@forcecage/tripwire` npm package, Node 23.6+).
- `config/` — example `forcecage.toml` and per-session bindings file.
- `tests/` — Python unit + integration suites and the native host e2e
  (`tests/forcecage-e2e.test.sh`).
- `docs/adr/` — the design decisions, rewritten generic from their
  source-deployment provenance (0001-0003).

The `forcecage` binary and the tripwire hook are the two things an external
host (or an agent harness) reaches for; everything else is their substrate.

## Quickstart

The floor is Linux with `bwrap` and unprivileged user namespaces, plus
`socat` and `setfacl`. The Egress gate needs `iron-proxy 0.53.0` on `PATH`
(or at a configured path) — see *Requirements*. The host needs an
unprivileged `agent` account and the sudoers hop `forcecage run` uses to drop
into it. The repo ships the example `forcecage.toml`, not the sudoers entry.

```sh
# 1. Install. The package is stdlib-only, so `pip install` is the whole cage.
git clone https://github.com/lobo235/forcecage
cd forcecage
python3 -m pip install -e .

# 2. Verify the host. Fails hard on anything the cage cannot run on.
forcecage check

# 3. Write a stable forcecage.toml (see config/forcecage.toml.example):
#    agent_user, the run/state dirs, the iron-proxy path + its pinned sha256,
#    the minter kind ("file" needs no server) and the tripwire state paths.

# 4. Write a per-session bindings file (see config/bindings.example.json):
#    one entry per credential — the placeholder the agent sees, the real
#    value (only the gate ever holds it), the host it may be injected for.

# 5. Cage a command. The agent command after `--` is opaque to forcecage;
#    the force field is everything around it.
forcecage run pi /home/agent/myclone /usr/local/bin/pi \
    --bindings ./bindings.json \
    -- pi --model gpt-5.5
```

`forcecage run` starts the gate, hops to the agent user, builds the bwrap
sandbox, runs the grant service, wires the tripwire and maps a Halt to exit
3. Use `--state-dir` to isolate the gate when running two cages at once. The
Claude Code and Codex hooks are the same tripwire core at a process boundary:
`forcecage tripwire-hook claude` (or `codex`) reads a hook payload on stdin,
or install the npm package and point the agent's hook config at its
`tripwire-hook` bin.

## The first consumer

The operator's agent workstation runs forcecage as its default safety
layer: its launchers call `forcecage run`, its bindings provider derives
the bindings file from the host's agent configuration, and its in-process
tripwire extension for `pi` consumes the detector core this repo publishes.
If forcecage works for that workstation, it should work for your agent —
but it is a demanding first customer (three agent flavors, a real multi-
host deployment, a real secret store), so we're learning that before you
are.

## License

[MIT](LICENSE). The egress gate depends on
[iron-proxy](https://github.com/ironsh/iron-proxy) (Apache-2.0).
