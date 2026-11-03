# ADR-0001: Agent panes run in a secretless sandbox; a credential-injecting egress gate holds every secret

**Status:** accepted
**Provenance:** extracted 2026-11-02 from the source deployment's
ADR-0042 (2026-10-24, v2), rewritten generic. See `README.md` for
provenance policy.

## Why

A detector (the **Tripwire**) can't stop a leak that carries no known value:
an agent that has read untrusted input can exfiltrate *anything* it knows,
not just the values the detector was told about. The literature's answer is
structural: once an agent has read untrusted input, that input must be unable
to trigger consequential actions (the "lethal trifecta"). The common shipped
pattern is a sandbox with **no secrets inside**, whose egress goes through a
gate that injects credentials only for the destinations they belong to
(Docker Sandboxes, OpenShell, iron-proxy). The standing principle this
implements: **the secret store holds every real secret, and agents get
brokered access, never a credential.**

## Decision

1. **bubblewrap Sandbox.** `forcecage` runs the agent inside bwrap. The
   filesystem view is a `$HOME` **allow list**, not a deny list, plus a
   sanitized agent directory rendered from the agent's own config. The
   network is reachable only through the Egress gate.
2. **The Egress gate is iron-proxy.** It runs under its own uid. It is
   default-deny by host glob or CIDR, speaks CONNECT and SOCKS5, reloads via
   `POST /v1/reload`, and writes a JSON audit log. Inside the Sandbox the
   agent holds only **Placeholders**. The gate swaps in the real value per
   **Credential binding**, which pairs one secret with the destinations it
   may be injected for. A Placeholder sent anywhere else is a **Halt**.
3. **The gate's secrets come from a Minter.** The default **Minter** is a
   file/env one: the real values come from the bindings file and land in
   `0600` files owned by the gate uid — no server needed. A Vault
   **Minter** (AppRole agent with a response-wrapped secret ID, dynamic
   leases with renewal) is a pluggable alternative for minted credentials.
   The gate never takes a raw token on its command line.
4. **Egress grants come from the operator only.** A new destination is an
   **Egress grant** with a time limit, approved by the operator through the
   **Grant service**, which lives next to the gate config. iron-proxy has no
   human-approval flow, so this part is built here. An agent can't grant
   itself access.
5. **Rollout is staged and opt-in.** Ship behind an explicit per-launch
   choice; an opt-out exists but is operator-scoped, never a setting the
   project itself can flip (a repo that could switch its own cage off is the
   hole this closes everywhere else).

## Considered options

- **nftables uid matching, or a per-session netns with no gate.** Rejected:
  either blocks egress but can't inject credentials, so secrets would have to
  stay inside.
- **A container runtime (Docker/Podman) per pane.** Rejected for bwrap:
  lighter, no daemon, and the pattern is already proven by existing
  sandbox-runtime work.
- **A deny-list `$HOME`.** Rejected: a dotfile that lands later is exposed by
  default.
- **Agent-requested grants with automatic approval.** Rejected: an injected
  agent would grant its own exfiltration route.
- **A hand-written gate.** Rejected: iron-proxy already covers per-host
  binding, default-deny and audit. The only gap is approval.
- **Static tokens for the gate.** Rejected in favour of a Minter interface
  with renewal, so the dynamic path stays open.

## Consequences

- **Platform prerequisite:** unprivileged user namespaces must be usable.
  Where the distro restricts them (AppArmor `unprivileged_userns`
  restrictions), the host needs an exception profile; the gate uid and the
  bwrap invocation belong to the host provisioning.
- iron-proxy's audit log writes header values in plain text, so the gate's
  log handling must mask them before anything ships them.
- Existing direct credential use (token files, env-var keys) becomes
  migration debt to move behind the gate.
- The swap is a substring replace: the agent sends
  `Bearer <placeholder>`, so the real value is the raw token (no `Bearer `
  prefix). That is a contract, not an implementation detail.
