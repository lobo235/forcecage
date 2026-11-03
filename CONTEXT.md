# Forcecage — domain glossary

The language of this codebase. Definitions only; decisions live in
`docs/adr/`, mechanics in `README.md` and the code.

## Terms

**Force field**:
The composite safety layer an **Agent user**'s pane runs under: the
**Sandbox** (mounts), the **Egress gate** (network), the **Grant service**
(operator approval) and the **Tripwire** (outbound values). Nothing the
model believes gets in or out; that is the whole point.
_Avoid_: AI safety layer, sandbox layer, isolation, sandboxing

**Forcecage**:
The open-source home of the **Force field**: the `forcecage` binary the
**Operator account** runs to cage a command — start the gate, hop to the
**Agent user**, build the **Sandbox**, run the **Grant service**, wire the
agent's **Tripwire**, map a **Halt** to exit 3 — plus the agent-agnostic
**Tripwire** hook and its detector core. It knows only the agent type and
the cage config; the agent command is opaque.
_Avoid_: cage binary, the sandbox layer

**Sandbox**:
The bubblewrap jail an agent pane runs its agent in: `$HOME` hidden except
an allow list, the project directory the only writable tree, no network
except through the **Egress gate**.
_Avoid_: container, jail, VM, isolation (bare)

**Egress gate**:
The host-side proxy that every network connection from a **Sandbox** goes
through: it injects credentials per **Credential binding**, tunnels allowed
hosts unread, and denies everything else. It runs under its own uid and
reads the real values from the **Minter**, the only home of secrets; no
agent ever holds one.
_Avoid_: firewall, MITM proxy, egress filter

**Placeholder**:
The stand-in value a **Sandbox** holds where a real credential would be;
worthless anywhere, and swapped for the real value only by the **Egress
gate**. The swap is a substring replace: the agent sends
`Bearer <placeholder>`, so the real value is the raw token, no `Bearer `
prefix.
_Avoid_: fake key, dummy token, redacted value

**Credential binding**:
The pairing of one secret with the destinations it may be injected for; a
**Placeholder** heading anywhere else is a **Halt**.
_Avoid_: credential scope, token rule

**Bindings provider**:
The host-side generator that derives the per-session **Credential bindings**
from the host's own credential sources (the agent's models file, a provider
credential file, the login shell) and writes the bindings file a **Force
field** session consumes. Each deployment brings its own; forcecage only
consumes the file.
_Avoid_: bindings (bare), credential resolver, keyring

**Minter**:
The component that produces the real credential value a **Credential
binding** swaps in for a **Placeholder**, with an expiry when it is
dynamic. A file/env **Minter** covers static values with no server; a
secret-store **Minter** (Vault, dynamic leases, AppRole) is a pluggable
alternative.
_Avoid_: issuer, vault (that is one implementation), broker (that is the
in-session route)

**Egress grant**:
The operator's approval of one denied destination for one session, with a
time limit, given through the one approval channel; never given by the
agent, and made permanent only by a reviewed change to the gate's allow
list.
_Avoid_: exception, allow rule, whitelist entry

**Grant service**:
The companion to the **Egress gate** that turns a denied destination into a
question for the operator and an approved answer into an **Egress grant**,
and that raises the **Halt** alert when the gate refuses a misdirected
**Placeholder**. It applies, expires and alerts; it never asks the operator
itself.
_Avoid_: approval bot, policy engine, judge

**Credential lease**:
The operator-approved, time-limited right of a session to hold one
credential through a **Placeholder**, bound to a reviewed **Lease kind**.
The agent asks, names the target and the access, and gives a reason; it
never holds the real value.
_Avoid_: token, temporary key, grant (that is an Egress grant)

**Lease kind**:
A reviewed template a **Credential lease** may bind to: which target, which
access, which **Minter** path, which expiry. The catalog of kinds is bounded
by construction; extending it is a **Prepared change**, not a runtime
choice.
_Avoid_: profile, template (bare), policy

**Leak report**:
The agent's report that a **Placeholder** may have leaked. The **Minter**
rotates automatically, without approval: revoke the reported value, re-mint
with the same access and expiry, keep the old value as a **Canary** until
the lease would have expired. A misdirected **Placeholder** caught by the
gate is still a **Halt**.
_Avoid_: incident, revocation (that is one of its steps)

**Tripwire**:
A deterministic check on an outbound tool call that refuses it when an
argument carries a known credential's value, a secret pattern or a planted
**Canary**, and alerts the operator; the agent is told only what was
refused and why. It acts in code, whatever the model believes.
_Avoid_: guardrail, injection detector, filter

**Canary**:
A unique planted marker, such as a decoy credential value or a decoy
credential file, that no real task ever uses, so any outbound use or read
of it is evidence of an attack.
_Avoid_: honeypot (that is a host), bait, tracer

**Halt**:
Stopping a session because a **Tripwire** caught a known credential's value
or a **Canary** leaving: the call is refused, the run ends (exit 3), and
the operator is alerted. Only deterministic evidence halts, never a
classifier.
_Avoid_: kill, abort, panic, lockdown

**Exposure**:
The record that untrusted content has entered the session: where it came
from, at which round, and how many external sends followed. Provenance,
never a verdict.
_Avoid_: compromised, injected, taint score

**Agent user**:
The unprivileged Unix account every agent runs as, never the operator's
own account: no sudo, no root-owned daemon socket, no SSH keys and no
secret-store token, so the broker is its only route to a credential. The
**Sandbox** confines it further; it does not replace it.
_Avoid_: service account, bot user, sandbox user

**Agent clone**:
An **Agent user**'s own clone of a project, the only tree an agent writes.
The operator reads it but never runs anything in it; work reaches the
operator as a pushed branch.
_Avoid_: workspace, worktree (git's term for something else), shared
checkout

**Agent harness**:
Everything an **Agent user**'s tools load and obey: extensions such as the
**Tripwire**, hooks, settings and permission policy. Readable by the agent,
never writable by it, and it holds no credentials, so no session can disarm
the next one.
_Avoid_: agent config (the agent's own state is not the harness), dotfiles,
profile

**Prepared change**:
A privileged change an agent hands to the operator instead of making it:
the exact command and the commit it applies, run by the operator after
review. Reads go through the broker; changes are prepared, never run by an
agent.
_Avoid_: request, ticket, approval, handoff

**Operator account**:
The human operator's own Unix account. It may hold root-equivalent
privileges, which is exactly why no agent runs as it.
_Avoid_: user (bare), admin, main account

## Notes

- Inside a **Sandbox** the **Tripwire** looks for **Placeholders** and
  **Canaries**, since no real credential value is there to match.
- A **Tripwire** match on a known credential's value or a **Canary** is a
  **Halt**; a match on a generic secret pattern only refuses that one call.
- The **Grant service** never initiates an approval: it applies, expires
  and alerts. The approval channel is the operator's, full stop.
- A client whose own login refreshes in response bodies (the gate rewrites
  requests) may carry the one documented real credential inside a Sandbox;
  the **Tripwire** treats it as a known value.
