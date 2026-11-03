# ADR-0003: Every launch runs sandboxed as the agent user; credentials are leased through one approval channel

**Status:** accepted
**Provenance:** extracted 2026-11-02 from the source deployment's
ADR-0044 (2026-10-31, v1), rewritten generic. See `README.md` for
provenance policy.

## Why

The goal is that every agent launcher — however many agent flavors the
operator runs — starts its agent (a) as the unprivileged Agent user, (b)
inside the secretless Sandbox, (c) with the Tripwire live, (d) with all
egress through the gate. And the agent may **lease** any credential it needs
by asking, without ever holding a real one. That last part changes the
approval story: approvals used to be per-destination TUI prompts. Leases
need one channel, and one channel means one audit trail.

## Decision

1. **The build cycle runs in user space**, with one exception: a throwaway
   Agent user on one host, made to the agreed spec, so the uid boundary is
   proven for real. A development Minter runs on loopback (`-dev-no-store-
   token` style: it never overwrites the operator's real token file). The
   iron-proxy binary is pinned and checksum-verified under the state
   directory.
2. **The agents' own model logins, with no pay-per-use billing anywhere.**
   Prefer a long-lived login token held by the gate, with a Placeholder in
   the agent's environment. Where the client refreshes its token **in
   response bodies** and the gate rewrites only requests, the client's own
   login is the **one documented real credential inside a Sandbox**; the
   Tripwire treats it as a known value. API keys are rejected where they
   bill per use.
3. **One shared Tripwire hook program** for every agent that supports
   command hooks, running the same matching code as the in-process detector:
   - Claude-style dialect: deny, a Halt with `continue: false`, per-match
     redaction of the tool output.
   - Codex-style dialect (no `continue: false`, no output replacement): a
     Halt is a deny plus stopping the agent process; a result that shows a
     credential is withheld whole.
   - Exposure lives in a per-session state file. Hooks are per-pane
     read-only config.
4. **One shared Agent user.** Isolation between sessions comes from the
   Sandbox's mounts. Per-project users are future work (each needs its own
   subid range, container daemon, logins and provisioning entries).
5. **One approval channel** for Egress grants and Credential leases alike —
   the operator's own surface (TUI when attended, phone otherwise). The
   Grant service becomes its gate-side half: it applies, expires and alerts,
   and **never asks the operator itself**. No second TUI approval path.
6. **Credential leases.** An agent may ask for any credential by naming the
   target and the access, with a reason. An approval binds only to a
   reviewed **Lease kind**:
   - **Minted leases** (dynamic secrets from the Minter) come first.
   - **Shared leases** (the original behind a new Placeholder) are labelled
     as such in the approval request.
   - A request that matches no kind becomes a Prepared change adding one,
     which keeps the catalog bounded.
7. **A Leak report rotates automatically, with no approval.** The Grant
   service revokes the reported Placeholder, re-mints a minted lease with
   the same access and expiry, and keeps the old Placeholder as a **Canary**
   until the lease would have expired. The gate catching a misdirected
   Placeholder is still a Halt. A report about a client's own login (the
   documented exception) halts the pane.
8. **Scope of the first cycle:** the hook, the Agent user hop, the Sandbox
   for every launcher, the gate with Credential bindings, the Grant service
   against a fake approver, and one minted lease kind end to end. It ends
   with an end-to-end run of every launcher against fakes. Nothing merges,
   pushes, releases or syncs, and **no launcher's default changes** until
   the cycle is proven.

## Considered options

- **Fakes only, no real Agent user.** Rejected; the uid boundary has to be
  proven.
- **An OpenAI-style API key behind a Placeholder.** Rejected where it bills
  per use.
- **Building a refresh-aware gate now.** Deferred; it is a new component on
  the credential path, and the documented exception covers the meantime.
- **Holding a client back until upstream supports `continue: false`.**
  Rejected; a deny plus a process kill is a sufficient Halt.
- **Per-project Agent users now.** Deferred; the provisioning cost is real
  and the Sandbox already isolates sessions.
- **Keeping a second approval path for attended panes.** Rejected; two
  channels means two audit trails and two self-approval surfaces.
- **Free-form leases of any secret path.** Rejected: one convincing reason
  from an injected agent away from reading anything.
- **Requiring approval before rotating on a leak.** Rejected; the leaked
  value would stay live through the approval wait, and leaked tokens have
  been used within about 30 minutes.

## Consequences

- The Grant service **never initiates an approval** — only applies, expires
  and alerts. The approval channel is the operator's, full stop.
- The catalog of Egress grant and Lease kinds is bounded by construction:
  extending it is a reviewed change, not a runtime choice.
- The documented real credential inside a Sandbox (the client's own login)
  is a standing exception the Tripwire knows about; a refresh-aware gate
  retires it.
- Default-to-Sandbox is a separate, later decision, per launcher, after the
  fakes prove the cycle.
