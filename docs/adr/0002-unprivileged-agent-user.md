# ADR-0002: Every agent runs as an unprivileged agent user, never the operator account

**Status:** accepted
**Provenance:** extracted 2026-11-02 from the source deployment's
ADR-0043 (2026-10-24, v2), rewritten generic. See `README.md` for
provenance policy.

## Why

If the agent runs as the operator's own account, that account typically has
several independent routes to root: passwordless sudo, a rootful container
daemon group (Docker's docs call it root-level), and an SSH key that, paired
with a locally stored secret token, becomes a fleet-wide certificate. Then
`0600` on a credential file protects nothing from the agent, and a detector
running inside a process the agent could edit or relaunch is not a boundary.
Removing any single privilege closes only one route. The secretless Sandbox
(ADR-0001) and the gate's own uid separate anything **only if the agent
can't become root** — so the uid boundary is the foundation, not a
convenience.

## Decision

1. **Agent user.** Every agent runs as a dedicated unprivileged account,
   whichever launcher started it. That account has no sudo, no root-owned
   daemon socket, no SSH keys and no secret-store token, so the broker is its
   only route to a credential. The Sandbox (ADR-0001) confines the pane
   further; it adds to the Agent user and doesn't replace it.
2. **Agent clones.** An agent writes only its own clone of a project, owned
   by the Agent user. The operator reads it but never runs anything in it.
   Work reaches the operator as a pushed branch. The git ownership check
   then refuses the operator's git inside an agent's tree, so a planted hook,
   `core.fsmonitor` or `.envrc` never runs as the operator.
3. **The uid hop.** Panes stay on the operator's session server. Each pane
   switches to the Agent user through one sudoers rule whose target is the
   Agent user, never root, for one fixed root-owned pane script. That script
   is the boundary between the two users and validates every argument.
   sudo-rs `use_pty` (on by default) plus `dev.tty.legacy_tiocsti=0` stop
   terminal injection; the session server parses everything the agent prints.
4. **Agent harness, read-only.** The harness — everything the agent's tools
   load and obey (extensions, hooks, settings, permission policy) — is
   rendered from canonical config: owned by the operator, readable by the
   agent, writable by nobody else, holding no credentials, so no session can
   disarm the next one. The agent's own state directory keeps only state and
   transcripts. Managed system policy files for each agent (allow-listed
   hooks only, no full-access profiles) are system-wide, so they bind the
   operator's own sessions too.
5. **Rootless containers per Agent user.** Root inside a container maps to
   that user's subordinate uids. The daemon socket stays outside the
   Sandbox until the daemon's own network goes through the Egress gate.
6. **Bare commands wrap too.** The agent binaries on the operator's PATH
   switch to the Agent user. Running as the operator needs a loud
   `--as-operator` flag or the real binary's full path.
7. **Brokered reads, Prepared changes.** Read-only host diagnostics become
   broker tools with fixed argument shapes and no pager. Privileged changes
   (provisioning runs, secret-store writes, restarts, host container runs)
   are **Prepared changes**: the agent hands over the exact command and its
   commit, and the operator runs them after review.
8. **The Operator account stays root-equivalent.** The boundary is between
   agent and operator; stripping the operator's own privileges costs daily
   convenience and still shares every operator file with the agent.

## Considered options

- **Strip the Operator account's privileges instead.** Rejected: agents
  would still share every operator file, and the rootful daemon group
  remains a shared root path.
- **Sandbox only, same user.** Rejected: it covers one launcher's panes and
  says nothing about the other agents the operator runs.
- **A shared group-writable tree, or an `as-agent` discipline.** Rejected:
  the operator's ordinary commands would run agent-written code as the
  operator.
- **An agent-owned session server the operator attaches to.** Rejected:
  replacing-client semantics hand code execution to the server's owner.
- **`run0` / `systemd-run --uid`.** Rejected: it needs the same grant as a
  polkit rule, with more moving parts.
- **A root-owned harness via provisioning.** Rejected: against the agent it
  protects no better than operator ownership, and it slows every harness
  change.
- **An agent-owned harness.** Rejected: an injected session could disarm
  every later one.
- **A narrow sudo allowlist for agents.** Rejected: the classic GTFOBins
  list — the container binary is root, `find -exec` spawns a shell, and
  pagers inherit their environment.
- **A privileged "ops agent" running as the operator.** Rejected: it is
  exactly the root-equivalent agent this ADR removes.

## Consequences

- **Host provisioning owns:** the Agent user, its subuid range, the sudoers
  hop, and the managed policy files.
- **The launcher owns:** the pane script and the hop, the command wrappers,
  the rendered harness, and Agent clone creation.
- **The user-namespace caveat:** outside the Sandbox, any local user can
  usually get a user namespace that holds capabilities, so the Agent user is
  a **uid boundary, not a namespace boundary**. Inside the Sandbox, every
  child is stacked under the sandbox profile.
- **Build order:** the Agent user comes before the Sandbox and the gate.
- Never let a valid secret-store token sit in an agent's home: it is itself
  one of the root routes.
