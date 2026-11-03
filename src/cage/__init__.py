"""cage -- the Forcecage sandbox core.

Three cooperating pieces (ADR-0001/0002/0003):

  * sandbox -- the bwrap layout builder (pure `build_argv`): the read-only
    system tree, the fresh-tmpfs $HOME, the env allowlist, and the socat
    forwarder that points every byte of egress at the in-sandbox gate socket.
  * gate    -- the host-side per-session egress gate (iron-proxy config,
    credential bindings, misdirected-Placeholder inert-sentinel swap, canary
    markers, audit tail).
  * grant   -- the per-session lease service: the agent requests a lease by
    kind (a label, never a value), the gate mints a Placeholder, the gate
    swaps the real value in on egress, and the grant service halts the pane
    on a planted canary or a misdirected placeholder.

The three modules are loaded by explicit path (SourceFileLoader), not by
package import, so the pure cores stay importable without a path setup. The
`forcecage` CLI (see `src/forcecage`) composes them into `forcecage run`.
"""
