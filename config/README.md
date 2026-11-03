# Configuration

Two files configure a Forcecage install:

## `forcecage.toml` (stable, per host)

Install-level settings: the Agent user, the state directories, the
iron-proxy binary and its pinned sha256, the Minter kind, and the tripwire
state paths. See `forcecage.toml.example`.

The file lives where the operator puts it; `forcecage run` finds it via
`$FORCECAGE_CONFIG`, then `forcecage.toml` in the current directory, then
the XDG config dir. CLI flags override any value.

## Bindings file (per session)

The list of **Credential bindings** for one session — what placeholder
maps to which real value, for which host. See `bindings.example.json`.

- `name` — stable identifier; the placeholder is `Placeholder-<name>`.
- `host` — the destination the value may be injected for (iron-proxy
  matches the request host; a different host for this placeholder is a
  Halt).
- `match_headers` — where to look for the placeholder (HTTP headers).
- `value` — the real value. For `bearer`, the raw token: the agent sends
  `Bearer <placeholder>` and the gate substring-swaps, so the value
  carries no `Bearer ` prefix. For `basic`, the base64 of `user:token`.
- `format` — `bearer` or `basic`. Documents what `value` is.

The source deployment derives this file from its agent configuration (the
**Bindings provider**); other deployments write it by hand or with their
own generator. The file is operator-readable: it holds real values and never
lands inside a Sandbox.
