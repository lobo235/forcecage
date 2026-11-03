"""agent-pane: the Agent-user side of a Forcecage run.

This module is what ``sudo -n -u <agent> python3 -m cage.agent_pane`` runs: the
hop destination. It owns, as the Agent user:

* a per-run agent scratch root (``~/.local/state/forcecage/runs/<id>``) holding
  the tripwire halts log and canary,
* the **bwrap Sandbox** (via :mod:`cage.sandbox`) -- the in-Sandbox socat
  forwarder is part of the bwrap command (it starts the forwarder, then the
  agent execs), and
* the **Grant service** (``cage.grant serve``, background).

It is a leaf process: it runs exactly the agent inside the Sandbox and exits
with the agent's status (a tripwire halt is the agent exiting 3). Everything it
owns is torn down in ``finally``.

Every operator-provided value (gate dir, ports, sockets, config) is an EXPLICIT
command-line argument, because the sudo hop resets the environment -- nothing
crosses that boundary by ambient env (the one exception is ``PYTHONPATH``,
carried across the hop as an ``env`` sub-command of the sudo invocation).

The tripwire is an agent-side contract, not a pane-owned daemon: the pane
prepares the halts log + canary on the Agent's host and hands the agent the
paths (the tripwire hook in the agent -- e.g. the pi-tripwire extension -- is
what reads the canary and halts). The detector, not this pane, is the boundary.
"""
import os
import sys

from cage.config import load_config


# ---------------------------------------------------------------------------
# pure builders (unit-tested)
# ---------------------------------------------------------------------------

def agent_pane_request(argv):
    """Parse the agent-pane argv (the hop destination's argv).

    ``python3 -m cage.agent_pane --run-id R --config P --gate-dir D
    --proxy-port PP --grant-port GP --gate-tunnel-socket T [--clone C]
    [--agent-user U] [--tripwire-notify CMD] -- <agent...>``
    """
    import argparse

    p = argparse.ArgumentParser(prog="agent-pane")
    p.add_argument("--run-id", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--gate-dir", required=True)
    p.add_argument("--proxy-port", type=int, required=True,
                   help="the in-Sandbox proxy port (the forwarder's listen)")
    p.add_argument("--gate-tunnel-socket", required=True,
                   help="HOST path of the gate tunnel socket (ro-bound into the "
                        "Sandbox at /run/forcecage/<basename>)")
    p.add_argument("--clone", default=None,
                   help="the agent's workdir (agent-owned; created if absent)")
    p.add_argument("--agent-user", default=None)
    p.add_argument("--tripwire-notify", default=None,
                   help="command to run on a tripwire halt (default: none)")
    # The bare `--` is argparse's own end-of-options marker: it is consumed
    # itself, and everything after it (the agent's argv) is collected by the
    # REMAINDER positional (which argparse never mis-parses).
    p.add_argument("rest", nargs=argparse.REMAINDER)
    args = p.parse_args(argv)
    return {
        "run_id": args.run_id,
        "config_path": args.config,
        "gate_dir": args.gate_dir,
        "proxy_port": args.proxy_port,
        "gate_tunnel": args.gate_tunnel_socket,
        "clone": args.clone,
        "agent_user": args.agent_user,
        "tripwire_notify": args.tripwire_notify,
        "agent": [a for a in args.rest if a != "--"],
    }


def gate_sock_sandbox_path(gate_tunnel_host):
    """The in-Sandbox path of the ro-bound gate tunnel socket.

    The bwrap narrow view mounts a fresh tmpfs at ``/run/forcecage`` and
    ro-binds the host socket into it (source = host basename, same name), so
    the in-Sandbox path keeps the host basename under the fixed in-Sandbox
    gate dir.
    """
    return "/run/forcecage/" + os.path.basename(gate_tunnel_host)


def tripwire_files(run_dir, run_id):
    """(halts log, canary file) in the Agent's per-run scratch root."""
    return (os.path.join(run_dir, "halts-" + run_id + ".jsonl"),
            os.path.join(run_dir, "canary-" + run_id + ".json"))


def agent_scratch_root(run_id):
    """The Agent's per-run scratch root (created 0700 by the pane)."""
    return os.path.expanduser("~/.local/state/forcecage/runs/" + run_id)


def bwrap_config(req, env):
    """The declarative bwrap config for :func:`cage.sandbox.build_argv`.

    Mount ordering is load-bearing inside :mod:`cage.sandbox` (tmpfs parents
    before ro-binds); the clone is the only rw bind and the agent's workdir
    (cwd). The gate dir is a NARROW view: a fresh tmpfs at the in-Sandbox path
    with only ca.crt, bundle.crt and the ro-bound tunnel socket inside.
    """
    from cage.sandbox import DEFAULT_SYSTEM_RO, DEFAULT_ENV_ALLOWLIST
    clone = req.get("clone")
    cfg = {
        "home": os.path.expanduser("~"),
        "cwd": clone or os.path.expanduser("~"),
        "tmpfs": ["/tmp"],
        "system_ro": list(DEFAULT_SYSTEM_RO),
        "gate_dir": req["gate_dir"],
        "gate_dir_sandbox": "/run/forcecage",
        "gate_socket": gate_sock_sandbox_path(req["gate_tunnel"]),
        "binds": _bwrap_binds(req),
        "env_allowlist": list(DEFAULT_ENV_ALLOWLIST),
        "env": env,
        "gate_listen": "127.0.0.1:" + str(req["proxy_port"]),
        "agent_argv": list(req["agent"]),
    }
    return cfg


def _bwrap_binds(req):
    """The rw/ro binds: the clone (the agent's workdir, rw) and the grant
    queue (the agent writes requests to `in` and reads replies from `out` --
    a filesystem contract, not a socket, so the unshared netns does not matter).
    Parent-before-child ordering is load-bearing: /run/forcecage's tmpfs is
    mounted by sandbox.build_argv before any caller bind."""
    binds = []
    clone = req.get("clone")
    if clone:
        binds.append((clone, clone, False))
    gate = req["gate_dir"]
    binds.append((gate + "/grant/in-agent", "/run/forcecage/grant/in-agent", False))
    binds.append((gate + "/grant/out", "/run/forcecage/grant/out", True))
    return binds


def grant_serve_argv(req, agent_pid, halts_file):
    """argv for the Grant service (runs as the Agent user, background). The
    grant contract is file-based (request/reply files in the gate dir's grant
    queue), so the in-Sandbox agent reaches it through the ro/rw binds, not a
    socket."""
    return [sys.executable, "-m", "cage.grant", "serve",
            "--gate-dir", req["gate_dir"],
            "--agent-pid", str(agent_pid),
            "--halt-file", halts_file]


def tripwire_bwrap_env(halts_file, canary_file, halt_marker, notify=None):
    """The agent-contract tripwire vars the Sandbox env carries (forwarded by
    :func:`cage.sandbox.ordered_env` even though they are not in the allowlist).

    ``halt_marker`` is inside the agent's workdir (a persistent rw bind), so a
    halt written by the agent-side tripwire hook survives the Sandbox and the
    pane can see it.
    """
    env = {
        "FC_TRIPWIRE_HALTS": halts_file,
        "FC_TRIPWIRE_CANARY": canary_file,
        "FORCECAGE_TRIPWIRE_HALT_FILE": halt_marker,
        "PI_TRIPWIRE": "on",
    }
    if notify:
        env["FC_TRIPWIRE_NOTIFY"] = notify
    return env


# ---------------------------------------------------------------------------
# the pane body
# ---------------------------------------------------------------------------

def agent_pane_main(req, spawn=None, spawn_bg=None, build_bwrap=None,
                    load_config_fn=None, make_canary=None):
    """The agent-pane body (runs as the Agent user):

    1. prepares the per-run scratch root (halts log, canary);
    2. spawns the bwrap Sandbox (the agent; the forwarder is inside it);
    3. spawns the Grant service (background);
    4. waits for the agent; tears everything down; returns the agent's code.
    """
    if load_config_fn is None:
        load_config_fn = load_config
    if make_canary is None:
        make_canary = _make_canary
    if spawn is None:
        spawn = _spawn_agent
    if spawn_bg is None:
        spawn_bg = _spawn_bg
    if build_bwrap is None:
        build_bwrap = _build_bwrap

    cfg = load_config_fn(req["config_path"])

    run_dir = agent_scratch_root(req["run_id"])
    os.makedirs(run_dir, mode=0o700, exist_ok=True)
    halts_file, canary_file = tripwire_files(run_dir, req["run_id"])
    make_canary(canary_file, req["run_id"])

    clone = req.get("clone")
    if clone:
        os.makedirs(clone, mode=0o700, exist_ok=True)

    halt_marker = (clone or run_dir) + "/.forcecage-halt"
    # the halt marker is truncated at the start of every run: a stale marker
    # from a prior run in the same clone must not halt this one.
    if os.path.exists(halt_marker):
        open(halt_marker, "w").close()

    # the grant queue must exist BEFORE the bwrap (the ro/rw binds need the
    # bind sources); the Grant service recreates them with its own modes.
    for sub in ("in-agent", "in-host", "out"):
        os.makedirs(os.path.join(req["gate_dir"], "grant", sub), exist_ok=True)

    # the agent's Sandbox env: the agent's own (post-sudo) env + the
    # agent-contract tripwire vars + the grant/sandbox coordinates the in-
    # Sandbox agent needs to reach the Grant service (file-based, via the
    # ro/rw binds of the gate dir's narrow view).
    env = dict(os.environ)
    env["FORCECAGE_GRANT_BIN"] = sys.executable + " -m cage.grant"
    env["FORCECAGE_SANDBOX_GATE_DIR"] = "/run/forcecage"
    env.update(tripwire_bwrap_env(halts_file, canary_file,
                                  halt_marker=halt_marker,
                                  notify=req.get("tripwire_notify")))
    if cfg.grant_catalog:
        env["FORCECAGE_GRANT_CATALOG"] = cfg.grant_catalog

    b_argv = build_bwrap(bwrap_config(req, env))
    s_proc = spawn(env, b_argv)

    g_argv = grant_serve_argv(req, s_proc.pid, halts_file)
    if cfg.grant_catalog:
        # the catalog is a reviewed artifact the Grant service reads at boot;
        # the path must be Agent-readable (it is not inside the Sandbox).
        g_argv += ["--catalog", cfg.grant_catalog]
    if cfg.minter_kind == "vault":
        g_argv += ["--vault-addr", cfg.vault_address,
                   "--vault-role-id-file", cfg.vault_role_id_file,
                   "--vault-secret-id-file", cfg.vault_secret_id_file]
    g_proc = spawn_bg(env, g_argv)

    halt_marker = (clone or run_dir) + "/.forcecage-halt"
    try:
        rc = s_proc.wait()
    finally:
        _teardown(s_proc, g_proc, req["gate_dir"])
    # the operator-facing halt contract: a PLANTED halt marker (non-empty) is a
    # halt, and a halt is exit 3 -- even when the agent itself did not exit 3
    # (an agent whose tripwire writes the marker without halting, e.g. a claude
    # or codex run). An agent that already exited 3 (its own tripwire) is
    # unchanged. A truncated (empty) marker is "no halt": the pane truncates it
    # at the start of every run, and a stale marker from a prior run in the same
    # clone must not halt this one.
    if rc != 3 and _halted(halt_marker):
        rc = 3
    return rc


def _halted(halt_marker):
    """True when the halt marker holds content (a planted halt). An absent or
    empty marker is "not halted" -- the pane truncates it at run start, so an
    empty marker is the "fresh" state, not a halt."""
    try:
        return os.path.getsize(halt_marker) > 0
    except OSError:
        return False


# ---------------------------------------------------------------------------
# real (host) implementations -- injectable for tests
# ---------------------------------------------------------------------------

def _build_bwrap(cfg):
    from cage.sandbox import build_argv
    return build_argv(cfg)


def _make_canary(path, run_id):
    """Write the planted canary (a credential-shaped value the tripwire hook
    recognises). The value is per-run and known to the tripwire hook; it is
    NOT a secret in the usual sense -- it is a tripwire, and its exposure is
    the point."""
    doc = {"run_id": run_id, "value": "canary-" + run_id}
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc + "\n" if isinstance(doc, str) else __import__("json").dumps(doc) + "\n")
    os.chmod(path, 0o600)


def _spawn_agent(env, argv):
    """The agent's stdout/stderr flow UP through sudo -> agent_pane -> run, so
    the operator (or a pane body) captures what the agent prints -- matching
    the launcher design where the pane body owns the agent's output."""
    import subprocess
    e = dict(os.environ)
    e.update(env)
    return subprocess.Popen(argv, env=e)


def _spawn_bg(env, argv):
    """The Grant service is a background sibling: its output is noise."""
    import subprocess
    e = dict(os.environ)
    e.update(env)
    return subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=e)


def _teardown(s_proc, g_proc, gate_dir):
    """Kill the grant service, then the bwrap (which kills the forwarder and
    the agent with it). The per-run scratch root is the agent's to keep
    (halts log, canary) -- retention is a separate concern, not a teardown."""
    for p in (g_proc, s_proc):
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    req = agent_pane_request(argv)
    rc = agent_pane_main(req)
    sys.exit(rc)


if __name__ == "__main__":
    main()
