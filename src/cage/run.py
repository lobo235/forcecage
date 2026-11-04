"""cage.run -- the operator side of a forcecage run.

This runs as the operator and absorbs the whole cage for one agent run:

  1. loads ``forcecage.toml`` and the per-session credential bindings;
  2. creates the per-session 0700 gate dir and picks free ports;
  3. starts the egress gate in the background (``cage.gate start --wait``);
  4. waits for gate readiness;
  5. hops to the Agent user (``sudo -n -u <agent>``) and runs
     ``cage.agent_pane`` (the bwrap exec, the Grant service, the halt mapping);
  6. tears the gate down on exit and returns the agent's exit code.

Every external point (gate start, the sudo hop, gate stop, the readiness
wait) is injectable so the orchestration is unit-testable without a live
host.
"""

import json
import os
import socket
import subprocess
import sys
import time

from .config import load_config, find_config, ConfigError


class RunError(Exception):
    """The run could not be composed (fails before or during the run)."""


# ---------------------------------------------------------------------------
# ports
# ---------------------------------------------------------------------------

def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def pick_ports(cfg, count=5):
    """Free ports in order [mgmt, proxy, tunnel, http, dns]."""
    # honor any operator-pinned ports from config, otherwise auto-assign
    names = ("mgmt", "proxy", "tunnel", "http", "dns")
    ports = {}
    for name in names:
        pinned = getattr(cfg, "port_" + name, None)
        ports[name] = int(pinned) if pinned else _free_port()
    return [ports[n] for n in names[:count]]


# ---------------------------------------------------------------------------
# config + bindings
# ---------------------------------------------------------------------------

def load_cfg(req):
    path = req.config_path or find_config()
    if path is None:
        from .config import Config
        return Config.from_dict({})
    if not os.path.isfile(path):
        raise RunError("config not found: %s" % path)
    return load_config(path)


def load_bindings(req):
    if not req.bindings_path:
        return []
    if not os.path.isfile(req.bindings_path):
        raise RunError("bindings not found: %s" % req.bindings_path)
    with open(req.bindings_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, list):
        raise RunError("bindings must be a JSON list: %s" % req.bindings_path)
    return doc


# ---------------------------------------------------------------------------
# gate argv
# ---------------------------------------------------------------------------

def gate_start_argv(cfg, gate_dir, ports, bindings_path, allowlist, upstream_deny=None):
    return [sys.executable, "-m", "cage.gate", "start",
            "--dir", gate_dir,
            "--port-mgmt", str(ports[0]),
            "--port-proxy", str(ports[1]),
            "--port-tunnel", str(ports[2]),
            "--port-http", str(ports[3]),
            "--port-dns", str(ports[4]),
            "--bindings", bindings_path,
            "--allowlist", json.dumps(allowlist),
            "--upstream-deny", json.dumps(list(upstream_deny) if upstream_deny is not None else cfg.upstream_deny),
            "--agent", cfg.agent_user,
            "--iron-proxy", cfg.iron_proxy,
            "--wait"]


def gate_stop_argv(gate_dir):
    return [sys.executable, "-m", "cage.gate", "stop", "--dir", gate_dir]


def agent_pane_argv(req, cfg, gate_dir, ports, config_path, run_id,
                    approval_in_sbx=False, extra_binds=""):
    """argv for the sudo-hop destination (the Agent-user side).

    Every value the Agent user needs crosses the hop as an EXPLICIT argument
    (the sudo environment reset strips ambient env): the config path, the gate
    dir, the in-Sandbox proxy port (ports[1]), the host gate tunnel socket,
    the clone (the agent's workdir), the agent command, and -- when the
    operator opted in -- the Grant escalation seam and extra Sandbox binds.
    """
    argv = [sys.executable, "-m", "cage.agent_pane",
            "--run-id", run_id,
            "--config", config_path,
            "--gate-dir", gate_dir,
            "--proxy-port", str(ports[1]),
            "--gate-tunnel-socket", os.path.join(gate_dir, "gate.sock"),
            "--agent-user", cfg.agent_user]
    if req.clone:
        argv += ["--clone", req.clone]
    if approval_in_sbx:
        argv += ["--approval-in-sbx"]
    if extra_binds:
        argv += ["--extra-binds", extra_binds]
    # the exec'd argv is the binary + its args (the agent NAME is operator-side
    # metadata, not part of the command the Sandbox runs).
    return argv + ["--", req.binary] + list(req.agent_args)


def hop_argv(cfg, agent_pane_args, pythonpath=None):
    """The operator->agent hop: sudo -n -u <agent> [env PYTHONPATH=...] <args>.

    sudo resets the environment by default, so a repo-relative cage package
    (not installed into site-packages) must be carried across the hop with an
    explicit ``env PYTHONPATH=...`` -- otherwise the agent cannot import it.
    """
    argv = ["sudo", "-n", "-u", cfg.agent_user]
    if pythonpath:
        argv += ["env", "PYTHONPATH=" + pythonpath]
    return argv + agent_pane_args


def _cage_src():
    """The directory that must be on PYTHONPATH to import ``cage`` (the parent
    of the package dir) -- so the agent-side hop works from a repo checkout.

    ``$FORCECAGE_PKG_ROOT`` overrides it: an install (or a test) where the Agent
    user cannot read the operator's checkout stages an agent-readable copy and
    points the hop at it. When unset, the hop uses this process's own import
    location (the usual case: cage is installed where the Agent can read it).
    """
    override = os.environ.get("FORCECAGE_PKG_ROOT")
    if override:
        return override
    import cage
    return os.path.dirname(os.path.dirname(os.path.abspath(cage.__file__)))


# ---------------------------------------------------------------------------
# the orchestration
# ---------------------------------------------------------------------------

def run(req, spawn_gate=None, hop_agent=None, stop_gate=None,
        wait_ready=None, now=None, sleep=None):
    """Compose and run one caged agent. Returns the agent's exit code.

    The injectable seams: ``spawn_gate(env, argv)`` (start the gate),
    ``hop_agent(env, argv)`` (the sudo to the agent), ``stop_gate(env, argv)``
    (teardown, returns rc), ``wait_ready(path, timeout)`` (gate readiness).
    """
    now = now or time.time
    sleep = sleep or time.sleep

    cfg = load_cfg(req)
    if req.state_dir:
        # per-session isolation: the gate (state_dir/gate) is a fixed path, so
        # concurrent runs must each own a state_dir. The flag overrides the
        # config (the plan's "CLI flags override the config").
        cfg.state_dir = os.path.expanduser(req.state_dir)
    bindings = load_bindings(req)
    config_path = req.config_path or find_config()
    if config_path is None:
        # no config file on disk (e.g. a test injected a bare Config): the
        # agent pane re-derives defaults from an empty config.
        config_path = os.path.join(cfg.state_dir, "forcecage.empty.toml")
        os.makedirs(cfg.state_dir, exist_ok=True)
        if not os.path.exists(config_path):
            with open(config_path, "w", encoding="utf-8") as fh:
                fh.write("")

    gate_dir = os.path.join(cfg.state_dir, "gate")
    os.makedirs(gate_dir, mode=0o700, exist_ok=True)
    os.chmod(gate_dir, 0o700)

    # persist the bindings where the gate reads them
    bindings_path = os.path.join(gate_dir, "bindings.json")
    with open(bindings_path, "w", encoding="utf-8") as fh:
        json.dump(bindings, fh, indent=2)
    os.chmod(bindings_path, 0o600)

    allowlist = {"domains": list(cfg.allowlist_domains),
                 "cidrs": list(cfg.allowlist_cidrs)}

    ports = pick_ports(cfg)
    gate_env = dict(os.environ)
    gate_argv = gate_start_argv(cfg, gate_dir, ports, bindings_path, allowlist)

    if spawn_gate is None:
        spawn_gate = lambda env, argv: subprocess.Popen(
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    if stop_gate is None:
        def stop_gate(env, argv):
            p = subprocess.run(argv, capture_output=True, text=True, env=env)
            return p.returncode
    if hop_agent is None:
        def hop_agent(env, argv):
            e = dict(os.environ)
            e.update(env)
            return subprocess.Popen(argv, env=e)
    if wait_ready is None:
        def wait_ready(path, timeout):
            deadline = now() + timeout
            while now() < deadline:
                if os.path.exists(path):
                    return True
                sleep(0.2)
            return os.path.exists(path)

    gate_proc = spawn_gate(gate_env, gate_argv)
    state_file = os.path.join(gate_dir, "state.json")

    def _teardown():
        try:
            stop_gate(gate_env, gate_stop_argv(gate_dir))
        except Exception:
            pass

    try:
        ready = wait_ready(state_file, cfg.ready_timeout)
        if not ready:
            print("forcecage: gate did not become ready within %.0fs; see %s"
                  % (cfg.ready_timeout, gate_dir), file=sys.stderr)
            return 2  # the finally still tears the gate down

        # the agent-side env: the host gate dir is the same path in the
        # Sandbox's narrow view (the default); the operator passes it through.
        agent_env = {
            "FORCECAGE_SANDBOX_GATE_DIR": gate_dir,
            "FORCECAGE_SANDBOX_GATE_DIR_HOST": gate_dir,
        }
        # forward the vault minter settings when the gate mints from vault
        if cfg.minter_kind == "vault":
            agent_env.update({
                "FORCECAGE_GRANT_VAULT_ADDR": cfg.vault_address,
                "FORCECAGE_GRANT_VAULT_ROLE_ID_FILE": cfg.vault_role_id_file,
                "FORCECAGE_GRANT_VAULT_SECRET_ID_FILE": cfg.vault_secret_id_file,
            })
        if cfg.grant_catalog:
            agent_env["FORCECAGE_GRANT_CATALOG"] = cfg.grant_catalog

        # operator-side seams that must cross the sudo hop as explicit args
        # (the env reset strips them): the Grant escalation seam (a test seam
        # the e2e uses to let a stand-in agent play the gateway) and extra
        # Sandbox binds. The FORCECAGE_ names are primary; the legacy ORC_ names
        # are honored so a pre-rename caller keeps working.
        approval_in_sbx = bool(
            os.environ.get("FORCECAGE_GRANT_APPROVAL_IN_SBX")
            or os.environ.get("ORC_GRANT_APPROVAL_IN_SBX"))
        extra_binds = (
            os.environ.get("FORCECAGE_SANDBOX_BINDS")
            or os.environ.get("ORC_SANDBOX_BINDS") or "")

        proc = hop_agent(agent_env, hop_argv(
            cfg, agent_pane_argv(req, cfg, gate_dir, ports, config_path,
                                 run_id="run-" + str(int(now())) + "-" + str(os.getpid()),
                                 approval_in_sbx=approval_in_sbx,
                                 extra_binds=extra_binds),
            pythonpath=_cage_src()))
        rc = proc.wait()
    finally:
        _teardown()
    return rc
