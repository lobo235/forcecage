"""bin/orc-sandbox: build and exec the bubblewrap Sandbox for one agent run.

ADR-0044. This is the in-Sandbox half of the egress layout. The host side
(the launcher) starts iron-proxy and a host-side `socat` bridge that connects
the gate unix socket to iron-proxy's tunnel_listen. This program runs *as the
Agent user* (the launcher hops to it with `sudo -n -u agent`) and:

  1. builds a bwrap argv that confines the agent: $HOME hidden except an
     explicit allowlist of ro/rw binds, the project clone the only writable
     tree, the system dirs read-only, the netns unshared;
  2. rebuilds a clean environment from an allowlist plus the proxy/CA vars
     that route every byte of egress through an in-Sandbox `socat` forwarder
     on 127.0.0.1:3128, which bridges to the bound gate socket;
  3. execs bwrap, whose command starts that forwarder and then execs the agent.

`build_argv(config)` is pure (no fs, env, or clock) so the layout is unit-
testable; `main` reads a thin set of FORCECAGE_SANDBOX_* env vars, builds the
config, and execs. A `--print-argv` hook prints the bwrap argv and exits, the
way an orchestrator launcher's script-print hook does.

The gate dir (a host path) carries the gate socket, the gate CA, and the
Grant service's files. The Sandbox sees a NARROW view of it at
`gate_dir_sandbox`: a fresh tmpfs holding only the CA, the bundle, the gate
socket, and the grant queue's agent side (in-agent rw, out ro -- bound by
the caller). The minted secrets, the Vault token, and the host approval
queue (in-host) stay out of the agent's mount namespace, so a same-uid
agent cannot read its own minted secrets or drop its own approval file.
"""
import os
import shlex
import sys

# The environment the agent is allowed to keep, everything else is dropped by
# --clearenv and not restored. Deliberately small: a credential that never
# makes this list is not in the Sandbox. Override the list with
# FORCECAGE_SANDBOX_ENV_ALLOWLIST (comma-separated).
DEFAULT_ENV_ALLOWLIST = [
    "PATH", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "XDG_RUNTIME_DIR", "DISPLAY", "WAYLAND_DISPLAY",
]

# System dirs bound read-only. /etc is bound whole for the cycle; the
# credential-shaped entries are handled by the Prepared /etc policy change
# (the host's provisioning playbook), not here.
DEFAULT_SYSTEM_RO = ["/usr", "/etc", "/lib", "/lib64", "/bin", "/sbin"]


def forwarder_script(gate_listen, gate_socket):
    """The in-Sandbox shell that starts the socat forwarder, then execs `$@`.

    `lo` is up in the unshared netns (bwrap brings it up), so the forwarder
    listens on loopback. The host side connects the bound unix socket to
    iron-proxy's tunnel_listen.
    """
    host, port = gate_listen.rsplit(":", 1)
    return (
        f"socat TCP-LISTEN:{port},bind={host},fork,reuseaddr "
        f"UNIX-CONNECT:{gate_socket} & sleep 0.4; exec \"$@\""
    )


def ordered_env(config):
    """The environment, in deterministic order: allowlist passthrough, then
    HOME, then the proxy/CA vars that define the Sandbox's egress."""
    env = {}
    for name in config["env_allowlist"]:
        if name in config["env"]:
            env[name] = config["env"][name]
    # The agent-contract vars: agent-pane sets these for the agent it is about
    # to run (the halt marker, the hook path, PI_TRIPWIRE for pi, CODEX_HOME
    # for codex, and the Grant-service coordinates -- the in-Sandbox gate dir
    # and the grant CLI path, which the agent's narrow orc-grant CLI needs to
    # file requests and read replies). They are part of the Sandbox contract,
    # so they are forwarded even though they are not in the operator's
    # allowlist -- without them the tripwire hook cannot find the halt marker,
    # codex loses its per-run config, and the agent cannot reach the Grant
    # service, all silently.
    for name in ("FORCECAGE_TRIPWIRE_HALT_FILE", "FORCECAGE_TRIPWIRE_HOOK", "PI_TRIPWIRE",
                 "CODEX_HOME", "FORCECAGE_GRANT_BIN", "FORCECAGE_SANDBOX_GATE_DIR",
                 "FORCECAGE_GRANT_CATALOG", "FC_TRIPWIRE_HALTS", "FC_TRIPWIRE_CANARY",
                 "FC_TRIPWIRE_NOTIFY", "PYTHONPATH"):
        if name in config["env"]:
            env[name] = config["env"][name]
    env["HOME"] = config["home"]
    proxy = f"http://{config['gate_listen']}"
    env["HTTP_PROXY"] = proxy
    env["HTTPS_PROXY"] = proxy
    env["http_proxy"] = proxy
    env["https_proxy"] = proxy
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = "127.0.0.1,localhost"
    gate = config["gate_dir_sandbox"]
    env["NODE_EXTRA_CA_CERTS"] = f"{gate}/ca.crt"
    env["SSL_CERT_FILE"] = f"{gate}/bundle.crt"
    env["CODEX_CA_CERTIFICATE"] = f"{gate}/ca.crt"
    env["GIT_SSL_CAINFO"] = f"{gate}/bundle.crt"
    return env


def build_argv(config):
    """Pure: a declarative config dict -> the bwrap argv (list of str).

    Mount ordering is load-bearing: bwrap applies directives in order, and a
    later mount at a parent path wipes anything mounted under it. So tmpfs
    entries (parents) are emitted before the system ro-binds and the explicit
    ro/rw binds. Within `binds`, the caller orders parent-before-child.
    """
    argv = ["bwrap", "--unshare-all", "--die-with-parent", "--dev", "/dev", "--proc", "/proc"]

    # tmpfs parents first: /tmp and $HOME (and anything else the caller names)
    tmpfs = list(config.get("tmpfs", []))
    if config["home"] not in tmpfs:
        tmpfs.append(config["home"])
    for t in tmpfs:
        argv += ["--tmpfs", t]

    for d in config["system_ro"]:
        argv += ["--ro-bind", d, d]

    # the gate dir, in a NARROW view: a fresh tmpfs at the in-Sandbox path
    # shadows the host gate dir (bwrap resolves bind sources in the original
    # namespace, so same-path file binds still work), and only what the agent
    # needs is bound into it: the CA and the bundle (the TLS env), the gate
    # socket (the forwarder connects to it; write is the socket's own ACL,
    # not the dir's), and the grant queue's parent -- the queue subdirs
    # (in-agent rw, out ro) ride the caller's `binds`, ordered after this
    # parent tmpfs. The service's own files -- minted secrets, the Vault
    # token, the host approval queue (in-host) -- stay out of the Sandbox.
    gate_host, gate_sbx = config["gate_dir"], config["gate_dir_sandbox"]
    argv += ["--tmpfs", gate_sbx]
    argv += ["--ro-bind", gate_host + "/ca.crt", gate_sbx + "/ca.crt"]
    argv += ["--ro-bind", gate_host + "/bundle.crt", gate_sbx + "/bundle.crt"]
    sock_sbx = config.get("gate_socket", gate_sbx + "/gate.sock")
    argv += ["--ro-bind", gate_host + "/" + os.path.basename(sock_sbx), sock_sbx]
    argv += ["--tmpfs", gate_sbx + "/grant"]

    for src, dst, ro in config["binds"]:
        argv += (["--ro-bind", src, dst] if ro else ["--bind", src, dst])

    argv += ["--clearenv"]
    for name, value in ordered_env(config).items():
        argv += ["--setenv", name, value]

    argv += ["--chdir", config.get("cwd", config["home"])]

    # in-Sandbox: start the forwarder, then exec the agent ($@ is the argv)
    gate_socket = config.get("gate_socket", config["gate_dir_sandbox"] + "/gate.sock")
    script = forwarder_script(config["gate_listen"], gate_socket)
    argv += ["bash", "-c", script, "-"] + list(config["agent_argv"])
    return argv


def config_from_env(environ):
    """The thin main: FORCECAGE_SANDBOX_* vars -> a build_argv config.

    `gate_socket` is the in-Sandbox path of the gate socket; it defaults to
    <gate_dir_sandbox>/gate.sock.
    """
    gate_dir_sandbox = environ.get("FORCECAGE_SANDBOX_GATE_DIR", "/run/forcecage")
    allowlist = environ.get("FORCECAGE_SANDBOX_ENV_ALLOWLIST", "")
    if allowlist:
        env_allowlist = [a for a in allowlist.split(",") if a]
    else:
        env_allowlist = list(DEFAULT_ENV_ALLOWLIST)
    home = environ.get("FORCECAGE_SANDBOX_HOME", "/home/agent")
    binds = []
    raw_binds = environ.get("FORCECAGE_SANDBOX_BINDS", "")
    for entry in filter(None, (b.strip() for b in raw_binds.split("\n"))):
        parts = entry.split(":")
        if len(parts) == 3:
            src, dst, ro = parts[0], parts[1], parts[2].strip() != "rw"
        elif len(parts) == 2:
            src, dst, ro = parts[0], parts[1], True
        else:
            raise SystemExit(f"orc-sandbox: bad --bind entry {entry!r} (want SRC:DST[:ro|rw])")
        binds.append((src, dst, ro))
    return {
        "home": home,
        "cwd": environ.get("FORCECAGE_SANDBOX_CWD", home),
        "tmpfs": ["/tmp"],
        "system_ro": list(DEFAULT_SYSTEM_RO),
        "gate_dir": environ.get("FORCECAGE_SANDBOX_GATE_DIR_HOST", gate_dir_sandbox),
        "gate_dir_sandbox": gate_dir_sandbox,
        "binds": binds,
        "env_allowlist": env_allowlist,
        "env": environ,
        "gate_listen": environ.get("FORCECAGE_SANDBOX_GATE_LISTEN", "127.0.0.1:3128"),
        "gate_socket": environ.get("FORCECAGE_SANDBOX_GATE_SOCKET", gate_dir_sandbox + "/gate.sock"),
        "agent_argv": [],
    }


def main(argv):
    args = list(argv)
    print_argv = False
    if args and args[0] == "--print-argv":
        print_argv = True
        args = args[1:]
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        print("usage: orc-sandbox [--print-argv] -- <agent> [args...]", file=sys.stderr)
        return 2
    config = config_from_env(os.environ)
    config["agent_argv"] = args
    bwrap_argv = build_argv(config)
    if print_argv:
        for a in bwrap_argv:
            print(a)
        return 0
    os.execvp(bwrap_argv[0], bwrap_argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
