#!/usr/bin/env python3
"""Table-driven unit tests over bin/orc-sandbox's pure build_argv (Slice A).

build_argv maps a declarative config to the bwrap argv. It is pure: no fs, no
env read, no clock. The layout invariants it encodes (ADR-0044):
  * $HOME is a tmpfs; everything the agent may see is an explicit ro/rw bind.
  * the system dirs are read-only.
  * the environment is cleared, then rebuilt from an allowlist plus the proxy/CA
    vars that point every byte of egress at the in-sandbox forwarder.
  * the netns is unshared; the only route out is the socat forwarder on
    127.0.0.1:3128 that bridges to the bound gate socket.
  * bwrap applies mounts in order, so a tmpfs of a parent must precede any
    bind into it -- the tests pin that ordering.
"""
import importlib.machinery
import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "src" / "cage" / "sandbox.py"
    loader = importlib.machinery.SourceFileLoader("forcecage_sandbox", str(path))
    spec = importlib.util.spec_from_loader("forcecage_sandbox", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


MOD = load_module()
build_argv = MOD.build_argv


def cfg(**over):
    """A complete, minimal config; callers override what a case needs."""
    base = {
        "home": "/home/agent",
        "cwd": "/home/agent/clones/example-app",
        "tmpfs": ["/tmp"],
        "system_ro": ["/usr", "/etc", "/lib", "/lib64", "/bin", "/sbin"],
        "gate_dir": "/run/forcecage",
        "gate_dir_sandbox": "/run/forcecage",
        "binds": [],
        "env_allowlist": ["PATH", "TERM", "LANG", "LC_ALL"],
        "env": {
            "PATH": "/usr/bin:/bin",
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GITHUB_TOKEN": "should-be-dropped",
            "EDITOR": "vim",
        },
        "gate_listen": "127.0.0.1:3128",
        "agent_argv": ["pi", "--version"],
    }
    base.update(over)
    return base


def env_pairs(argv):
    """The {(--setenv NAME)} -> VALUE mapping, preserving order."""
    out = []
    i = 0
    while i < len(argv):
        if argv[i] == "--setenv":
            out.append((argv[i + 1], argv[i + 2]))
            i += 3
        else:
            i += 1
    return out


def has_seq(argv, seq):
    """True when `seq` occurs as a contiguous run in argv."""
    n = len(seq)
    return any(argv[i:i + n] == seq for i in range(len(argv) - n + 1))


class BuildArgv(unittest.TestCase):
    def test_head_is_bwrap_unshared_dying(self):
        argv = build_argv(cfg())
        self.assertEqual(argv[0], "bwrap")
        for flag in ("--unshare-all", "--die-with-parent"):
            self.assertIn(flag, argv)
        # no --new-session: a fullscreen TUI needs the controlling tty
        self.assertNotIn("--new-session", argv)
        # core mounts present
        for flag in ("--dev", "/dev", "--proc", "/proc"):
            self.assertIn(flag, argv)

    def test_system_dirs_are_readonly(self):
        argv = build_argv(cfg())
        for d in ["/usr", "/etc", "/lib", "/lib64", "/bin", "/sbin"]:
            self.assertTrue(has_seq(argv, ["--ro-bind", d, d]), f"{d} not ro-bound")

    def test_home_is_tmpfs_and_home_env_set(self):
        argv = build_argv(cfg())
        # home is a tmpfs
        self.assertTrue(has_seq(argv, ["--tmpfs", "/home/agent"]))
        # HOME points at the sandbox home
        env = dict(env_pairs(argv))
        self.assertEqual(env["HOME"], "/home/agent")

    def test_env_allowlist_only(self):
        argv = build_argv(cfg())
        names = [n for n, _ in env_pairs(argv)]
        # allowed passthroughs present
        for keep in ("PATH", "TERM", "LANG", "LC_ALL"):
            self.assertIn(keep, names)
        # non-allowlisted names dropped
        for drop in ("GITHUB_TOKEN", "EDITOR"):
            self.assertNotIn(drop, names)
        # the value that was dropped does not appear anywhere in the argv
        self.assertNotIn("should-be-dropped", argv)

    def test_absent_allowlist_var_is_skipped(self):
        argv = build_argv(cfg(env={
            "PATH": "/usr/bin:/bin",
            "TERM": "xterm-256color",
            # LANG and LC_ALL not set in the host env
        }))
        env = dict(env_pairs(argv))
        self.assertNotIn("LANG", env)
        self.assertNotIn("LC_ALL", env)
        self.assertIn("PATH", env)

    def test_contract_env_vars_are_forwarded_without_allowlist(self):
        # The agent-contract vars (the tripwire halt marker + hook, PI_TRIPWIRE,
        # CODEX_HOME, and the Grant-service coordinates -- the in-Sandbox gate
        # dir + the orc-grant CLI path the agent's narrow CLI needs) are part of
        # the Sandbox contract: agent-pane sets them for the agent it is about
        # to run, and orc-sandbox must forward them even though the operator's
        # allowlist does not name them -- without them the tripwire hook cannot
        # find the halt marker, codex loses its per-run config, and the agent
        # cannot reach the Grant service, all silently.
        argv = build_argv(cfg(env={
            "PATH": "/usr/bin:/bin",
            "TERM": "xterm-256color",
            "FORCECAGE_TRIPWIRE_HALT_FILE": "/run/forcecage/tripwire-halt",
            "FORCECAGE_TRIPWIRE_HOOK": "/home/agent/bin/tripwire-hook",
            "PI_TRIPWIRE": "on",
            "CODEX_HOME": "/home/agent/codex-run",
            "FORCECAGE_GRANT_BIN": "/home/agent/bin/orc-grant",
            "FORCECAGE_SANDBOX_GATE_DIR": "/run/forcecage",
        }))
        env = dict(env_pairs(argv))
        self.assertEqual(env["FORCECAGE_TRIPWIRE_HALT_FILE"], "/run/forcecage/tripwire-halt")
        self.assertEqual(env["FORCECAGE_TRIPWIRE_HOOK"], "/home/agent/bin/tripwire-hook")
        self.assertEqual(env["PI_TRIPWIRE"], "on")
        self.assertEqual(env["CODEX_HOME"], "/home/agent/codex-run")
        self.assertEqual(env["FORCECAGE_GRANT_BIN"], "/home/agent/bin/orc-grant")
        self.assertEqual(env["FORCECAGE_SANDBOX_GATE_DIR"], "/run/forcecage")

    def test_absent_contract_env_var_is_not_set(self):
        argv = build_argv(cfg())
        env = dict(env_pairs(argv))
        for name in ("FORCECAGE_TRIPWIRE_HALT_FILE", "FORCECAGE_TRIPWIRE_HOOK",
                     "PI_TRIPWIRE", "CODEX_HOME",
                     "FORCECAGE_GRANT_BIN", "FORCECAGE_SANDBOX_GATE_DIR"):
            self.assertNotIn(name, env)

    def test_proxy_and_ca_vars_are_derived(self):
        argv = build_argv(cfg())
        env = dict(env_pairs(argv))
        proxy = "http://127.0.0.1:3128"
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            self.assertEqual(env[k], proxy)
        self.assertIn("127.0.0.1", env["NO_PROXY"])
        self.assertIn("localhost", env["NO_PROXY"])
        self.assertEqual(env["NODE_EXTRA_CA_CERTS"], "/run/forcecage/ca.crt")
        self.assertEqual(env["SSL_CERT_FILE"], "/run/forcecage/bundle.crt")
        self.assertEqual(env["CODEX_CA_CERTIFICATE"], "/run/forcecage/ca.crt")
        self.assertEqual(env["GIT_SSL_CAINFO"], "/run/forcecage/bundle.crt")

    def test_cwd_is_chdir(self):
        argv = build_argv(cfg(cwd="/home/agent/clones/example-app"))
        i = argv.index("--chdir")
        self.assertEqual(argv[i + 1], "/home/agent/clones/example-app")

    def test_cwd_defaults_to_home(self):
        c = cfg()
        del c["cwd"]
        argv = build_argv(c)
        i = argv.index("--chdir")
        self.assertEqual(argv[i + 1], "/home/agent")

    def test_ro_and_rw_binds(self):
        argv = build_argv(cfg(binds=[
            ("/home/agent/.config", "/home/agent/.config", True),
            ("/home/agent/clones/example-app", "/home/agent/clones/example-app", False),
        ]))
        # ro-bind for the config dir
        self.assertTrue(has_seq(argv, ["--ro-bind", "/home/agent/.config", "/home/agent/.config"]))
        # plain (writable) bind for the clone
        self.assertTrue(has_seq(argv, ["--bind", "/home/agent/clones/example-app", "/home/agent/clones/example-app"]))

    def test_gate_dir_is_a_narrow_view(self):
        # the host gate dir is NOT bound whole: only the CA, the bundle, the
        # gate socket and the grant queue's parent tmpfs land in the Sandbox,
        # so the agent cannot see the minted secrets, the Vault token, the
        # mgmt token, state.json, in-host, or the AppRole files.
        argv = build_argv(cfg())
        self.assertFalse(has_seq(argv, ["--ro-bind", "/run/forcecage", "/run/forcecage"]),
                         "the whole host gate dir must not be bound")
        self.assertTrue(has_seq(argv, ["--tmpfs", "/run/forcecage"]))
        self.assertTrue(has_seq(argv, ["--ro-bind", "/run/forcecage/ca.crt", "/run/forcecage/ca.crt"]))
        self.assertTrue(has_seq(argv, ["--ro-bind", "/run/forcecage/bundle.crt", "/run/forcecage/bundle.crt"]))
        self.assertTrue(has_seq(argv, ["--ro-bind", "/run/forcecage/gate.sock", "/run/forcecage/gate.sock"]))
        self.assertTrue(has_seq(argv, ["--tmpfs", "/run/forcecage/grant"]))
        # no other host-gate file may be named anywhere in the argv
        for secretish in ("vault-token.json", "mgmt-token", "state.json", "in-host",
                          "placeholders.json", "role-id", "secret-id"):
            self.assertNotIn(secretish, argv)

    def test_gate_narrow_view_with_separate_host_path(self):
        # host gate dir != in-Sandbox path: the file binds map host->sandbox
        argv = build_argv(cfg(gate_dir="/host/gate-x",
                              gate_dir_sandbox="/run/forcecage"))
        self.assertTrue(has_seq(argv, ["--tmpfs", "/run/forcecage"]))
        self.assertTrue(has_seq(argv, ["--ro-bind", "/host/gate-x/ca.crt", "/run/forcecage/ca.crt"]))
        self.assertTrue(has_seq(argv, ["--ro-bind", "/host/gate-x/bundle.crt", "/run/forcecage/bundle.crt"]))
        self.assertTrue(has_seq(argv, ["--ro-bind", "/host/gate-x/gate.sock", "/run/forcecage/gate.sock"]))
        self.assertTrue(has_seq(argv, ["--tmpfs", "/run/forcecage/grant"]))

    def test_gate_custom_socket_name_binds_host_basenames(self):
        # the host socket is <host gate dir>/<basename of the in-Sandbox socket>
        argv = build_argv(cfg(gate_dir="/host/gate-x",
                              gate_dir_sandbox="/run/gate-y",
                              gate_socket="/run/gate-y/tunnel.sock"))
        self.assertTrue(has_seq(argv, ["--ro-bind", "/host/gate-x/tunnel.sock", "/run/gate-y/tunnel.sock"]))
        self.assertFalse(has_seq(argv, ["--ro-bind", "/host/gate-x/gate.sock", "/run/gate-y/tunnel.sock"]))

    def test_gate_tmpfs_precedes_file_binds_and_caller_binds(self):
        # load-bearing ordering: the gate tmpfs (and the grant-dir tmpfs) must
        # come before any bind into them, or a later tmpfs wipes the bind
        argv = build_argv(cfg(binds=[
            ("/host/gate/grant/in-agent", "/run/forcecage/grant/in-agent", False),
            ("/host/gate/grant/out", "/run/forcecage/grant/out", True),
        ]))
        tmpfs_gate = argv.index("/run/forcecage")
        bind_ca = argv.index("/run/forcecage/ca.crt")
        tmpfs_grant = argv.index("/run/forcecage/grant")
        bind_in_agent = argv.index("/run/forcecage/grant/in-agent")
        bind_out = argv.index("/run/forcecage/grant/out")
        self.assertLess(tmpfs_gate, bind_ca)
        self.assertLess(tmpfs_grant, bind_in_agent)
        self.assertLess(tmpfs_grant, bind_out)
        # the queue subdirs the caller binds
        self.assertTrue(has_seq(argv, ["--bind", "/host/gate/grant/in-agent", "/run/forcecage/grant/in-agent"]))
        self.assertTrue(has_seq(argv, ["--ro-bind", "/host/gate/grant/out", "/run/forcecage/grant/out"]))

    def test_forwarder_command_present(self):
        argv = build_argv(cfg(agent_argv=["pi", "--version"]))
        # the in-sandbox command is a bash -c that starts socat then execs
        i = argv.index("bash")
        self.assertEqual(argv[i + 1], "-c")
        script = argv[i + 2]
        self.assertIn("socat", script)
        self.assertIn("TCP-LISTEN:3128", script)
        self.assertIn("bind=127.0.0.1", script)
        self.assertIn("UNIX-CONNECT:/run/forcecage/gate.sock", script)
        self.assertIn("exec", script)
        # the agent argv is appended after the bash -c script and its $0
        self.assertEqual(argv[i + 4:], ["pi", "--version"])

    def test_forwarder_uses_custom_gate_socket(self):
        argv = build_argv(cfg(gate_dir_sandbox="/run/gate-x",
                              gate_listen="127.0.0.1:4321"))
        script = argv[argv.index("-c") + 1]
        self.assertIn("TCP-LISTEN:4321", script)
        self.assertIn("UNIX-CONNECT:/run/gate-x/gate.sock", script)

    def test_tmpfs_precedes_bind_into_it(self):
        # the load-bearing ordering: a tmpfs of a parent must come before any
        # bind into that parent, or the later tmpfs wipes the bind
        argv = build_argv(cfg(binds=[
            ("/host/cfg", "/home/agent/.config", True),
        ]))
        tmpfs_home = argv.index("/home/agent")  # the --tmpfs /home/agent dest
        bind_cfg = argv.index("/home/agent/.config")
        self.assertLess(tmpfs_home, bind_cfg)

    def test_tmpfs_tmp_precedes_bind_into_tmp(self):
        argv = build_argv(cfg(binds=[
            ("/host/stuff", "/tmp/inside", False),
        ]))
        tmpfs_tmp = argv.index("/tmp")
        bind_tmp = argv.index("/tmp/inside")
        self.assertLess(tmpfs_tmp, bind_tmp)

    def test_command_is_last(self):
        argv = build_argv(cfg(agent_argv=["codex", "exec"]))
        self.assertEqual(argv[-2:], ["codex", "exec"])

    def test_no_credential_leaks_into_argv(self):
        argv = build_argv(cfg(env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/home/agent",  # must be overridden by the sandbox home
            "SECRET_TOKEN": "abc123",
        }))
        self.assertNotIn("abc123", argv)
        env = dict(env_pairs(argv))
        self.assertEqual(env["HOME"], "/home/agent")


if __name__ == "__main__":
    unittest.main(verbosity=2)
