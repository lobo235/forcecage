#!/usr/bin/env python3
"""Unit tests for cage.agent_pane: the Agent-user half of a forcecage run.

The spawn points (Sandbox, Grant service) and the config loader are injected,
so the whole composition -- request parsing, scratch-root prep, bwrap config,
grant argv, halt mapping, teardown -- is exercised without a live host.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import cage.agent_pane as ap  # noqa: E402
from cage.config import Config  # noqa: E402


class FakeProc:
    def __init__(self, rc=0):
        self.rc = rc
        self.waited = False
        self.pid = 12345

    def wait(self):
        self.waited = True
        return self.rc

    def terminate(self):
        pass

    def kill(self):
        pass


class RequestTest(unittest.TestCase):
    def test_parses_flags_and_agent_args(self):
        req = ap.agent_pane_request([
            "--run-id", "r1",
            "--config", "/c.toml",
            "--gate-dir", "/g",
            "--proxy-port", "3128",
            "--gate-tunnel-socket", "/g/gate.sock",
            "--clone", "/clone",
            "--agent-user", "agent",
            "--", "-p", "hello",
        ])
        self.assertEqual(req["run_id"], "r1")
        self.assertEqual(req["config_path"], "/c.toml")
        self.assertEqual(req["gate_dir"], "/g")
        self.assertEqual(req["proxy_port"], 3128)
        self.assertEqual(req["gate_tunnel"], "/g/gate.sock")
        self.assertEqual(req["clone"], "/clone")
        self.assertEqual(req["agent_user"], "agent")
        self.assertEqual(req["agent"], ["-p", "hello"])

    def test_agent_args_with_own_flags(self):
        req = ap.agent_pane_request([
            "--run-id", "r1", "--config", "/c.toml", "--gate-dir", "/g",
            "--proxy-port", "1", "--gate-tunnel-socket", "/g/gate.sock",
            "--", "--model", "x", "-p", "hi",
        ])
        self.assertEqual(req["agent"], ["--model", "x", "-p", "hi"])

    def test_optional_flags_default(self):
        req = ap.agent_pane_request([
            "--run-id", "r1", "--config", "/c.toml", "--gate-dir", "/g",
            "--proxy-port", "1", "--gate-tunnel-socket", "/g/gate.sock",
            "--", "pi",
        ])
        self.assertIsNone(req["clone"])
        self.assertIsNone(req["agent_user"])
        self.assertEqual(req["agent"], ["pi"])


class GateSockPathTest(unittest.TestCase):
    def test_basename_preserved_under_fixed_dir(self):
        self.assertEqual(
            ap.gate_sock_sandbox_path("/run/forcecage/gate.sock"),
            "/run/forcecage/gate.sock")

    def test_other_gate_dir(self):
        self.assertEqual(
            ap.gate_sock_sandbox_path("/state/gate/gate.sock"),
            "/run/forcecage/gate.sock")


class BwrapConfigTest(unittest.TestCase):
    def _req(self, clone="/clone"):
        return {"gate_dir": "/g", "proxy_port": 3128,
                "gate_tunnel": "/g/gate.sock", "clone": clone, "agent": ["pi"]}

    def test_gate_listen(self):
        cfg = ap.bwrap_config(self._req(), {})
        self.assertEqual(cfg["gate_listen"], "127.0.0.1:3128")

    def test_gate_narrow_view_paths(self):
        cfg = ap.bwrap_config(self._req(), {})
        self.assertEqual(cfg["gate_dir"], "/g")
        self.assertEqual(cfg["gate_dir_sandbox"], "/run/forcecage")
        self.assertEqual(cfg["gate_socket"], "/run/forcecage/gate.sock")

    def test_clone_rw_bind(self):
        cfg = ap.bwrap_config(self._req(), {})
        self.assertIn(("/clone", "/clone", False), cfg["binds"])

    def test_grant_queue_binds(self):
        cfg = ap.bwrap_config(self._req(), {})
        self.assertIn(("/g/grant/in-agent", "/run/forcecage/grant/in-agent", False),
                      cfg["binds"])
        self.assertIn(("/g/grant/out", "/run/forcecage/grant/out", True), cfg["binds"])
        # in-host (the approver's queue) is NOT bound: the agent does not approve
        self.assertNotIn("/g/grant/in-host", [b[0] for b in cfg["binds"]])

    def test_no_clone(self):
        cfg = ap.bwrap_config(self._req(clone=None), {})
        self.assertNotIn(("", "", False), cfg["binds"])
        self.assertEqual(len(cfg["binds"]), 2)  # grant queue only


class GrantArgvTest(unittest.TestCase):
    def test_serve_argv(self):
        req = {"gate_dir": "/g"}
        argv = ap.grant_serve_argv(req, 4242, "/halt.log")
        self.assertEqual(argv[:4],
                         [sys.executable, "-m", "cage.grant", "serve"])
        self.assertIn("--gate-dir", argv)
        self.assertIn("/g", argv)
        self.assertIn("--agent-pid", argv)
        self.assertIn("4242", argv)
        self.assertIn("--halt-file", argv)
        self.assertIn("/halt.log", argv)


class TripwireEnvTest(unittest.TestCase):
    def test_contract_vars(self):
        env = ap.tripwire_bwrap_env("/h.jsonl", "/c.json", "/clone/.forcecage-halt")
        self.assertEqual(env["FC_TRIPWIRE_HALTS"], "/h.jsonl")
        self.assertEqual(env["FC_TRIPWIRE_CANARY"], "/c.json")
        self.assertEqual(env["FORCECAGE_TRIPWIRE_HALT_FILE"], "/clone/.forcecage-halt")
        self.assertEqual(env["PI_TRIPWIRE"], "on")
        self.assertNotIn("FC_TRIPWIRE_NOTIFY", env)

    def test_notify(self):
        env = ap.tripwire_bwrap_env("/h", "/c", "/m", notify="/notify")
        self.assertEqual(env["FC_TRIPWIRE_NOTIFY"], "/notify")


class PaneMainTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="fc-pane-home-")
        self._old_home = os.environ.get("HOME")
        os.environ["HOME"] = self.home
        self.gate = tempfile.mkdtemp(prefix="fc-pane-gate-")
        self.clone = tempfile.mkdtemp(prefix="fc-pane-clone-")

    def tearDown(self):
        if self._old_home is None:
            del os.environ["HOME"]
        else:
            os.environ["HOME"] = self._old_home

    def _req(self):
        return {
            "run_id": "r1",
            "config_path": "/does/not/matter.toml",
            "gate_dir": self.gate,
            "proxy_port": 3128,
            "gate_tunnel": self.gate + "/gate.sock",
            "clone": self.clone,
            "agent_user": "agent",
            "tripwire_notify": None,
            "agent": ["pi", "-p", "hi"],
        }

    def _cfg(self):
        return Config.from_dict({})

    def test_spawns_sandbox_and_grant(self):
        starts = []

        def spawn(env, argv):
            starts.append(("sandbox", argv))
            return FakeProc(rc=0)

        def spawn_bg(env, argv):
            starts.append(("grant", argv))
            return FakeProc(rc=0)

        rc = ap.agent_pane_main(self._req(), spawn=spawn, spawn_bg=spawn_bg,
                                load_config_fn=lambda p: self._cfg(),
                                build_bwrap=lambda cfg: ["bwrap", "x"])
        self.assertEqual(rc, 0)
        self.assertEqual([k for k, _ in starts], ["sandbox", "grant"])
        grant_argv = [a for k, a in starts if k == "grant"][0]
        self.assertIn("serve", grant_argv)
        self.assertIn(self.gate, grant_argv)

    def test_agent_rc_propagates(self):
        def spawn(env, argv):
            return FakeProc(rc=7)
        rc = ap.agent_pane_main(self._req(), spawn=spawn,
                                spawn_bg=lambda e, a: FakeProc(),
                                load_config_fn=lambda p: self._cfg(),
                                build_bwrap=lambda cfg: ["bwrap"])
        self.assertEqual(rc, 7)

    def test_halt_marker_maps_to_exit_3(self):
        def spawn(env, argv):
            # the sandbox "runs" and a hook plants the halt marker
            with open(self.clone + "/.forcecage-halt", "w") as fh:
                fh.write("HOLD")
            return FakeProc(rc=0)  # the agent itself returned 0
        rc = ap.agent_pane_main(self._req(), spawn=spawn,
                                spawn_bg=lambda e, a: FakeProc(),
                                load_config_fn=lambda p: self._cfg(),
                                build_bwrap=lambda cfg: ["bwrap"])
        self.assertEqual(rc, 3)

    def test_agent_exit_3_unchanged(self):
        def spawn(env, argv):
            return FakeProc(rc=3)  # the agent's own tripwire halted it
        rc = ap.agent_pane_main(self._req(), spawn=spawn,
                                spawn_bg=lambda e, a: FakeProc(),
                                load_config_fn=lambda p: self._cfg(),
                                build_bwrap=lambda cfg: ["bwrap"])
        self.assertEqual(rc, 3)

    def test_stale_halt_marker_truncated(self):
        with open(self.clone + "/.forcecage-halt", "w") as fh:
            fh.write("stale")
        rc = ap.agent_pane_main(self._req(),
                                spawn=lambda e, a: FakeProc(rc=0),
                                spawn_bg=lambda e, a: FakeProc(),
                                load_config_fn=lambda p: self._cfg(),
                                build_bwrap=lambda cfg: ["bwrap"])
        self.assertEqual(rc, 0)
        with open(self.clone + "/.forcecage-halt") as fh:
            self.assertEqual(fh.read(), "")

    def test_scratch_root_and_canary(self):
        rc = ap.agent_pane_main(self._req(),
                                spawn=lambda e, a: FakeProc(rc=0),
                                spawn_bg=lambda e, a: FakeProc(),
                                load_config_fn=lambda p: self._cfg(),
                                build_bwrap=lambda cfg: ["bwrap"])
        self.assertEqual(rc, 0)
        run_dir = os.path.join(self.home, ".local/state/forcecage/runs/r1")
        self.assertTrue(os.path.isdir(run_dir))
        halts = os.path.join(run_dir, "halts-r1.jsonl")
        canary = os.path.join(run_dir, "canary-r1.json")
        self.assertTrue(os.path.isfile(canary))
        doc = json.loads(open(canary).read())
        self.assertEqual(doc["run_id"], "r1")

    def test_grant_catalog_forwarded(self):
        cfg = Config.from_dict({"gate": {"grant_catalog": "/cat.json"}})
        starts = []

        def spawn_bg(env, argv):
            starts.append(argv)
            return FakeProc(rc=0)
        ap.agent_pane_main(self._req(), spawn=lambda e, a: FakeProc(rc=0),
                           spawn_bg=spawn_bg, load_config_fn=lambda p: cfg,
                           build_bwrap=lambda cfg2: ["bwrap"])
        self.assertIn("--catalog", starts[0])
        self.assertIn("/cat.json", starts[0])

    def test_vault_minter_forwards_vault_flags(self):
        cfg = Config.from_dict({
            "minter": {"kind": "vault",
                       "vault": {"address": "http://v:8200",
                                 "role_id_file": "/rid",
                                 "secret_id_file": "/sid"}}})
        starts = []

        def spawn_bg(env, argv):
            starts.append(argv)
            return FakeProc(rc=0)
        ap.agent_pane_main(self._req(), spawn=lambda e, a: FakeProc(rc=0),
                           spawn_bg=spawn_bg, load_config_fn=lambda p: cfg,
                           build_bwrap=lambda cfg2: ["bwrap"])
        argv = starts[0]
        self.assertIn("--vault-addr", argv)
        self.assertIn("http://v:8200", argv)


if __name__ == "__main__":
    unittest.main()
