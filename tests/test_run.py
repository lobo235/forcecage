#!/usr/bin/env python3
"""Unit tests for cage.run: the operator-side orchestration of a forcecage run.

The four external seams (gate start, the sudo hop, gate stop, the readiness
wait) are injected, so the composition order, the argv it builds, the env it
hands to the agent, and the teardown (incl. the not-ready failure path) are
all verified without a live host.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import cage.run as run  # noqa: E402


class FakeProc:
    def __init__(self, rc=0):
        self.rc = rc

    def wait(self):
        return self.rc


class FakeReq:
    def __init__(self, **over):
        self.command = "run"
        self.config_path = over.get("config_path")
        self.bindings_path = over.get("bindings_path")
        self.agent = over.get("agent", "pi")
        self.clone = over.get("clone", "/home/agent/clones/x")
        self.binary = over.get("binary", "/usr/bin/pi")
        self.agent_args = over.get("agent_args", ["-p", "hi"])


def _config_file(state_dir, sections=None):
    lines = ["[forcecage]", 'state_dir = "%s"' % state_dir]
    for sec, kv in (sections or {}).items():
        lines.append("[%s]" % sec)
        for k, v in kv.items():
            if isinstance(v, str):
                lines.append('%s = "%s"' % (k, v))
            elif isinstance(v, (list, tuple)):
                lines.append("%s = [%s]" % (k, ", ".join('"%s"' % x for x in v)))
            elif isinstance(v, bool):
                lines.append("%s = %s" % (k, "true" if v else "false"))
            else:
                lines.append("%s = %s" % (k, v))
    p = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    p.write("\n".join(lines) + "\n")
    p.close()
    return p.name


class ArgvTest(unittest.TestCase):
    def test_gate_start_argv(self):
        cfg = _mk_cfg()
        argv = run.gate_start_argv(cfg, "/g", [1, 2, 3, 4, 5], "/b.json",
                                   {"domains": ["a"], "cidrs": ["127.0.0.1/32"]})
        self.assertEqual(argv[2], "cage.gate")
        self.assertEqual(argv[3], "start")
        self.assertIn("--port-tunnel", argv)
        self.assertIn("3", argv)
        self.assertIn("--bindings", argv)
        self.assertIn("/b.json", argv)
        self.assertIn("--wait", argv)

    def test_gate_stop_argv(self):
        argv = run.gate_stop_argv("/g")
        self.assertEqual(argv[2], "cage.gate")
        self.assertEqual(argv[3], "stop")
        self.assertIn("/g", argv)

    def test_agent_pane_argv(self):
        req = FakeReq()
        cfg = _mk_cfg()
        argv = run.agent_pane_argv(req, cfg, "/g", [10, 20, 30, 40, 50],
                                   "/c.toml", "r1")
        self.assertEqual(argv[2], "cage.agent_pane")
        self.assertIn("--run-id", argv)
        self.assertIn("r1", argv)
        self.assertIn("--config", argv)
        self.assertIn("/c.toml", argv)
        self.assertIn("--gate-dir", argv)
        self.assertIn("/g", argv)
        # the in-Sandbox proxy port is the 2nd of the five ports
        self.assertIn("--proxy-port", argv)
        self.assertIn("20", argv)
        # the gate tunnel socket is the gate's fixed gate.sock
        self.assertIn("--gate-tunnel-socket", argv)
        self.assertIn("/g/gate.sock", argv)
        self.assertIn("--", argv)
        self.assertEqual(argv[argv.index("--") + 1:], ["/usr/bin/pi", "-p", "hi"])

    def test_agent_pane_argv_no_clone(self):
        req = FakeReq(clone=None)
        argv = run.agent_pane_argv(req, _mk_cfg(), "/g", [1, 2, 3, 4, 5],
                                   "/c.toml", "r1")
        self.assertNotIn("--clone", argv)

    def test_hop_argv(self):
        cfg = _mk_cfg()
        argv = run.hop_argv(cfg, ["/x", "-m"])
        self.assertEqual(argv[:4], ["sudo", "-n", "-u", cfg.agent_user])
        self.assertEqual(argv[4:], ["/x", "-m"])

    def test_hop_argv_carries_pythonpath(self):
        cfg = _mk_cfg()
        argv = run.hop_argv(cfg, ["/x"], pythonpath="/staged/cage-src")
        self.assertEqual(argv[:7],
                         ["sudo", "-n", "-u", cfg.agent_user, "env",
                          "PYTHONPATH=/staged/cage-src", "/x"])


class PickPortsTest(unittest.TestCase):
    def test_five_auto_ports(self):
        cfg = _mk_cfg()
        ports = run.pick_ports(cfg)
        self.assertEqual(len(ports), 5)
        self.assertTrue(all(isinstance(p, int) and 0 < p < 65536 for p in ports))

    def test_pinned_ports_honored(self):
        cfg = _mk_cfg()
        cfg.port_tunnel = 4444
        ports = run.pick_ports(cfg)
        self.assertEqual(ports[2], 4444)


class RunFlowTest(unittest.TestCase):
    def _capture(self):
        caps = {"gate": [], "hop": [], "stop": []}
        def spawn_gate(env, argv):
            caps["gate"].append(argv)
            return FakeProc()
        def hop_agent(env, argv):
            caps["hop"].append((env, argv))
            return FakeProc(rc=5)
        def stop_gate(env, argv):
            caps["stop"].append(argv)
            return 0
        return caps, spawn_gate, hop_agent, stop_gate

    def _state(self):
        return tempfile.mkdtemp(prefix="fc-run-state-")

    def test_happy_path(self):
        caps, sg, ha, stg = self._capture()
        state = self._state()
        req = FakeReq(config_path=_config_file(state))
        rc = run.run(req, spawn_gate=sg, hop_agent=ha, stop_gate=stg,
                     wait_ready=lambda path, timeout: True)
        self.assertEqual(rc, 5)
        self.assertEqual(len(caps["gate"]), 1)
        self.assertEqual(len(caps["stop"]), 1)  # teardown happened
        env, argv = caps["hop"][0]
        self.assertIn("cage.agent_pane", argv)
        self.assertIn("FORCECAGE_SANDBOX_GATE_DIR_HOST", env)
        self.assertTrue(env["FORCECAGE_SANDBOX_GATE_DIR_HOST"].startswith(state))

    def test_not_ready_fails_and_tears_down(self):
        caps, sg, ha, stg = self._capture()
        state = self._state()
        req = FakeReq(config_path=_config_file(state))
        rc = run.run(req, spawn_gate=sg, hop_agent=ha, stop_gate=stg,
                     wait_ready=lambda path, timeout: False)
        self.assertEqual(rc, 2)
        self.assertEqual(len(caps["hop"]), 0)  # never reached the agent
        self.assertEqual(len(caps["stop"]), 1)  # still torn down

    def test_vault_minter_env_forwarded(self):
        caps, sg, ha, stg = self._capture()
        state = self._state()
        cfg_path = _config_file(state, {
            "minter": {"kind": "vault"},
            "minter.vault": {"address": "http://127.0.0.1:8200"}})
        req = FakeReq(config_path=cfg_path)
        run.run(req, spawn_gate=sg, hop_agent=ha, stop_gate=stg,
                wait_ready=lambda p, t: True)
        env, _ = caps["hop"][0]
        self.assertEqual(env.get("FORCECAGE_GRANT_VAULT_ADDR"), "http://127.0.0.1:8200")

    def test_bindings_written_to_gate_dir(self):
        caps, sg, ha, stg = self._capture()
        state = self._state()
        bpath = os.path.join(state, "b.json")
        with open(bpath, "w") as fh:
            json.dump([{"name": "a", "host": "h", "placeholder": "P", "value": "v"}], fh)
        req = FakeReq(config_path=_config_file(state), bindings_path=bpath)
        run.run(req, spawn_gate=sg, hop_agent=ha, stop_gate=stg,
                wait_ready=lambda p, t: True)
        gate_dir = os.path.join(state, "gate")
        self.assertTrue(os.path.isfile(os.path.join(gate_dir, "bindings.json")))

    def test_tear_down_even_if_agent_errors(self):
        caps = {"stop": []}
        def hop_agent(env, argv):
            p = FakeProc(rc=0)
            p.wait = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
            return p
        with self.assertRaises(RuntimeError):
            run.run(FakeReq(config_path=_config_file(self._state())),
                    spawn_gate=lambda e, a: FakeProc(),
                    hop_agent=hop_agent,
                    stop_gate=lambda e, a: caps["stop"].append(a) or 0,
                    wait_ready=lambda p, t: True)
        self.assertEqual(len(caps["stop"]), 1)  # teardown in finally


def _mk_cfg():
    from cage.config import Config
    return Config.from_dict({})


if __name__ == "__main__":
    unittest.main()
