#!/usr/bin/env python3
"""Unit tests for cage.cli: the forcecage command surface.

The surface is deliberately small: ``run`` (absorb the whole cage -- the
agent-user hop, the gate, the bwrap layout, the grant service, teardown),
``check`` (verify the host prerequisites before a run), and ``version``.
Arg parsing is pure; ``run`` dispatches to ``cage.run`` lazily so this module
is testable before the run orchestration exists.
"""
import io
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import cage.cli as cli  # noqa: E402


class ParseRun(unittest.TestCase):
    def test_full_run(self):
        r = cli.parse_args([
            "run", "--bindings", "/x/bindings.json",
            "pi", "/home/agent/clones/example-app", "/home/agent/bin/pi",
            "--", "-p", "hello", "--model", "m"])
        self.assertEqual(r.command, "run")
        self.assertEqual(r.agent, "pi")
        self.assertEqual(r.clone, "/home/agent/clones/example-app")
        self.assertEqual(r.binary, "/home/agent/bin/pi")
        self.assertEqual(r.agent_args, ["-p", "hello", "--model", "m"])
        self.assertEqual(r.bindings_path, "/x/bindings.json")

    def test_run_with_no_agent_args(self):
        r = cli.parse_args(["run", "claude", "/c", "/b", "--"])
        self.assertEqual(r.agent_args, [])

    def test_run_requires_separator(self):
        with self.assertRaises(SystemExit):
            cli.parse_args(["run", "pi", "/c", "/b", "-p", "hello"])

    def test_run_config_flag(self):
        r = cli.parse_args(["--config", "/x/forcecage.toml", "run",
                             "pi", "/c", "/b", "--"])
        self.assertEqual(r.config_path, "/x/forcecage.toml")


class ParseCheck(unittest.TestCase):
    def test_check(self):
        r = cli.parse_args(["check"])
        self.assertEqual(r.command, "check")

    def test_check_with_bindings(self):
        r = cli.parse_args(["--config", "/x.toml", "check", "--bindings", "/b.json"])
        self.assertEqual(r.command, "check")
        self.assertEqual(r.config_path, "/x.toml")
        self.assertEqual(r.bindings_path, "/b.json")


class ParseVersion(unittest.TestCase):
    def test_version(self):
        r = cli.parse_args(["version"])
        self.assertEqual(r.command, "version")

    def test_version_main(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.main(["version"]), 0)
        self.assertIn("forcecage", buf.getvalue())


class MainDispatch(unittest.TestCase):
    def test_no_command_fails(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                cli.main([])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_unknown_agent_rejected(self):
        # run validates the agent name (pi/claude/codex)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.main(["run", "weird", "/c", "/b", "--"])


class ParseTripwireHook(unittest.TestCase):
    def test_parse_claude(self):
        r = cli.parse_args(["tripwire-hook", "claude"])
        self.assertEqual(r.command, "tripwire-hook")
        self.assertEqual(r.agent, "claude")

    def test_parse_codex(self):
        r = cli.parse_args(["tripwire-hook", "codex"])
        self.assertEqual(r.agent, "codex")


class TripwireHookBin(unittest.TestCase):
    def test_override_wins(self):
        with mock.patch.dict(os.environ, {"FORCECAGE_TRIPWIRE_BIN": "/x/hook"}):
            self.assertEqual(cli._tripwire_bin(), "/x/hook")

    def test_falls_back_to_repo_local(self):
        env = {k: v for k, v in os.environ.items() if k != "FORCECAGE_TRIPWIRE_BIN"}
        with mock.patch.dict(os.environ, env, clear=True):
            bin_path = cli._tripwire_bin()
        # In the forcecage checkout the repo-local bin exists and is the fallback.
        self.assertTrue(bin_path is None or os.path.isfile(bin_path))


class TripwireHookDispatch(unittest.TestCase):
    def test_unknown_agent(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.main(["tripwire-hook", "weird"])

    def test_execs_node_with_bin_and_agent(self):
        req = cli.parse_args(["tripwire-hook", "claude"])
        with mock.patch("shutil.which", return_value="/usr/bin/node"), \
                mock.patch("cage.cli.subprocess.run",
                           return_value=mock.Mock(returncode=0)) as run:
            self.assertEqual(cli.cmd_tripwire_hook(req), 0)
        run.assert_called_once()
        args = run.call_args[0][0]
        self.assertEqual(args[0], "/usr/bin/node")
        self.assertEqual(args[2], "claude")

    def test_node_missing(self):
        req = cli.parse_args(["tripwire-hook", "claude"])
        with mock.patch("shutil.which", return_value=None):
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    cli.cmd_tripwire_hook(req)


if __name__ == "__main__":
    unittest.main()
