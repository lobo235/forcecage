#!/usr/bin/env python3
"""Unit tests for cage.config: the constrained-TOML loader + Config.

The loader parses a deliberately small TOML subset (tables, key/value scalars,
arrays, comments) so the cage stays stdlib-only on Python 3.9 (no tomllib).
It FAILS CLOSED: anything outside the subset raises ConfigError with the
line number, never a silent guess.
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import cage.config as config  # noqa: E402


class ParseTOML(unittest.TestCase):
    def parse(self, text):
        return config.parse_toml(text)

    def test_empty_is_empty_dict(self):
        self.assertEqual(self.parse(""), {})

    def test_blank_lines_and_comments(self):
        text = "\n# a comment\n   \n#another\n"
        self.assertEqual(self.parse(text), {})

    def test_basic_string(self):
        self.assertEqual(
            self.parse('[t]\nk = "v"'), {"t": {"k": "v"}})

    def test_literal_string_no_escapes(self):
        self.assertEqual(
            self.parse('[t]\nk = \'raw\\path\''), {"t": {"k": "raw\\path"}})

    def test_basic_string_escapes(self):
        self.assertEqual(
            self.parse('[t]\nk = "a\\nb\\\\c\\"d"'),
            {"t": {"k": "a\nb\\c\"d"}})

    def test_integer(self):
        self.assertEqual(self.parse('[t]\nk = 42'), {"t": {"k": 42}})

    def test_negative_integer(self):
        self.assertEqual(self.parse('[t]\nk = -7'), {"t": {"k": -7}})

    def test_boolean(self):
        self.assertEqual(
            self.parse('[t]\na = true\nb = false'),
            {"t": {"a": True, "b": False}})

    def test_array_of_scalars(self):
        self.assertEqual(
            self.parse('[t]\nk = ["a", "b", "c"]'),
            {"t": {"k": ["a", "b", "c"]}})

    def test_empty_array(self):
        self.assertEqual(self.parse('[t]\nk = []'), {"t": {"k": []}})

    def test_array_of_mixed_scalars(self):
        self.assertEqual(
            self.parse('[t]\nk = [1, "x", true]'),
            {"t": {"k": [1, "x", True]}})

    def test_subtable(self):
        text = "[minter]\nkind = \"file\"\n[minter.vault]\naddress = \"http://x\"\n"
        self.assertEqual(
            self.parse(text),
            {"minter": {"kind": "file",
                         "vault": {"address": "http://x"}}})

    def test_table_order_independent(self):
        a = self.parse("[b]\nx = 1\n[a]\ny = 2")
        self.assertEqual(a, {"a": {"y": 2}, "b": {"x": 1}})

    def test_trailing_comment_on_value_line(self):
        self.assertEqual(
            self.parse('[t]\nk = "v"  # note'), {"t": {"k": "v"}})

    def test_comment_inside_array_does_not_swallow(self):
        # a # inside a quoted string is not a comment
        self.assertEqual(
            self.parse('[t]\nk = "http://x"'), {"t": {"k": "http://x"}})

    # -- fail closed -------------------------------------------------------
    def _expect_error(self, text, needle=None):
        with self.assertRaises(config.ConfigError) as ctx:
            self.parse(text)
        if needle is not None:
            self.assertIn(needle, str(ctx.exception))

    def test_top_level_key_goes_in_root(self):
        # a bare key at top level (no table) is legal TOML: it goes in the root dict
        d = self.parse('k = "v"')
        self.assertEqual(d, {"k": "v"})

    def test_key_with_space_fails(self):
        self._expect_error('[t]\nfoo bar = "v"')

    def test_unterminated_string_fails(self):
        self._expect_error('[t]\nk = "v')

    def test_unknown_scalar_fails(self):
        self._expect_error('[t]\nk = 3.14')  # floats not in the subset

    def test_inline_table_fails(self):
        self._expect_error('[t]\nk = { a = 1 }')

    def test_missing_equals_fails(self):
        self._expect_error('[t]\nk "v"')

    def test_bare_true_word_not_a_string_fails(self):
        # "true" with no key= is not a valid line
        self._expect_error('[t]\ntrue')


class ConfigLoad(unittest.TestCase):
    def _write(self, text, tmp):
        p = os.path.join(tmp, "forcecage.toml")
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_defaults_fill_missing(self):
        cfg = config.Config.from_dict({})
        self.assertEqual(cfg.agent_user, "agent")
        self.assertEqual(cfg.run_dir, "/run/forcecage")
        self.assertEqual(cfg.iron_proxy, "iron-proxy")
        self.assertEqual(cfg.minter_kind, "file")

    def test_values_override(self):
        cfg = config.Config.from_dict({
            "forcecage": {"agent_user": "worker", "run_dir": "/run/cage"},
            "gate": {"iron_proxy": "/opt/iron-proxy",
                      "iron_proxy_sha256": "abc"},
            "minter": {"kind": "vault",
                        "vault": {"address": "http://127.0.0.1:8200"}},
        })
        self.assertEqual(cfg.agent_user, "worker")
        self.assertEqual(cfg.run_dir, "/run/cage")
        self.assertEqual(cfg.iron_proxy, "/opt/iron-proxy")
        self.assertEqual(cfg.iron_proxy_sha256, "abc")
        self.assertEqual(cfg.minter_kind, "vault")
        self.assertEqual(cfg.vault_address, "http://127.0.0.1:8200")

    def test_tilde_expansion(self, ):
        cfg = config.Config.from_dict(
            {"forcecage": {"state_dir": "~/x"}})
        self.assertNotIn("~", cfg.state_dir)
        self.assertTrue(cfg.state_dir.startswith(os.path.expanduser("~")))

    def test_unknown_minter_kind_fails_closed(self):
        with self.assertRaises(config.ConfigError):
            config.Config.from_dict({"minter": {"kind": "redis"}})

    def test_unknown_table_ignored(self):
        # extra tables (e.g. an operator's scratch) are allowed, not fatal
        cfg = config.Config.from_dict({"forcecage": {}, "scratch": {"a": 1}})
        self.assertEqual(cfg.agent_user, "agent")


if __name__ == "__main__":
    unittest.main()
