#!/usr/bin/env python3
"""Unit tests for cage.check: the host-prerequisite verification.

The host probes (id / sudo) are injected; the fs checks (iron-proxy,
bindings) run against temp files. The bwrap check is asserted against the
real PATH so it reports exactly what is true on this host.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import cage.check as check  # noqa: E402
import cage.config as config  # noqa: E402


def _probe(mapping):
    """A probe that answers (id -u / sudo) from mapping keyed by a token."""
    def p(args):
        if args[:2] == ["id", "-u"]:
            return mapping.get("id", (0, "", ""))
        if args[:3] == ["sudo", "-n", "-u"]:
            return mapping.get("sudo", (0, "", ""))
        return (127, "", "unexpected %r" % args)
    return p


class CheckHostTest(unittest.TestCase):
    def _cfg(self, **over):
        cfg = config.Config.from_dict({})
        for k, v in over.items():
            setattr(cfg, k, v)
        return cfg

    def test_all_green(self):
        iron = os.path.join(tempfile.mkdtemp(), "iron")
        with open(iron, "w") as fh:
            fh.write("bin")
        cfg = self._cfg(iron_proxy=iron)
        results = check.check_host(cfg, None, _probe({
            "id": (0, "1000\n", ""), "sudo": (0, "", "")}))
        by_label = {r.label: r for r in results}
        self.assertTrue(by_label["agent user 'agent' exists"].ok)
        self.assertTrue(by_label["passwordless sudo to 'agent'"].ok)
        self.assertTrue(by_label["iron-proxy %s" % iron].ok)
        # bwrap: assert it reports the truth of this host's PATH
        expected_bwrap = shutil.which("bwrap") is not None
        self.assertEqual(by_label["bwrap present"].ok, expected_bwrap)

    def test_sudo_failure_fails(self):
        iron = os.path.join(tempfile.mkdtemp(), "iron")
        with open(iron, "w") as fh:
            fh.write("bin")
        cfg = self._cfg(iron_proxy=iron)
        results = check.check_host(cfg, None, _probe({
            "id": (0, "1000\n", ""),
            "sudo": (1, "", "sudo: a password is required")}))
        by_label = {r.label: r for r in results}
        self.assertFalse(by_label["passwordless sudo to 'agent'"].ok)
        self.assertIn("password", by_label["passwordless sudo to 'agent'"].detail)

    def test_unknown_user_fails(self):
        iron = os.path.join(tempfile.mkdtemp(), "iron")
        with open(iron, "w") as fh:
            fh.write("bin")
        cfg = self._cfg(iron_proxy=iron)
        results = check.check_host(cfg, None, _probe({
            "id": (1, "", "id: no such user"), "sudo": (0, "", "")}))
        by_label = {r.label: r for r in results}
        self.assertFalse(by_label["agent user 'agent' exists"].ok)


class IronProxyTest(unittest.TestCase):
    def _cfg(self, iron, sha=""):
        return config.Config.from_dict({
            "gate": {"iron_proxy": iron, "iron_proxy_sha256": sha}})

    def test_present_no_pin_ok(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "iron")
        with open(p, "w") as fh:
            fh.write("x")
        self.assertTrue(check._check_iron_proxy(self._cfg(p)).ok)

    def test_sha256_match(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "iron")
        with open(p, "wb") as fh:
            fh.write(b"binary")
        h = hashlib.sha256(b"binary").hexdigest()
        self.assertTrue(check._check_iron_proxy(self._cfg(p, h)).ok)

    def test_sha256_mismatch(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "iron")
        with open(p, "wb") as fh:
            fh.write(b"binary")
        r = check._check_iron_proxy(self._cfg(p, "0" * 64))
        self.assertFalse(r.ok)
        self.assertIn("mismatch", r.detail)

    def test_path_name_not_found(self):
        # a PATH name that does not resolve fails
        r = check._check_iron_proxy(self._cfg("forcecage-iron-proxy-does-not-exist"))
        self.assertFalse(r.ok)

    def test_missing_file(self):
        r = check._check_iron_proxy(self._cfg("/nonexistent/iron"))
        self.assertFalse(r.ok)


class BindingsTest(unittest.TestCase):
    def _file(self, doc):
        p = os.path.join(tempfile.mkdtemp(), "b.json")
        with open(p, "w") as fh:
            json.dump(doc, fh)
        return p

    def test_valid(self):
        p = self._file([{"name": "a", "host": "h", "placeholder": "P-a",
                          "value": "v"}])
        self.assertTrue(check._check_bindings(p).ok)

    def test_missing_value(self):
        p = self._file([{"name": "a", "host": "h", "placeholder": "P-a"}])
        self.assertFalse(check._check_bindings(p).ok)

    def test_missing_placeholder(self):
        p = self._file([{"name": "a", "host": "h", "value": "v"}])
        self.assertFalse(check._check_bindings(p).ok)

    def test_not_a_list(self):
        p = self._file({"a": 1})
        self.assertFalse(check._check_bindings(p).ok)

    def test_bad_json(self):
        p = os.path.join(tempfile.mkdtemp(), "b.json")
        with open(p, "w") as fh:
            fh.write("{ not json")
        self.assertFalse(check._check_bindings(p).ok)

    def test_missing_file(self):
        self.assertFalse(check._check_bindings("/nonexistent/b.json").ok)


if __name__ == "__main__":
    unittest.main()
