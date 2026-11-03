#!/usr/bin/env python3
"""Unit tests for cage.minter: the value-source interface the gate feeds.

The Minter turns a credential binding into a 0600 ``secret_file`` path the
gate binds. Two backends:

  * FileMinter   -- static value: the binding's ``value`` (written) or an
                    existing ``secret_file`` (returned as-is).
  * VaultMinter  -- dynamic value: reads a KV secret via the vault CLI
                    (AppRole); the runner is injectable so tests need no
                    vault server.

Both fail closed: a binding that names neither a value nor a vault path is an
error, not an empty secret.
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import cage.minter as minter  # noqa: E402


class FileMinterTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp(prefix="fc-minter-")
        self.m = minter.FileMinter()

    def test_mint_from_value_writes_0600_file(self):
        b = {"name": "example-api", "value": "the-real-token"}
        path = self.m.mint(b, self.dir)
        self.assertTrue(os.path.exists(path))
        with open(path) as fh:
            self.assertEqual(fh.read(), "the-real-token")
        mode = (os.stat(path).st_mode & 0o777)
        self.assertEqual(mode, 0o600)

    def test_mint_from_existing_secret_file_returns_it(self):
        src = os.path.join(self.dir, "orig")
        with open(src, "w") as fh:
            fh.write("already-here")
        b = {"name": "x", "secret_file": src}
        path = self.m.mint(b, self.dir)
        self.assertEqual(path, src)

    def test_secret_file_wins_over_value(self):
        src = os.path.join(self.dir, "orig")
        with open(src, "w") as fh:
            fh.write("from-file")
        b = {"name": "x", "secret_file": src, "value": "inline"}
        self.assertEqual(self.m.mint(b, self.dir), src)

    def test_neither_value_nor_secret_file_fails(self):
        with self.assertRaises(minter.MinterError):
            self.m.mint({"name": "x"}, self.dir)

    def test_name_is_sanitized_into_a_filename(self):
        b = {"name": "a/b c", "value": "v"}
        path = self.m.mint(b, self.dir)
        base = os.path.basename(path)
        self.assertNotIn("/", base)
        self.assertTrue(base.endswith(".secret"))

    def test_close_is_a_noop(self):
        self.m.close()  # must not raise


class VaultMinterTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp(prefix="fc-vault-minter-")
        self.role = os.path.join(self.dir, "role-id")
        self.secret = os.path.join(self.dir, "secret-id")
        with open(self.role, "w") as fh:
            fh.write("rid\n")
        with open(self.secret, "w") as fh:
            fh.write("sid\n")
        self.calls = []

        def run_cli(args, token):
            self.calls.append((list(args), token))
            if args[:2] == ["write", "-field=token"]:
                return 0, "tok-123\n", ""
            if args[:2] == ["token", "lookup"]:
                return 0, '{"created_time": 100, "ttl": 120}\n', ""
            if args[:2] == ["kv", "get"]:
                return 0, "vault-value-here\n", ""
            return 1, "", "unexpected: %r" % args

        self.m = minter.VaultMinter(
            addr="http://127.0.0.1:8200", role_id_file=self.role,
            secret_id_file=self.secret, token_dir=self.dir, run_cli=run_cli)

    def test_mint_shared_reads_kv_and_writes_0600(self):
        b = {"name": "example-api", "vault": {"mode": "shared", "path": "secret/gate/example-api"}}
        path = self.m.mint(b, self.dir)
        with open(path) as fh:
            self.assertEqual(fh.read(), "vault-value-here")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        # it logged in via AppRole before reading
        self.assertTrue(any(a[:2] == ["write", "-field=token"] for a, _ in self.calls))

    def test_binding_without_vault_fails(self):
        with self.assertRaises(minter.MinterError):
            self.m.mint({"name": "x", "value": "v"}, self.dir)

    def test_login_failure_raises(self):
        bad = minter.VaultMinter(
            addr="http://x", role_id_file=self.role, secret_id_file=self.secret,
            token_dir=self.dir,
            run_cli=lambda args, token: (1, "", "boom"))
        b = {"name": "example-api", "vault": {"mode": "shared", "path": "p"}}
        with self.assertRaises(minter.MinterError):
            bad.mint(b, self.dir)


class MakeMinterTest(unittest.TestCase):
    def test_file_kind(self):
        self.assertIsInstance(minter.make_minter({"kind": "file"}), minter.FileMinter)

    def test_vault_kind(self):
        m = minter.make_minter({"kind": "vault"})
        self.assertIsInstance(m, minter.VaultMinter)

    def test_unknown_kind_fails(self):
        with self.assertRaises(minter.MinterError):
            minter.make_minter({"kind": "redis"})


if __name__ == "__main__":
    unittest.main()
