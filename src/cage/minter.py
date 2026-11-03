"""cage.minter -- how the gate gets the real value for a credential binding.

A credential binding says "this placeholder, for this host, stands in for a
secret." The gate never sees the secret; it binds a 0600 ``secret_file`` and
substring-swaps the placeholder for whatever that file holds. The Minter is
the seam that produces that file:

  * FileMinter   -- the default. The value is static: it comes from the
                    binding's ``value`` (written to a 0600 file) or an
                    existing ``secret_file`` (returned as-is). No server needed.
  * VaultMinter  -- dynamic. The value is read from Vault (AppRole login, KV).
                    "shared" kinds read one KV value; "dynamic" kinds mint a
                    fresh KV entry per call (the grant service retires it on
                    expiry/leak). The vault CLI runner is injectable so the
                    core is testable without a server.

Both fail closed: a binding that names neither a value nor a vault path is a
:class:`MinterError`, not an empty secret (an empty secret is a silent leak).
"""

import json
import os
import subprocess
import time
import uuid

# AppRole tokens are re-used while >= 10% of their TTL remains (60 s floor),
# mirroring the grant service's vault client so the two never disagree.
_TOKEN_REUSE_FRACTION = 0.9
_TOKEN_MIN_REUSE_SECONDS = 60.0


class MinterError(Exception):
    """The Minter could not produce a secret for a binding (fail closed)."""


def _safe_name(name):
    name = "".join(c if c.isalnum() or c in "-_.+" else "_" for c in str(name))
    return name or "secret"


def _write_0600(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(value)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


class Minter:
    """Value-source interface. ``mint`` returns a 0600 ``secret_file`` path."""

    def mint(self, binding, workdir):
        raise NotImplementedError

    def close(self):
        pass


class FileMinter(Minter):
    """Static values from the bindings file."""

    def mint(self, binding, workdir):
        name = binding.get("name", "secret")
        if "secret_file" in binding:
            return binding["secret_file"]
        if "value" in binding:
            os.makedirs(workdir, exist_ok=True)
            path = os.path.join(workdir, _safe_name(name) + ".secret")
            _write_0600(path, binding["value"])
            return path
        raise MinterError(
            "binding %r names neither a value nor a secret_file" % name)

    def close(self):
        pass


class VaultMinter(Minter):
    """Dynamic values from Vault (AppRole login + KV).

    ``run_cli`` is injectable: ``(args, token) -> (rc, out, err)``. When unset
    the ``vault`` CLI is invoked with an isolated HOME so a surrounding
    ``~/.vault-token`` is never picked up.
    """

    def __init__(self, addr, role_id_file, secret_id_file, token_dir,
                 run_cli=None, now=None):
        self.addr = addr
        self.role_id_file = role_id_file
        self.secret_id_file = secret_id_file
        self.token_dir = token_dir
        self.token_file = os.path.join(token_dir, "vault-token.json")
        self._run_cli = run_cli
        self._now = now or time.time

    # -- cli + auth ---------------------------------------------------------

    def _vault(self, args, token):
        if self._run_cli is not None:
            return self._run_cli(args, token)
        env = {**os.environ, "VAULT_ADDR": self.addr, "VAULT_TOKEN": token,
               "HOME": self.token_dir}
        p = subprocess.run(["vault"] + args, capture_output=True, text=True, env=env)
        return p.returncode, p.stdout, p.stderr

    def _login(self):
        with open(self.role_id_file, encoding="utf-8") as fh:
            role_id = fh.read().strip()
        with open(self.secret_id_file, encoding="utf-8") as fh:
            secret_id = fh.read().strip()
        rc, out, err = self._vault(["write", "-field=token", "auth/approle/login",
                                    "role_id=" + role_id, "secret_id=" + secret_id], "")
        if rc != 0:
            raise MinterError("vault login failed: %s" % (err or out).strip())
        lines = [l for l in out.splitlines() if l.strip()]
        token = lines[-1] if lines else ""
        if not token:
            raise MinterError("vault login returned no token")
        created, ttl = self._now(), 120
        rc2, out2, _ = self._vault(["token", "lookup"], token)
        if rc2 == 0:
            try:
                doc = json.loads(out2)
                if doc.get("created_time") is not None:
                    created = float(doc["created_time"])
                ttl = int(doc.get("ttl", 120))
            except json.JSONDecodeError:
                pass
        os.makedirs(self.token_dir, exist_ok=True)
        tmp = self.token_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"token": token, "created": created, "ttl": ttl}, fh)
        os.replace(tmp, self.token_file)
        os.chmod(self.token_file, 0o600)

    def _auth(self):
        try:
            with open(self.token_file, encoding="utf-8") as fh:
                rec = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            rec = {}
        token = rec.get("token")
        if token:
            age = self._now() - float(rec.get("created") or 0)
            if age < max(_TOKEN_MIN_REUSE_SECONDS,
                         float(rec.get("ttl") or 0) * _TOKEN_REUSE_FRACTION):
                return token
        self._login()
        with open(self.token_file, encoding="utf-8") as fh:
            return json.load(fh)["token"]

    # -- the interface the gate uses ----------------------------------------

    def _read(self, vault):
        if vault.get("mode") == "shared":
            return self._read_shared(vault)
        value = "grant-%s" % uuid.uuid4().hex
        rc, out, err = self._vault(["kv", "put", vault["path"], "value=" + value],
                                   self._auth())
        if rc != 0:
            raise MinterError("vault kv put %s: %s"
                              % (vault["path"], (err or out).strip()))
        return value

    def _read_shared(self, vault):
        rc, out, err = self._vault(["kv", "get", "-field=value", vault["path"]],
                                   self._auth())
        if rc != 0:
            raise MinterError("vault kv get %s: %s"
                              % (vault["path"], (err or out).strip()))
        lines = [l for l in out.splitlines() if l.strip()]
        return lines[-1] if lines else ""

    def mint(self, binding, workdir):
        vault = binding.get("vault")
        if not vault or "path" not in vault:
            raise MinterError("binding %r names no vault path" % binding.get("name"))
        value = self._read(vault)
        os.makedirs(workdir, exist_ok=True)
        path = os.path.join(workdir, _safe_name(binding.get("name", "secret")) + ".secret")
        _write_0600(path, value)
        return path

    def close(self):
        try:
            os.remove(self.token_file)
        except FileNotFoundError:
            pass


def make_minter(spec):
    """Build a Minter from a resolved config dict (``kind`` + vault fields)."""
    kind = spec.get("kind", "file")
    if kind == "file":
        return FileMinter()
    if kind == "vault":
        return VaultMinter(
            addr=spec.get("vault_address", ""),
            role_id_file=spec.get("vault_role_id_file", ""),
            secret_id_file=spec.get("vault_secret_id_file", ""),
            token_dir=spec.get("vault_token_dir", ""))
    raise MinterError("unknown minter kind %r" % kind)
