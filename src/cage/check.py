"""cage.check -- verify the host prerequisites before a ``forcecage run``.

Read-only: it never writes, starts a gate, or touches the agent. It checks
the fixed host contract a caged run depends on (the agent user, the
passwordless sudo hop, bwrap, the iron-proxy binary + its pinned hash) and,
optionally, a bindings file. Each check is a labelled result; the exit code is
0 only when every check passes. The host probes are injectable so the logic is
testable without the host changes.
"""

import hashlib
import json
import os
import shutil
import subprocess

from .config import Config, load_config, find_config, ConfigError


def _default_probe(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError as e:
        return 127, "", str(e)


class Result:
    def __init__(self, label, ok, detail=""):
        self.label = label
        self.ok = ok
        self.detail = detail


def load_cfg(req):
    path = req.config_path or find_config()
    if path is None:
        return Config.from_dict({})
    if not os.path.isfile(path):
        raise SystemExit("forcecage: config not found: %s" % path)
    return load_config(path)


def _check_iron_proxy(cfg):
    path = cfg.iron_proxy
    if not os.path.isabs(path):
        resolved = shutil.which(path)
        if not resolved:
            return Result("iron-proxy present", False, "not on PATH: %s" % path)
        path = resolved
    if not os.path.isfile(path):
        return Result("iron-proxy present", False, "not a file: %s" % path)
    if cfg.iron_proxy_sha256:
        with open(path, "rb") as fh:
            h = hashlib.sha256(fh.read()).hexdigest()
        if h != cfg.iron_proxy_sha256:
            return Result("iron-proxy sha256", False,
                          "mismatch: %s != %s" % (h[:12], cfg.iron_proxy_sha256[:12]))
    return Result("iron-proxy %s" % path, True, "")


def _check_bindings(path):
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        return Result("bindings parse", False, str(e))
    if not isinstance(doc, list):
        return Result("bindings parse", False, "expected a JSON list")
    for i, b in enumerate(doc):
        if not isinstance(b, dict):
            return Result("bindings parse", False, "binding %d is not an object" % i)
        if "placeholder" not in b or "host" not in b:
            return Result("bindings parse", False,
                          "binding %d missing placeholder/host" % i)
        if "value" not in b and "secret_file" not in b and "vault" not in b:
            return Result("bindings parse", False,
                          "binding %d names no value/secret_file/vault" % i)
    return Result("bindings (%d)" % len(doc), True, "")


def check_host(cfg, bindings_path, probe):
    results = []
    rc, _out, err = probe(["id", "-u", cfg.agent_user])
    results.append(Result("agent user %r exists" % cfg.agent_user, rc == 0,
                          err.strip() if rc else ""))
    rc, _out, err = probe(["sudo", "-n", "-u", cfg.agent_user, "true"])
    results.append(Result("passwordless sudo to %r" % cfg.agent_user, rc == 0,
                          err.strip() if rc else ""))
    bwrap = shutil.which("bwrap")
    results.append(Result("bwrap present", bool(bwrap), bwrap or "not on PATH"))
    results.append(_check_iron_proxy(cfg))
    if bindings_path:
        results.append(_check_bindings(bindings_path))
    return results


def cmd_check(req, probe=None):
    probe = probe or _default_probe
    try:
        cfg = load_cfg(req)
    except ConfigError as e:
        print("FAIL  config: %s" % e)
        return 1
    results = check_host(cfg, req.bindings_path, probe)
    ok = True
    for r in results:
        line = "%s  %s" % ("ok" if r.ok else "FAIL", r.label)
        if r.detail:
            line += "  (%s)" % r.detail
        print(line)
        ok = ok and r.ok
    return 0 if ok else 1
