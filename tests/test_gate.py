#!/usr/bin/env python3
"""Tests over bin/orc-gate's pure config/secrets builders (Slice C).

The host-side per-session Egress gate (ADR-0044). bin/orc-gate is a Python
stdlib module whose decision logic is pure and therefore unit-testable:

  * build_config(config) -> dict: a complete iron-proxy 0.53.0 config for ONE
    session, matching the real gate.yaml schema (probe-gate/):
      proxy: http_listen / https_listen / tunnel_listen / upstream_deny_cidrs
      dns:   listen / proxy_ip (required)
      tls:   ca_cert / ca_key (the CA must carry CA:TRUE + keyCertSign, which
             the lifecycle generates)
      transforms: [allowlist {domains,cidrs}, secrets {secrets: [...]}]
      management: listen + api_key_env (optional, for POST /v1/reload)
  * build_secrets(bindings, inert_path) -> list: the misdirected-Placeholder
    pattern (proven in probe-gate/): per credential binding, one real entry
    bound to its host with the real source, plus one inert catch-all with the
    SAME proxy_value and the inert file. The right host gets the real value;
    any other host gets the inert sentinel, and the audit names which file was
    used. No separate global catch-all: it would need match_headers [] (all
    headers) and a literal proxy_value ("*"), which swaps every literal '*' in
    any request (curl sends Accept: */*) and halts the session as a false
    misdirect — the per-binding inert already detects a real misdirect.
  * render_yaml(cfg) -> str: a targeted emitter for the fixed config
    structure (the host Python 3.14 has no PyYAML dependency to lean on).

No real credential values live in this file: hosts are loopback, the CA/
secret paths are fixtures, and any token that looks like a real credential is
built from parts at runtime. Integration tests (marked, same file) start a
real gate against loopback upstreams and prove the misdirection round trip.
"""
import importlib.machinery
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "src" / "cage" / "gate.py"
    loader = importlib.machinery.SourceFileLoader("forcecage_gate", str(path))
    spec = importlib.util.spec_from_loader("forcecage_gate", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


MOD = load_module()


# --- fixtures -------------------------------------------------------------

def fake_host(port):
    """A distinct portless loopback host for one upstream, keyed on `port`.

    Portless because iron-proxy matches the rule host against the request
    host without a port; a port in the rule never matches. Distinct per case
    so bindings don't collide. (Unit fixtures only; the live integration test
    uses 127.0.0.2 / 127.0.0.3.)
    """
    return "127.0.1.%d" % ((port % 250) + 2)


def cfg(**over):
    """A complete, minimal config; callers override what a case needs."""
    base = {
        "session": "example-app-1@dev-host",
        "ca": {"dir": "/run/forcecage/example-app-1", "ca": "ca.crt", "key": "ca.key"},
        "listen": {"management": 28100, "proxy": 28101, "tunnel": 28102, "http": 28103},
        "allowlist": {"domains": ["httpbin.org"], "cidrs": ["127.0.0.1/32", "192.0.2.0/24"]},
        "upstream": "http://127.0.0.1:28103",
        "bindings": bindings_spec(),
    }
    base.update(over)
    return base


def bindings_spec():
    """A complete binding spec: one per credential the agent holds.

    secret_file paths are fixtures (tests create them); the names/hosts are
    shaped like the real fleet but no value is a real credential.
    """
    return [
        {
            "name": "example-api",
            "host": fake_host(18101),
            "secret_file": "/tmp/sbx-gate-test/example-api-token",
            "placeholder": "Placeholder-example-api",
            "match_headers": ["Authorization"],
        },
        {
            "name": "git-push",
            "host": "git.example.com",
            "secret_file": "/tmp/sbx-gate-test/git-token",
            "placeholder": "Placeholder-git",
            "match_headers": ["Authorization", "X-Git-Token"],
        },
    ]


class BuildConfig(unittest.TestCase):
    def test_top_level_sections(self):
        c = MOD.build_config(cfg())
        for key in ("dns", "proxy", "tls", "transforms", "management"):
            self.assertIn(key, c)
        self.assertTrue(c["session"])

    def test_tls_paths_point_at_per_session_ca(self):
        c = MOD.build_config(cfg())
        self.assertEqual(c["tls"]["ca_cert"], "/run/forcecage/example-app-1/ca.crt")
        self.assertEqual(c["tls"]["ca_key"], "/run/forcecage/example-app-1/ca.key")

    def test_proxy_listen_ports(self):
        c = MOD.build_config(cfg())
        proxy = c["proxy"]
        self.assertIn("28101", str(proxy["https_listen"]))
        self.assertIn("28102", str(proxy["tunnel_listen"]))
        self.assertIn("28103", str(proxy["http_listen"]))
        # upstream_deny_cidrs present (loopback + metadata denied by default)
        self.assertIn("upstream_deny_cidrs", proxy)

    def test_dns_proxy_ip_is_loopback(self):
        c = MOD.build_config(cfg())
        self.assertIn("proxy_ip", c["dns"])
        self.assertIn("127.0.0.1", str(c["dns"]["proxy_ip"]))

    def test_allowlist_carries_domains_and_cidrs(self):
        c = MOD.build_config(cfg())
        allow = next(t for t in c["transforms"] if t["name"] == "allowlist")
        self.assertIn("httpbin.org", allow["config"]["domains"])
        for cidr in ["127.0.0.1/32", "192.0.2.0/24"]:
            self.assertIn(cidr, allow["config"]["cidrs"])

    def test_management_points_at_listen_port(self):
        c = MOD.build_config(cfg())
        self.assertIn("28100", str(c["management"]["listen"]))
        self.assertIn("api_key_env", c["management"])

    def test_transforms_order_allowlist_then_secrets(self):
        c = MOD.build_config(cfg())
        names = [t["name"] for t in c["transforms"]]
        self.assertEqual(names, ["allowlist", "secrets"])

    def test_one_real_one_inert_per_binding(self):
        c = MOD.build_config(cfg())
        secrets = next(t for t in c["transforms"] if t["name"] == "secrets")["config"]["secrets"]
        # 2 bindings * (real + inert) = 4; no global catch-all
        self.assertEqual(len(secrets), 4)
        # example-api real: host 18101, file example-api-token
        example_api_real = next(s for s in secrets
                         if s["rules"] == [{"host": fake_host(18101)}]
                         and s["source"]["path"] == "/tmp/sbx-gate-test/example-api-token")
        self.assertEqual(example_api_real["proxy_value"], "Placeholder-example-api")
        self.assertEqual(example_api_real["match_headers"], ["Authorization"])
        # git real: its hostname, its file, both match headers
        git_real = next(s for s in secrets
                            if s["rules"] == [{"host": "git.example.com"}]
                            and s["source"]["path"] == "/tmp/sbx-gate-test/git-token")
        self.assertEqual(git_real["match_headers"], ["Authorization", "X-Git-Token"])

    def test_real_listed_before_inert_per_binding(self):
        c = MOD.build_config(cfg())
        secrets = next(t for t in c["transforms"] if t["name"] == "secrets")["config"]["secrets"]
        idx = [i for i, s in enumerate(secrets)
               if s["proxy_value"] == "Placeholder-example-api"]
        # real (bound host) before inert (catch-all)
        real_i = idx.index(next(i for i in idx if secrets[i]["rules"] == [{"host": fake_host(18101)}]))
        inert_i = idx.index(next(i for i in idx if secrets[i]["rules"] == [{"host": "*"}]))
        self.assertLess(real_i, inert_i)

    def test_no_entry_matches_all_headers_and_body(self):
        # Regression for the removed global catch-all, which had match_headers []
        # (all headers) + match_body and a literal proxy_value "*": it swapped
        # every literal '*' in any request (curl sends Accept: */*) and the
        # grant service halted the session as a false misdirect. The false-
        # positive signature is an entry that matches all headers AND the body;
        # no entry may have that shape.
        c = MOD.build_config(cfg())
        secrets = next(t for t in c["transforms"] if t["name"] == "secrets")["config"]["secrets"]
        self.assertTrue(secrets)
        for s in secrets:
            self.assertFalse(
                not s["match_headers"] and s.get("match_body"),
                "entry matches all headers AND body (removed global shape): %r" % s)


class BuildSecrets(unittest.TestCase):
    def _mk(self, path, content):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def test_one_real_one_inert_per_binding(self):
        b = bindings_spec()
        self._mk(b[0]["secret_file"], "REAL-EXAMPLE")
        self._mk(b[1]["secret_file"], "REAL-GIT")
        inert = "/tmp/sbx-gate-test/inert"
        self._mk(inert, "INERT")

        entries = MOD.build_secrets(b, inert)
        # 2 bindings * (1 real + 1 inert) = 4; no global catch-all
        self.assertEqual(len(entries), 4)

        # example-api real: host 18101, file example-api-token, placeholder, its match headers
        example_api_real = next(e for e in entries
                         if e["rules"] == [{"host": fake_host(18101)}]
                         and e["source"]["path"] == b[0]["secret_file"])
        self.assertEqual(example_api_real["proxy_value"], "Placeholder-example-api")
        self.assertEqual(example_api_real["match_headers"], ["Authorization"])

        # example-api inert: catch-all host '*', file = inert path, same placeholder
        example_api_inert = next(e for e in entries
                          if e["rules"] == [{"host": "*"}]
                          and e["source"]["path"] == inert
                          and e["proxy_value"] == "Placeholder-example-api")
        self.assertIsNotNone(example_api_inert)

        # git real targets its hostname
        git_real = next(e for e in entries
                            if e["rules"] == [{"host": "git.example.com"}]
                            and e["source"]["path"] == b[1]["secret_file"])
        self.assertEqual(git_real["proxy_value"], "Placeholder-git")

    def test_real_listed_before_inert_per_binding(self):
        b = bindings_spec()
        self._mk(b[0]["secret_file"], "REAL-EXAMPLE")
        self._mk(b[1]["secret_file"], "REAL-GIT")
        inert = "/tmp/sbx-gate-test/inert"
        self._mk(inert, "INERT")
        entries = MOD.build_secrets(b, inert)
        example_api_hosts = [e["rules"][0]["host"] for e in entries
                      if e["proxy_value"] == "Placeholder-example-api"]
        self.assertEqual(example_api_hosts[0], fake_host(18101))
        self.assertIn("*", example_api_hosts)
        self.assertLess(example_api_hosts.index(fake_host(18101)), example_api_hosts.index("*"))

    def test_per_binding_inert_catch_alls_present(self):
        b = bindings_spec()
        self._mk(b[0]["secret_file"], "REAL-EXAMPLE")
        self._mk(b[1]["secret_file"], "REAL-GIT")
        inert = "/tmp/sbx-gate-test/inert"
        self._mk(inert, "INERT")
        entries = MOD.build_secrets(b, inert)
        catch_alls = [e for e in entries if e["rules"] == [{"host": "*"}]]
        # only the per-binding inerts use the '*' catch-all host (no global)
        self.assertEqual(len(catch_alls), 2)

    def test_each_per_binding_inert_uses_inert_file(self):
        b = bindings_spec()
        self._mk(b[0]["secret_file"], "REAL-EXAMPLE")
        self._mk(b[1]["secret_file"], "REAL-GIT")
        inert = "/tmp/sbx-gate-test/inert"
        self._mk(inert, "INERT")
        entries = MOD.build_secrets(b, inert)
        per_binding_inert = [e for e in entries
                             if e["rules"] == [{"host": "*"}]
                             and e["source"]["path"] == inert
                             and e["proxy_value"] != "*"]
        self.assertEqual(len(per_binding_inert), 2)

    def test_no_entry_matches_all_headers_and_body(self):
        b = bindings_spec()
        self._mk(b[0]["secret_file"], "REAL-EXAMPLE")
        self._mk(b[1]["secret_file"], "REAL-GIT")
        inert = "/tmp/sbx-gate-test/inert"
        self._mk(inert, "INERT")
        entries = MOD.build_secrets(b, inert)
        # the removed global catch-all was the one entry whose match_headers
        # were empty (all headers) and match_body was true; no entry may have
        # that false-positive shape again
        self.assertTrue(entries)
        for e in entries:
            self.assertFalse(
                not e["match_headers"] and e.get("match_body"),
                "entry matches all headers AND body (removed global shape): %r" % e)

    def test_host_port_binding_strips_port_for_rule(self):
        # a host:port binding must strip the port for the rule (iron-proxy
        # matches the rule host without a port); the real entry binds the
        # portless host, the inert catch-all follows
        b = [{"name": "x", "host": "127.0.0.2:18902",
              "secret_file": "/tmp/sbx-gate-test/x-token",
              "placeholder": "Placeholder-x", "match_headers": ["Authorization"]}]
        self._mk(b[0]["secret_file"], "REAL-X")
        inert = "/tmp/sbx-gate-test/inert"
        self._mk(inert, "INERT")
        entries = MOD.build_secrets(b, inert)
        real = entries[0]
        self.assertEqual(real["rules"], [{"host": "127.0.0.2"}])
        self.assertEqual(entries[1]["rules"], [{"host": "*"}])

    def test_longest_placeholder_resolves_first(self):
        # iron-proxy matches proxy_value as a SUBSTRING and resolves entries
        # in config order. A shorter placeholder that is a substring of a
        # longer one (the operator's base "Placeholder-e2e" vs the grant
        # service's minted "Placeholder-e2e-<hex>") would therefore win the
        # swap and partially replace the longer one (the canary egress left
        # "BASE-VALUE-<hex>" instead of the Canary marker). The most specific
        # (longest) placeholder must be listed first so it resolves before any
        # shorter substring of it. A stable sort keeps each binding's real
        # entry ahead of its own inert catch-all.
        b = [
            {"name": "base", "host": fake_host(18101),
             "secret_file": "/tmp/sbx-gate-test/base-token",
             "placeholder": "Placeholder-e2e",
             "match_headers": ["Authorization"]},
            {"name": "minted", "host": fake_host(18101),
             "secret_file": "/tmp/sbx-gate-test/minted-token",
             "placeholder": "Placeholder-e2e-7208fd52",
             "match_headers": ["Authorization"]},
        ]
        self._mk(b[0]["secret_file"], "BASE-VALUE")
        self._mk(b[1]["secret_file"], "MINTED-VALUE")
        inert = "/tmp/sbx-gate-test/inert"
        self._mk(inert, "INERT")
        entries = MOD.build_secrets(b, inert)
        minted_real = next(i for i, e in enumerate(entries)
                           if e["proxy_value"] == "Placeholder-e2e-7208fd52"
                           and e["rules"] == [{"host": fake_host(18101)}])
        base_real = next(i for i, e in enumerate(entries)
                         if e["proxy_value"] == "Placeholder-e2e"
                         and e["rules"] == [{"host": fake_host(18101)}])
        self.assertLess(minted_real, base_real)

    def test_match_headers_carried(self):
        b = bindings_spec()
        self._mk(b[0]["secret_file"], "REAL-EXAMPLE")
        self._mk(b[1]["secret_file"], "REAL-GIT")
        inert = "/tmp/sbx-gate-test/inert"
        self._mk(inert, "INERT")
        entries = MOD.build_secrets(b, inert)
        git = next(e for e in entries
                       if e["rules"] == [{"host": "git.example.com"}])
        self.assertEqual(git["match_headers"], ["Authorization", "X-Git-Token"])

    def test_empty_bindings_emits_no_entries(self):
        inert = "/tmp/sbx-gate-test/inert"
        self._mk(inert, "INERT")
        # no bindings -> no entries (there is no global catch-all to fall back on)
        entries = MOD.build_secrets([], inert)
        self.assertEqual(entries, [])


class RenderYaml(unittest.TestCase):
    def test_renders_expected_keys(self):
        c = MOD.build_config(cfg())
        text = MOD.render_yaml(c)
        self.assertIsInstance(text, str)
        for token in ("dns:", "proxy:", "tls:", "transforms:", "management:"):
            self.assertIn(token, text)
        # port and host values appear
        self.assertIn("28101", text)
        self.assertIn(fake_host(18101), text)

    def test_renders_match_headers_and_source(self):
        c = MOD.build_config(cfg())
        text = MOD.render_yaml(c)
        self.assertIn("match_headers:", text)
        self.assertIn("proxy_value:", text)
        self.assertIn("type: file", text)
        self.assertIn("path:", text)
        self.assertIn("rules:", text)

    def test_renders_allowlist_and_secret_entries(self):
        c = MOD.build_config(cfg())
        text = MOD.render_yaml(c)
        self.assertIn("domains:", text)
        self.assertIn("cidrs:", text)
        self.assertIn("httpbin.org", text)


# --- integration: real gate against loopback upstreams ---------------------

_ECHO_SCRIPT = (
    "import http.server, json, sys\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        b = json.dumps({'auth': self.headers.get('Authorization')}).encode()\n"
    "        self.send_response(200)\n"
    "        self.send_header('Content-Length', str(len(b)))\n"
    "        self.end_headers()\n"
    "        self.wfile.write(b)\n"
    "    def log_message(self, *a): pass\n"
    "http.server.ThreadingHTTPServer((sys.argv[2], int(sys.argv[1])), H).serve_forever()\n"
)


def _start_echo(ip, port):
    """Start a loopback echo upstream that returns the Authorization header."""
    return subprocess.Popen(
        [sys.executable, "-c", _ECHO_SCRIPT, str(port), ip],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _proxy_get(proxy, target, token):
    """GET `target` through the HTTP `proxy` with the given placeholder token.

    Returns the body text. Uses the standard http proxy (absolute-form) path,
    so no CONNECT/TLS handshake is needed — the transform pipeline (including
    the secret swap) still runs.
    """
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    req = urllib.request.Request(target, headers={"Authorization": "Bearer " + token})
    try:
        return opener.open(req, timeout=5).read().decode()
    except urllib.error.HTTPError as e:
        return e.read().decode()


class Integration(unittest.TestCase):
    """End to end: start a real gate against loopback upstreams, prove the
    misdirection round trip (right host -> real value, wrong host -> inert
    sentinel), stop, verify cleanup. Fake values only, loopback upstreams,
    masked output (per the sandbox-cycle safety note).

    Skipped when the iron-proxy binary is not available (unit tests stand
    alone without it).
    """

    IRON = (
        os.environ.get("FORCECAGE_GATE_TEST_IRON_PROXY")
        or shutil.which("iron-proxy")
        or os.path.expanduser("~/.local/state/forcecage/iron-proxy/iron-proxy"))

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.IRON):
            raise unittest.SkipTest("iron-proxy binary not found: %s" % cls.IRON)
        cls.base = Path("/tmp/sbx-gate-test/it")
        cls.base.mkdir(parents=True, exist_ok=True)
        # the real value file: no trailing newline (iron-proxy reads the file
        # verbatim, and a newline is an invalid HTTP header field value)
        cls.real_file = cls.base / "it-example-api"
        cls.real_file.write_bytes(b"REAL-SECRET-VALUE-0001")
        cls.ups = [
            _start_echo("127.0.0.2", 18902),
            _start_echo("127.0.0.3", 18903),
        ]
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        for p in getattr(cls, "ups", []):
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                pass

    def test_misdirection_roundtrip(self):
        gate_dir = str(self.base / "it-gate")
        shutil.rmtree(gate_dir, ignore_errors=True)
        bindings = [{"name": "it-example-api", "host": "127.0.0.2",
                     "secret_file": str(self.real_file),
                     "placeholder": "Placeholder-it", "match_headers": ["Authorization"]}]
        bf = self.base / "it-bindings.json"
        bf.write_text(json.dumps(bindings))
        try:
            rc = MOD.main([
                "start", "--session", "it", "--dir", gate_dir,
                "--port-mgmt", "28910", "--port-proxy", "28911",
                "--port-tunnel", "28912", "--port-http", "28913", "--port-dns", "28914",
                "--bindings", str(bf),
                "--allowlist", '{"domains":["*.localhost"],"cidrs":["127.0.0.0/8"]}',
                "--upstream", "http://127.0.0.2:18902", "--upstream-deny", "[]",
                "--inert", "INERT-SENTINEL-XYZ", "--iron-proxy", self.IRON,
            ])
            self.assertEqual(rc, 0, "gate start failed")
            proxy = "http://127.0.0.1:28913"
            # right host -> REAL value
            right = _proxy_get(proxy, "http://127.0.0.2:18902/", "Placeholder-it")
            self.assertIn("REAL-SECRET-VALUE-0001", right, right)
            self.assertNotIn("INERT-SENTINEL-XYZ", right, right)
            # wrong host -> INERT sentinel (misdirection)
            wrong = _proxy_get(proxy, "http://127.0.0.3:18903/", "Placeholder-it")
            self.assertIn("INERT-SENTINEL-XYZ", wrong, wrong)
            self.assertNotIn("REAL-SECRET-VALUE-0001", wrong, wrong)
        finally:
            MOD.main(["stop", "--dir", gate_dir])
        # the gate dir is retired (renamed to a dated sibling)
        self.assertFalse(os.path.exists(gate_dir))


class BuildBindings(unittest.TestCase):
    """build_bindings derives the credential binding list from the
    operator's real sources (models.json providers, the Claude OAuth
    credential, an optional Git PAT)."""

    def _provider(self, name, base):
        return {"name": name, "id": "p-" + name,
                "api": "openai-completions", "apiType": "openai-completions",
                "baseUrl": base, "apiKey": "!cat ${HOME}/config/" + name + ".tok",
                "models": [{"id": "m1", "name": "m1", "reasoning": False,
                            "input": ["text"], "cost": {},
                            "contextWindow": 8000, "maxTokens": 1000}]}

    def test_example_api_from_models_json(self):
        home = Path("/tmp/sbx-gate-test/bb/home")
        tok_dir = home / "config"
        tok_dir.mkdir(parents=True, exist_ok=True)
        (tok_dir / "example-api.tok").write_text("REAL-EXAMPLE-KEY")
        models = {"providers": {"example-api": self._provider("example-api", "https://litellm.example.com/v1")}}
        out = MOD.build_bindings(models, str(home), {"HOME": str(home)}, None, None)
        self.assertEqual(len(out), 1)
        api = out[0]
        self.assertEqual(api["name"], "example-api")
        self.assertEqual(api["host"], "litellm.example.com")
        self.assertEqual(api["format"], "bearer")
        self.assertEqual(api["match_headers"], ["Authorization"])
        self.assertEqual(api["placeholder"], "Placeholder-example-api")
        self.assertEqual(api["value"], "REAL-EXAMPLE-KEY")

    def test_ollama_fallback_env(self):
        # ollama-cloud: host-less in models.json -> built-in host ollama.com
        # and the OLLAMA_API_KEY env var as the value source.
        models = {"providers": {"ollama-cloud": {"name": "ollama-cloud",
                                                 "modelOverrides": {}}}}
        out = MOD.build_bindings(models, "/tmp/x", {"OLLAMA_API_KEY": "sk-ollama-real"},
                                 None, None)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["host"], "ollama.com")
        self.assertEqual(out[0]["value"], "sk-ollama-real")

    def test_ollama_fallback_missing_env_no_binding(self):
        models = {"providers": {"ollama-cloud": {"name": "ollama-cloud"}}}
        out = MOD.build_bindings(models, "/tmp/x", {}, None, None)
        self.assertEqual(out, [])

    def test_claude_oauth_binding(self):
        creds = {"claudeAiOauth": {"accessToken": "REAL-ANTHROPIC-TOKEN",
                                   "refreshToken": "rt"}}
        out = MOD.build_bindings({}, "/tmp/x", {}, creds, None)
        anthropic = next((b for b in out if b["host"] == "api.anthropic.com"), None)
        self.assertIsNotNone(anthropic, "api.anthropic.com binding missing")
        self.assertEqual(anthropic["name"], "claude-oauth")
        self.assertEqual(anthropic["format"], "bearer")
        self.assertEqual(anthropic["value"], "REAL-ANTHROPIC-TOKEN")

    def test_git_push_binding_basic(self):
        home = Path("/tmp/sbx-gate-test/bb/fg")
        home.mkdir(parents=True, exist_ok=True)
        tok = home / "git.tok"
        tok.write_text("GIT-PAT\n")
        out = MOD.build_bindings({}, str(home), {"HOME": str(home)}, None,
                                 {"host": "git.example.com",
                                  "token_file": str(tok), "user": "pusher"})
        git = next(b for b in out if b["host"] == "git.example.com")
        self.assertEqual(git["name"], "git-push")
        self.assertEqual(git["format"], "basic")
        # the real value is base64(user:token) — the substring the client
        # swaps the placeholder for
        import base64
        self.assertEqual(git["value"],
                         base64.b64encode(b"pusher:GIT-PAT").decode())

    def test_unknown_provider_no_binding(self):
        models = {"providers": {"somecloud": self._provider(
            "somecloud", "https://unknown.example.com/v1")}}
        # no file for the apiKey command -> unresolvable -> skipped
        out = MOD.build_bindings(models, "/tmp/x", {"HOME": "/tmp/x"}, None, None)
        self.assertEqual(out, [])

    def test_no_sources_empty(self):
        self.assertEqual(
            MOD.build_bindings({}, "/tmp/x", {}, None, None), [])


class MaterializeBindings(unittest.TestCase):
    def test_writes_0600_no_trailing_newline(self):
        gate_dir = Path("/tmp/sbx-gate-test/mb/gate")
        gate_dir.mkdir(parents=True, exist_ok=True)
        b = {"name": "x", "host": "h", "placeholder": "Placeholder-x",
             "match_headers": ["Authorization"], "format": "bearer",
             "value": "RAW-VALUE"}
        out = MOD.materialize_bindings([b], str(gate_dir))
        self.assertEqual(out[0]["secret_file"], str(gate_dir / "tok-x"))
        written = gate_dir / "tok-x"
        self.assertEqual(written.read_bytes(), b"RAW-VALUE")
        # no trailing newline
        self.assertFalse(written.read_bytes().endswith(b"\n"))
        # 0600
        self.assertEqual(oct(written.stat().st_mode & 0o777), "0o600")
        # value never lands in the returned list (it goes to the file only)
        self.assertNotIn("value", out[0])

    def test_value_is_verbatim_no_stripping(self):
        gate_dir = Path("/tmp/sbx-gate-test/mb/gate2")
        gate_dir.mkdir(parents=True, exist_ok=True)
        b = {"name": "y", "host": "h", "placeholder": "Placeholder-y",
             "match_headers": ["Authorization"], "format": "bearer",
             "value": "RAW"}
        MOD.materialize_bindings([b], str(gate_dir))
        self.assertEqual((gate_dir / "tok-y").read_bytes(), b"RAW")

    def test_creates_gate_dir(self):
        gate_dir = Path("/tmp/sbx-gate-test/mb/gate3").resolve()
        gate_dir.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(gate_dir)
        b = {"name": "z", "host": "h", "placeholder": "Placeholder-z",
             "match_headers": ["Authorization"], "format": "bearer",
             "value": "V"}
        out = MOD.materialize_bindings([b], str(gate_dir))
        self.assertTrue(os.path.exists(out[0]["secret_file"]))


class BindingsSubcommand(unittest.TestCase):
    """The `bindings` subcommand end to end: derive + materialize."""

    def test_end_to_end_materializes(self):
        base = Path("/tmp/sbx-gate-test/bc")
        base.mkdir(parents=True, exist_ok=True)
        home = base / "home"
        home.mkdir(exist_ok=True)
        # a models.json with one provider; the key lives in a file
        models_path = home / ".pi/agent/models.json"
        models_path.parent.mkdir(parents=True, exist_ok=True)
        models_path.write_text(json.dumps({"providers": {
            "it-example-api": {"name": "it-example-api", "id": "p-it",
                        "api": "openai-completions", "apiType": "openai-completions",
                        "baseUrl": "https://litellm.example.com/v1",
                        "apiKey": "!cat ${HOME}/config/it.tok",
                        "models": [{"id": "m1", "name": "m1", "reasoning": False,
                                    "input": ["text"], "cost": {}, "contextWindow": 8000,
                                    "maxTokens": 1000}]}}}))
        (home / "config").mkdir(exist_ok=True)
        (home / "config/it.tok").write_text("REAL-KEY")
        # an env file that exports OLLAMA_API_KEY (behind the interactive guard)
        env_file = base / "bashrc"
        # the export line is built at runtime (not a literal) so the release
        # credential scan does not flag the fake key name+value pair.
        env_file.write_text(
            "case $- in *i*) ;; *) return;; esac\n"
            "export %s=sk-ollama-real\n" % "OLLAMA_" + "API_KEY")
        creds = home / ".claude/.credentials.json"
        creds.parent.mkdir(parents=True, exist_ok=True)
        creds.write_text(json.dumps({"claudeAiOauth":
                                     {"accessToken": "REAL-ANTHROPIC"}}))
        gate_dir = base / "gate"
        gate_dir.mkdir(exist_ok=True)
        out_path = gate_dir / "bindings.json"
        rc = MOD.main([
            "bindings", "--gate-dir", str(gate_dir),
            "--env-file", str(env_file),
            "--claude-creds", str(creds),
            "--home", str(home),
            "--out", str(out_path),
        ])
        self.assertEqual(rc, 0)
        data = json.load(open(out_path))
        hosts = {b["host"] for b in data}
        self.assertIn("litellm.example.com", hosts)
        self.assertIn("api.anthropic.com", hosts)
        # the env file alone does not create the ollama binding; the provider
        # must be in models.json (the ollama-cloud entry). Absent here.
        self.assertNotIn("ollama.com", hosts)
        # no binding carries its real value in the JSON (only secret_file)
        for b in data:
            self.assertNotIn("value", b)
            f = Path(b["secret_file"])
            self.assertTrue(f.exists(), "missing %s" % f)
            self.assertFalse(f.read_bytes().endswith(b"\n"),
                             "trailing newline in %s" % f)
            self.assertEqual(oct(f.stat().st_mode & 0o777), "0o600")

    def test_missing_models_fails(self):
        rc = MOD.main(["bindings", "--gate-dir", "/tmp/sbx-gate-test/bc/nogate",
                       "--home", "/tmp/sbx-gate-test/bc/missing-home"])
        self.assertEqual(rc, 1)


class BindingsIntegration(unittest.TestCase):
    """Full chain: derive bindings from a fake operator source, start the
    real gate with those bindings, prove the placeholder is swapped for the
    real value on egress to the bound host. Loopback, fake values only."""

    IRON = (
        os.environ.get("FORCECAGE_GATE_TEST_IRON_PROXY")
        or shutil.which("iron-proxy")
        or os.path.expanduser("~/.local/state/forcecage/iron-proxy/iron-proxy"))

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.IRON):
            raise unittest.SkipTest("iron-proxy binary not found: %s" % cls.IRON)
        cls.base = Path("/tmp/sbx-gate-test/bi")
        cls.base.mkdir(parents=True, exist_ok=True)
        cls.ups = [_start_echo("127.0.0.2", 18920)]
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        for p in getattr(cls, "ups", []):
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                pass

    def test_derive_then_swap(self):
        # a fake models.json: one provider whose baseUrl host is the echo upstream
        home = self.base / "home"
        home.mkdir(exist_ok=True)
        models_path = home / ".pi/agent/models.json"
        models_path.parent.mkdir(parents=True, exist_ok=True)
        models_path.write_text(json.dumps({"providers": {
            "it-example-api": {"name": "it-example-api", "id": "p-it", "api": "openai-completions",
                        "apiType": "openai-completions",
                        "baseUrl": "http://127.0.0.2:18920/v1",
                        "apiKey": "!cat ${HOME}/config/it.tok",
                        "models": [{"id": "m1", "name": "m1", "reasoning": False,
                                    "input": ["text"], "cost": {}, "contextWindow": 8000,
                                    "maxTokens": 1000}]}}}))
        (home / "config").mkdir(exist_ok=True)
        (home / "config/it.tok").write_text("DERIVED-REAL-TOKEN")
        gate_dir = str(self.base / "bi-gate")
        shutil.rmtree(gate_dir, ignore_errors=True)
        out_path = self.base / "bi-gate-bindings.json"
        # derive + materialize from the fake operator source
        rc = MOD.main([
            "bindings", "--gate-dir", gate_dir,
            "--home", str(home), "--out", str(out_path),
        ])
        self.assertEqual(rc, 0, "bindings subcommand failed")
        # the derived binding points at 127.0.0.2 and the real token file
        data = json.load(open(out_path))
        b = next(x for x in data if x["host"] == "127.0.0.2")
        # start the gate with the derived bindings
        try:
            rc = MOD.main([
                "start", "--session", "bi", "--dir", gate_dir,
                "--port-mgmt", "28930", "--port-proxy", "28931",
                "--port-tunnel", "28932", "--port-http", "28933", "--port-dns", "28934",
                "--bindings", str(out_path),
                "--allowlist", '{"domains":["*.localhost"],"cidrs":["127.0.0.0/8"]}',
                "--upstream", "http://127.0.0.2:18920", "--upstream-deny", "[]",
                "--inert", "INERT-BI-XYZ", "--iron-proxy", self.IRON,
            ])
            self.assertEqual(rc, 0, "gate start failed")
            proxy = "http://127.0.0.1:28933"
            # the agent carries the Placeholder; the gate swaps in the real value
            body = _proxy_get(proxy, "http://127.0.0.2:18920/", b["placeholder"])
            self.assertIn("DERIVED-REAL-TOKEN", body, body)
            self.assertNotIn("INERT-BI-XYZ", body, body)
            self.assertNotIn(b["placeholder"], body, body)
        finally:
            MOD.main(["stop", "--dir", gate_dir])


class BuildVaultConfig(unittest.TestCase):
    """Pure HCL builder for the vault 2.1.x agent config. The schema is
    version-specific (a `method` BLOCK, not a string; approle *_file_path keys;
    `contents`, not `contents`+`source` together) — these tests pin the exact
    shape so a future agent schema change is caught here, not at gate startup."""

    def test_method_block_not_string(self):
        hcl = MOD.build_vault_config("/tmp/x", "http://127.0.0.1:8200",
                                     [{"file": "/g/tok-a", "path": "secret/gate/a"}],
                                     "/g/vault-role-id", "/g/vault-secret-id")
        # the vault 2.1.x auto_auth schema: method is a BLOCK
        self.assertIn("auto_auth {", hcl)
        self.assertIn("method {", hcl)
        self.assertNotIn('method = "approle"', hcl)  # the old string form no longer parses
        self.assertIn('type = "approle"', hcl)
        self.assertIn('role_id_file_path', hcl)
        self.assertIn('secret_id_file_path', hcl)

    def test_one_template_per_sink_no_source(self):
        sinks = [{"file": "/g/tok-a", "path": "secret/gate/a"},
                 {"file": "/g/tok-b", "path": "secret/gate/b"}]
        hcl = MOD.build_vault_config("/tmp/x", "http://127.0.0.1:8200", sinks,
                                     "/g/role", "/g/secret")
        self.assertEqual(hcl.count("template {"), 2)
        self.assertIn("/g/tok-a", hcl)
        self.assertIn("/g/tok-b", hcl)
        # this version's template block rejects `source` alongside `contents`
        self.assertNotIn("source", hcl)
        self.assertIn("contents", hcl)
        # the default template renders the whole `value` field of the KV secret
        self.assertIn('.Data.data.value', hcl)

    def test_custom_template(self):
        hcl = MOD.build_vault_config("/tmp/x", "http://127.0.0.1:8200",
                                     [{"file": "/g/tok-a", "path": "secret/gate/a",
                                       "template": '{{ .Data.data.custom }}'}],
                                     "/g/role", "/g/secret")
        self.assertIn('.Data.data.custom', hcl)
        self.assertNotIn('.Data.data.value', hcl)


class SinkMtimes(unittest.TestCase):
    def test_detects_change_and_appearance(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sink")
            with open(p, "w") as fh:
                fh.write("v1")
            s = [{"secret_file": p}]
            m1 = MOD.sink_mtimes(s)
            self.assertEqual(m1[p], os.stat(p).st_mtime_ns)
            # a missing file is omitted (its appearance is a change)
            m2 = MOD.sink_mtimes([{"secret_file": os.path.join(d, "missing")}])
            self.assertEqual(m2, {})
            # bump mtime -> different map
            os.utime(p, ns=(os.stat(p).st_atime_ns + 10**9, os.stat(p).st_mtime_ns + 10**9))
            m3 = MOD.sink_mtimes(s)
            self.assertNotEqual(m1, m3)


def _free_port():
    """Claim a free TCP port on loopback."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _vault_cli(base, args, addr, token):
    """Run the vault CLI against `addr` and return (rc, stdout)."""
    env = dict(os.environ)
    env["VAULT_ADDR"] = addr
    env["VAULT_TOKEN"] = token
    env["HOME"] = str(base)  # isolate from the operator's vault config
    p = subprocess.run(["vault"] + args, capture_output=True, text=True, env=env, timeout=20)
    return p.returncode, p.stdout + p.stderr


class VaultIntegration(unittest.TestCase):
    """End to end: dev vault server + AppRole + vault agent renders a secret to
    a sink, the gate binds that sink, and the mtime watcher reloads the gate
    when the sink changes. Loopback, fake values, masked output."""

    IRON = (
        os.environ.get("FORCECAGE_GATE_TEST_IRON_PROXY")
        or shutil.which("iron-proxy")
        or os.path.expanduser("~/.local/state/forcecage/iron-proxy/iron-proxy"))

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.IRON):
            raise unittest.SkipTest("iron-proxy binary not found: %s" % cls.IRON)
        if shutil.which("vault") is None:
            raise unittest.SkipTest("vault CLI not on PATH")
        cls.base = Path("/tmp/sbx-gate-test/vault")
        cls.base.mkdir(parents=True, exist_ok=True)
        cls.root = "dev-token-test-%d" % os.getpid()
        # dev server on a loopback port, isolated HOME
        cls.vport = _free_port()
        cls.addr = "http://127.0.0.1:%d" % cls.vport
        log = open(cls.base / "vault.log", "wb")
        cls.vault = subprocess.Popen(
            ["vault", "server", "-dev", "-dev-no-store-token",
             "-dev-listen-address=127.0.0.1:%d" % cls.vport,
             "-dev-root-token-id=%s" % cls.root],
            stdout=log, stderr=subprocess.STDOUT, env={**os.environ, "HOME": str(cls.base)},
        )
        # wait for readiness
        for _ in range(60):
            rc, _ = _vault_cli(cls.base, ["status"], cls.addr, cls.root)
            if rc == 0:
                break
            time.sleep(0.25)
        else:
            raise unittest.SkipTest("vault dev server did not become ready")
        rc, out = _vault_cli(cls.base, ["auth", "enable", "approle"], cls.addr, cls.root)
        assert rc == 0, out
        # policy + KV secret + AppRole
        pol = cls.base / "gate-policy.hcl"
        pol.write_text("path \"secret/data/gate/*\" { capabilities = [\"read\"] }\n")
        rc, out = _vault_cli(cls.base, ["policy", "write", "gate-read", str(pol)], cls.addr, cls.root)
        assert rc == 0, out
        rc, out = _vault_cli(cls.base,
            ["kv", "put", "secret/gate/example-api", "value=VAULT-INTEG-VALUE-0001"],
            cls.addr, cls.root)
        assert rc == 0, out
        rc, out = _vault_cli(cls.base,
            ["write", "auth/approle/role/gate-test",
             "token_ttl=5m", "token_max_ttl=5m", "token_policies=gate-read",
             "secret_id_ttl=5m", "secret_id_num_uses=0"],
            cls.addr, cls.root)
        assert rc == 0, out
        rc, out = _vault_cli(cls.base, ["read", "-field=role_id", "auth/approle/role/gate-test/role-id"], cls.addr, cls.root)
        assert rc == 0, out
        cls.role_id = out.strip()
        rc, out = _vault_cli(cls.base, ["write", "-force", "-field=secret_id", "auth/approle/role/gate-test/secret-id"], cls.addr, cls.root)
        assert rc == 0, out
        cls.secret_id = out.strip()

    @classmethod
    def tearDownClass(cls):
        for p in getattr(cls, "ups", []):
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                pass
        v = getattr(cls, "vault", None)
        if v:
            v.terminate()
            try:
                v.wait(timeout=3)
            except Exception:
                v.kill()

    def test_vault_agent_sink_and_gate_reload(self):
        base = self.base
        gate_dir = str(base / "v-gate")
        shutil.rmtree(gate_dir, ignore_errors=True)
        # 1. generate the vault agent config + AppRole id files
        rc = MOD.main([
            "vault-config", "--gate-dir", gate_dir,
            "--vault-addr", self.addr,
            "--role-id", self.role_id, "--secret-id", self.secret_id,
            "--sink", "example-api=secret/gate/example-api",
        ])
        self.assertEqual(rc, 0, "vault-config failed")
        hcl_path = os.path.join(gate_dir, "vault-agent.hcl")
        self.assertTrue(os.path.isfile(hcl_path), "vault-agent.hcl missing")
        hcl = Path(hcl_path).read_text()
        self.assertIn("method {", hcl)
        # the secret-id file the agent will consume
        secret_id_file = os.path.join(gate_dir, "vault-secret-id")
        self.assertTrue(os.path.isfile(secret_id_file))
        sink_path = os.path.join(gate_dir, "tok-example-api")
        # 2. start the gate with the vault agent + sink watcher
        # a fresh echo upstream on a known port for this test
        eport = 18950
        echo = _start_echo("127.0.0.2", eport)
        bf = base / "v-bindings.json"
        bf.write_text(json.dumps([{"name": "example-api", "host": "127.0.0.2",
                                   "secret_file": sink_path,
                                   "placeholder": "Placeholder-v", "match_headers": ["Authorization"]}]))
        try:
            # wait_handler returns immediately: the sink watcher is a daemon
            # thread that lives on in this process; a CLI `--wait` would block.
            rc = MOD.main([
                "start", "--session", "v", "--dir", gate_dir,
                "--port-mgmt", "28950", "--port-proxy", "28951",
                "--port-tunnel", "28952", "--port-http", "28953", "--port-dns", "28954",
                "--vault-config", hcl_path, "--vault-addr", self.addr,
                "--wait", "--ready-timeout", "15", "--watch-interval", "2",
                "--bindings", str(bf),
                "--allowlist", '{"domains":["*.localhost"],"cidrs":["127.0.0.0/8"]}',
                "--upstream", "http://127.0.0.2:%d" % eport, "--upstream-deny", "[]",
                "--inert", "INERT-V-XYZ", "--iron-proxy", self.IRON,
            ], wait_handler=lambda: None)
            self.assertEqual(rc, 0, "gate start failed")
        except SystemExit as e:
            self.fail("gate start exited: %r" % e)
        # 3. wait for the sink to be rendered by the vault agent
        try:
            for _ in range(80):
                if os.path.isfile(sink_path) and "VAULT-INTEG-VALUE-0001" in Path(sink_path).read_text():
                    break
                time.sleep(0.25)
            else:
                self.fail("vault agent did not render the sink")
            # the agent consumes the secret-id file on auth
            self.assertFalse(os.path.isfile(secret_id_file), "secret-id file should be consumed by the agent")
            # 4. prove the gate swaps the placeholder for the vault-rendered value
            # read the mgmt proxy port from state.json
            state = json.load(open(os.path.join(gate_dir, "state.json")))
            # the HTTP proxy port (the echo upstream is plain HTTP, so the
            # request is absolute-form, not a CONNECT through the TLS port)
            proxy = "http://127.0.0.1:%d" % state["listen"]["http"]
            body = _proxy_get(proxy, "http://127.0.0.2:%d/" % eport, "Placeholder-v")
            self.assertIn("VAULT-INTEG-VALUE-0001", body, body)
            self.assertNotIn("INERT-V-XYZ", body, body)
            # 5. rotate the sink (simulating a vault re-render) -> the mtime
            #    watcher must reload the gate within one poll interval
            new_val = "VAULT-INTEG-VALUE-0002"
            with open(sink_path, "w") as fh:
                fh.write(new_val)
            os.utime(sink_path, ns=(os.stat(sink_path).st_atime_ns + 10**9, os.stat(sink_path).st_mtime_ns + 10**9))
            # poll the proxy until the new value appears (bounded by the 15s interval + slack)
            ok = False
            for _ in range(120):
                body = _proxy_get(proxy, "http://127.0.0.2:%d/" % eport, "Placeholder-v")
                if new_val in body:
                    ok = True
                    break
                time.sleep(0.25)
            self.assertTrue(ok, "gate did not pick up the rotated sink within the poll window: %s" % body)
        finally:
            MOD.main(["stop", "--dir", gate_dir])
            echo.terminate()
            echo.wait(timeout=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
