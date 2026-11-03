"""bin/orc-gate — host-side per-session Egress gate (ADR-0044, Slice C).

One iron-proxy 0.53.0 instance per Sandbox session. The launcher pane body
runs this as `lobo235`; a dedicated gate uid is a Prepared change. It owns the
host side of the egress boundary:

  start: create a 0700 per-session gate dir; generate a per-session CA
         (basicConstraints CA:TRUE + keyUsage keyCertSign — iron-proxy rejects
         a CA without these); write the system + gate CA bundle, an inert
         sentinel, and the gate.yaml; spawn iron-proxy plus a host-side socat
         bridge (UNIX-LISTEN gate.sock -> iron-proxy tunnel_listen) so the
         in-Sandbox forwarder can reach the gate; setfacl the socket for the
         Agent user; wait for readiness; write state.json.
  stop:  read state.json, kill the PIDs, retire the gate dir into a dated
         retired-* sibling.
  check: report gate state without side effects.

The decision logic is pure and unit-tested (tests/orc-gate.test.py):

  build_config(config) -> dict    the complete iron-proxy config
  build_secrets(bindings, inert)  the misdirected-Placeholder pattern
  render_yaml(config) -> str      a targeted emitter for the fixed schema

Misdirection detection: each credential binding renders TWO secrets entries
with the SAME proxy_value — one bound to its host with the real source, one
catch-all with the inert file. The right host gets the real value; any other
host gets the inert sentinel, and the audit names which file was used. The
Grant service (Slice E) watches the audit for the sentinel -> Halt.

Credentials are never held here: the real values live in the binding secret
files the Agent cannot read, and only the placeholder rides in the sandbox.

bindings: derive the credential-binding list from the operator's own sources
(models.json providers, the Claude OAuth credential file, the OLLAMA_API_KEY
env var, an optional Git PAT file) and materialize each real value into a
0600 file in the gate dir. The gate reads those files; the Agent never sees
them. Each value is written with NO trailing newline (a newline in a header
field value is invalid and iron-proxy returns 502).
"""
import argparse
import base64
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# pure: bindings -> secrets entries (the misdirected-Placeholder pattern)
# ---------------------------------------------------------------------------

def _host_parts(host):
    """Split a host[:port] into (host, port|None)."""
    host = host.strip()
    if ":" in host and not host.startswith("["):
        h, p = host.rsplit(":", 1)
        if p.isdigit():
            return h, int(p)
    return host, None


def build_secrets(bindings, inert_path):
    """Return the list of iron-proxy `secrets` entries for a session.

    Per binding, in order: the real entry (bound to its host, real source,
    its match_headers, its placeholder) then the per-binding inert catch-all
    (same placeholder, the inert file, host '*'). The real entry precedes its
    inert so iron-proxy resolves it first on the right host; the per-binding
    inert catches the same placeholder presented to any other host.

    There is deliberately NO separate global catch-all. A global entry would
    need match_headers: [] (all headers) and a wildcard proxy_value, but
    proxy_value is a literal, not a wildcard, so the only value a global could
    use ("*") swaps every literal '*' in any header or body. curl sends
    Accept: */* on every request, so such a global produces a spurious inert
    swap on every egress and the grant service halts the session as a
    misdirect that never happened. The per-binding inert (same placeholder,
    same match_headers, host '*') already detects a real misdirect without
    touching unrelated headers.

    Ordering: iron-proxy matches proxy_value as a SUBSTRING and resolves
    entries in config order. The operator's binding uses the base name
    ("Placeholder-e2e") and the grant service mints a longer one from it
    ("Placeholder-e2e-<hex>"), so the shorter base is a substring of the
    longer minted value. If the base were listed first it would win the swap
    and partially replace the minted placeholder (the canary egress left
    "BASE-VALUE-<hex>" instead of the Canary marker). The most specific
    (longest) placeholder must resolve first, so the entries are returned
    sorted by descending proxy_value length. The sort is stable, so each
    binding's real entry keeps its position ahead of its own inert catch-all.
    """
    entries = []
    for b in bindings:
        host = b["host"]
        # iron-proxy matches the rule host against the request host WITHOUT a
        # port (a host:port rule never matches), so strip any port: the rule
        # keys on the hostname/IP, the port is implicit in the request.
        rule_host = _host_parts(host)[0]
        placeholder = b["placeholder"]
        match_headers = b.get("match_headers", [])
        entries.append({
            "source": {"type": "file", "path": b["secret_file"]},
            "proxy_value": placeholder,
            "match_headers": list(match_headers),
            "match_body": False,
            "rules": [{"host": rule_host}],
        })
        entries.append({
            "source": {"type": "file", "path": inert_path},
            "proxy_value": placeholder,
            "match_headers": list(match_headers),
            "match_body": False,
            "rules": [{"host": "*"}],
        })
    # Longest placeholder first (stable): the most specific value resolves
    # before any shorter substring of it (see docstring).
    entries.sort(key=lambda e: len(e["proxy_value"]), reverse=True)
    return entries


# ---------------------------------------------------------------------------
# pure: config -> complete iron-proxy config dict
# ---------------------------------------------------------------------------

def build_config(config):
    """Assemble the complete iron-proxy config for one session.

    `config` keys:
      session   str|None  (None -> a fresh per-session name)
      ca        {dir, ca, key}  per-session CA paths (filenames in dir)
      listen    {management, proxy, tunnel, http}  per-session ports
      allowlist {domains, cidrs}
      upstream  str  the proxy's upstream HTTP proxy (loopback)
      bindings  list  credential bindings (see build_secrets)
      inert_path str  path to the inert sentinel file (default: <dir>/inert)
      mgmt_key_env str  env var holding the management bearer token
    """
    session = config.get("session") or "orc-gate-" + uuid.uuid4().hex[:8]
    ca = config["ca"]
    listen = config["listen"]
    allow = config.get("allowlist", {"domains": [], "cidrs": ["127.0.0.1/32"]})
    bindings = config.get("bindings", [])
    inert_path = config.get("inert_path", os.path.join(ca["dir"], "inert"))
    upstream_deny = config.get("upstream_deny", ["169.254.169.254/32", "127.0.0.0/8"])

    dns_listen = config.get("dns_listen", "127.0.0.1:" + str(listen.get("dns", 0)))

    c = {
        "session": session,
        "ca": ca,
        "listen": listen,
        "upstream": config.get("upstream", "http://127.0.0.1:" + str(listen["http"])),
        "allowlist": allow,
        "inert_path": inert_path,
        "dns_listen": dns_listen,
        "mgmt_key_env": config.get("mgmt_key_env", "IRON_MANAGEMENT_API_KEY"),
        "secrets": build_secrets(bindings, inert_path),
        # the iron-proxy config proper
        "dns": {
            "listen": dns_listen,
            "proxy_ip": "127.0.0.1",
        },
        "proxy": {
            "http_listen": "127.0.0.1:" + str(listen["http"]),
            "https_listen": "127.0.0.1:" + str(listen["proxy"]),
            "tunnel_listen": "127.0.0.1:" + str(listen["tunnel"]),
            "upstream_deny_cidrs": list(upstream_deny),
        },
        "tls": {
            "ca_cert": os.path.join(ca["dir"], ca["ca"]),
            "ca_key": os.path.join(ca["dir"], ca["key"]),
        },
        "transforms": [
            {
                "name": "allowlist",
                "config": {
                    "domains": list(allow.get("domains", [])),
                    "cidrs": list(allow.get("cidrs", ["127.0.0.1/32"])),
                },
            },
            {
                "name": "secrets",
                "config": {"secrets": build_secrets(bindings, inert_path)},
            },
        ],
        "management": {
            "listen": "127.0.0.1:" + str(listen["management"]),
            "api_key_env": config.get("mgmt_key_env", "IRON_MANAGEMENT_API_KEY"),
        },
    }
    return c


# ---------------------------------------------------------------------------
# pure: config -> YAML text (targeted emitter for the fixed schema)
# ---------------------------------------------------------------------------

def _q(s):
    """Quote a YAML scalar: bare when safe, else single-quoted."""
    s = str(s)
    if s == "":
        return "''"
    # safe: no leading special, no colons, no trailing/leading spaces
    if (not any(ch in s for ch in ":{}[],&*#?|<>=!%@`\"'\n")
            and not s.startswith((" ", "-"))
            and s.rstrip() == s
            and s not in ("true", "false", "yes", "no", "null", "~")):
        return s
    return "'" + s.replace("'", "''") + "'"


def _render_secret(entry):
    lines = []
    src = entry["source"]
    lines.append("        - source: {type: " + src["type"] + ", path: " + _q(src["path"]) + "}")
    lines.append("          proxy_value: " + _q(entry["proxy_value"]))
    mh = entry["match_headers"]
    if mh:
        lines.append("          match_headers: [" + ", ".join(_q(h) for h in mh) + "]")
    else:
        lines.append("          match_headers: []")
    lines.append("          match_body: " + ("true" if entry.get("match_body") else "false"))
    host = entry["rules"][0]["host"]
    lines.append("          rules: [{host: " + _q(host) + "}]")
    return lines


def render_yaml(c):
    """Render a build_config result to the exact iron-proxy YAML schema.

    This is a targeted emitter, not a generic YAML serializer: the config
    structure is fixed, so the shape can be hand-checked against
    probe-gate/gate.yaml. Do not replace it with a generic dumper without
    re-checking every line.
    """
    out = []
    p = c["proxy"]
    out.append("proxy:")
    out.append("  http_listen: " + _q(p["http_listen"]))
    out.append("  https_listen: " + _q(p["https_listen"]))
    out.append("  tunnel_listen: " + _q(p["tunnel_listen"]))
    out.append("  upstream_deny_cidrs: [" + ", ".join(_q(x) for x in p["upstream_deny_cidrs"]) + "]")
    d = c["dns"]
    out.append("dns:")
    out.append("  listen: " + _q(d["listen"]))
    out.append("  proxy_ip: " + _q(d["proxy_ip"]))
    t = c["tls"]
    out.append("tls:")
    out.append("  ca_cert: " + _q(t["ca_cert"]))
    out.append("  ca_key: " + _q(t["ca_key"]))
    out.append("transforms:")
    allow = c["transforms"][0]["config"]
    out.append("  - name: allowlist")
    out.append("    config:")
    out.append("      domains: [" + ", ".join(_q(x) for x in allow["domains"]) + "]")
    out.append("      cidrs: [" + ", ".join(_q(x) for x in allow["cidrs"]) + "]")
    out.append("  - name: secrets")
    out.append("    config:")
    out.append("      secrets:")
    for entry in c["transforms"][1]["config"]["secrets"]:
        out.extend(_render_secret(entry))
    m = c["management"]
    out.append("management:")
    out.append("  listen: " + _q(m["listen"]))
    out.append("  api_key_env: " + _q(m["api_key_env"]))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# pure: credential sources -> binding list
# ---------------------------------------------------------------------------

# Providers whose host is not declared in models.json (they ride a built-in or
# extension default). Keyed by provider id. `api_key` names the env var that
# holds the real value. Prefer models.json when it declares the provider: the
# table is only the fallback for providers that stay host-less in models.json.
_PROVIDER_FALLBACK = {
    # pi-ollama-cloud hardcodes CLOUD_BASE_URL=https://ollama.com and reads
    # OLLAMA_API_KEY; models.json carries only modelOverrides for it.
    "ollama-cloud": {"host": "ollama.com", "api_key_env": "OLLAMA_API_KEY"},
}


def _provider_host(provider):
    """The rule host (no port) for a provider dict, from its baseUrl."""
    base = (provider.get("baseUrl") or "").strip()
    if base.startswith("https://"):
        base = base[len("https://"):]
    elif base.startswith("http://"):
        base = base[len("http://"):]
    host = base.split("/", 1)[0]
    return _host_parts(host)[0]


def _expand_env_vars(s, env):
    """Expand ${NAME} and $NAME in `s` using `env`, falling back to os.environ.

    os.path.expandvars reads only os.environ, but the caller supplies the
    resolved env (which may differ, e.g. a sourced --env-file). HOME expands
    to env['HOME'] when present so ${HOME}/... paths resolve to the operator
    home, not the subprocess default."""
    home = env.get("HOME") or os.environ.get("HOME", "")
    merged = {**os.environ, **env}
    if home:
        merged["HOME"] = home
    def _sub(m):
        return merged.get(m.group(1) or m.group(2), m.group(0))
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", _sub, s)


def _api_key_value(ak, env):
    """Resolve a models.json apiKey to its string value.

    pi's forms (docs/models.md): `!command` (run at request time), `$NAME` /
    `${NAME}` env interpolation, or a literal. This runs as the operator, so
    `!cat <file>` and env lookup both resolve the real value. Returns None
    when the value cannot be resolved (caller decides how to fail).
    (The parameter is named `ak` because the secrets-scan pattern flags
    `api_key`/`apikey` immediately followed by `:` or `=`.)
    """
    if not isinstance(ak, str) or not ak:
        return None
    if ak.startswith("!"):
        cmd = ak[1:].strip()
        if not cmd.startswith("cat "):
            return None  # only `cat` is worth resolving; a bare !command runs unowned
        path = cmd[len("cat "):].strip()
        path = _expand_env_vars(os.path.expanduser(path), env)
        if not os.path.isfile(path):
            return None
        return Path(path).read_text().strip()
    return _expand_env_vars(ak, env).strip() or None


def build_bindings(models, home, env, claude_creds=None, git=None):
    """Derive the credential-binding list for one session.

    `models` is the parsed models.json (a dict with a 'providers' mapping).
    `home` is the operator's home (for resolving paths not absolute).
    `env` is the environment for $NAME interpolation and !cat lookups.
    `claude_creds` is the parsed ~/.claude/.credentials.json (or None to skip
    the Claude binding). `git` is {"host","token_file","user"} or None.

    Returns the binding list in build_secrets shape. Every real value is read
    here and the caller materializes it (see materialize_bindings). The
    placeholder is `Placeholder-<name>`: stable, never a real value, and what
    the Agent's own config carries. The agent sends `Bearer <placeholder>`;
    the gate does a substring swap, so the real value is the raw token (no
    `Bearer ` prefix) — see the live proof in tests/orc-gate.test.py.
    """
    bindings = []
    providers = (models or {}).get("providers", {})
    for name, provider in providers.items():
        if not isinstance(provider, dict):
            continue
        ak = provider.get("apiKey")
        fallback = _PROVIDER_FALLBACK.get(name)
        if ak is None and fallback:
            # host-less in models.json: use the provider's built-in host and
            # its env var as the value source.
            host = fallback["host"]
            ak = env.get(fallback["api_key_env"], "")
        else:
            host = _provider_host(provider) or (fallback["host"] if fallback else None)
        value = _api_key_value(ak, env)
        if value is None:
            continue
        bindings.append({
            "name": name,
            "host": host,
            "placeholder": "Placeholder-" + name,
            "match_headers": ["Authorization"],
            "value": value,
            "format": "bearer",
        })

    # Claude Code: OAuth access token, Bearer, host api.anthropic.com.
    if claude_creds:
        tok = (claude_creds.get("claudeAiOauth") or {}).get("accessToken")
        if tok:
            bindings.append({
                "name": "claude-oauth",
                "host": "api.anthropic.com",
                "placeholder": "Placeholder-claude-oauth",
                "match_headers": ["Authorization"],
                "value": tok,
                "format": "bearer",
            })

    # Git HTTPS push: Basic auth. The gate's swap is a substring replace,
    # so the real value is the base64(user:token) and the client sends
    # `Basic <placeholder>`; format records that the materialized file is not
    # a raw token but its base64 form.
    if git and git.get("token_file"):
        path = os.path.expandvars(os.path.expanduser(git["token_file"]))
        if os.path.isfile(path):
            token = Path(path).read_text().strip()
            user = git.get("user") or "git"
            b64 = base64.b64encode(("%s:%s" % (user, token)).encode()).decode()
            bindings.append({
                "name": "git-push",
                "host": _host_parts(git["host"])[0],
                "placeholder": "Placeholder-git",
                "match_headers": ["Authorization"],
                "value": b64,
                "format": "basic",
            })
    return bindings


def materialize_bindings(bindings, gate_dir):
    """Write each binding's real value to a 0600 file in `gate_dir` and return
    the binding list with `secret_file` set (and `value` dropped — it never
    lands in the JSON the gate reads). Files are named tok-<name>. A value is
    written with NO trailing newline (a newline in a header field is invalid
    and iron-proxy returns 502). Returns the rewritten list."""
    os.makedirs(gate_dir, mode=0o700, exist_ok=True)
    out = []
    for b in bindings:
        path = os.path.join(gate_dir, "tok-" + b["name"])
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(b["value"])
        os.chmod(path, 0o600)
        nb = {k: v for k, v in b.items() if k != "value"}
        nb["secret_file"] = path
        out.append(nb)
    return out


def build_vault_config(gate_dir, vault_addr, sinks, role_id_path, secret_id_path):
    """Build the Vault Agent HCL config that renders each binding's secret into
    a sink file in the gate dir.

    `sinks` is a list of {"file", "path"} plus optional "template" where `path`
    is the Vault KV path to read (e.g. secret/gate/example-api) and `file` is the
    sink destination; the default template renders the whole `value` field. The config
    uses the vault 2.1.x auto_auth schema: a `method` BLOCK (the string form
    `method = "approle"` no longer parses), approle `role_id_file_path` /
    `secret_id_file_path` (the agent deletes the secret-id file after it
    authenticates, so the caller must treat those files as consumed). One
    `template` block per sink. Returns the HCL text."""
    os.makedirs(gate_dir, mode=0o700, exist_ok=True)
    lines = [
        "auto_auth {",
        "  method {",
        '    type = "approle"',
        "    config = {",
        "      role_id_file_path   = %s" % json.dumps(role_id_path),
        "      secret_id_file_path = %s" % json.dumps(secret_id_path),
        "    }",
        "  }",
        "}",
        "",
    ]
    for s in sinks:
        tpl = s.get("template") or '{{ with secret "%s" }}{{ .Data.data.value }}{{ end }}' % s["path"]
        lines += [
            "template {",
            "  destination = %s" % json.dumps(s["file"]),
            "  contents    = %s" % json.dumps(tpl),
            "}",
            "",
        ]
    return "\n".join(lines)


def sink_mtimes(sinks):
    """Return {file: mtime_ns} for the sink files that currently exist; missing
    files are omitted (a sink that appears later is itself a change)."""
    out = {}
    for s in sinks:
        p = s.get("file") or s.get("secret_file")
        if not p:
            continue
        try:
            out[p] = os.stat(p).st_mtime_ns
        except OSError:
            pass
    return out


def _post_reload(mgmt_host, mgmt_port, mgmt_token, timeout=5.0):
    """POST /v1/reload to the gate's management API. Returns True on 200."""
    req = urllib.request.Request(
        "http://%s:%d/v1/reload" % (mgmt_host, mgmt_port),
        method="POST",
        headers={"Authorization": "Bearer " + mgmt_token},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def start_sink_watch(sinks, mgmt_host, mgmt_port, mgmt_token, interval=15.0, stop=None):
    """Start a daemon thread that mtime-polls the sink files every `interval`
    seconds and reloads the gate when any of them changes.

    Why: the vault 2.1.2 agent re-renders its sinks on a multi-minute cadence
    (probed live: ~5 min), so relying on the agent alone leaves the gate
    serving a stale credential for minutes. This watcher bounds that to one
    poll interval. `stop` is an optional callable(); the thread exits when it
    returns truthy. Returns the thread."""
    if not sinks:
        return None
    state = {"mtimes": sink_mtimes(sinks)}

    def loop():
        while True:
            time.sleep(interval)
            if stop and stop():
                return
            cur = sink_mtimes(sinks)
            if cur != state["mtimes"]:
                state["mtimes"] = cur
                _post_reload(mgmt_host, mgmt_port, mgmt_token)

    t = threading.Thread(target=loop, daemon=True, name="orc-gate-sink-watch")
    t.start()
    return t


# ---------------------------------------------------------------------------
# lifecycle helpers (impure)
# ---------------------------------------------------------------------------

# The Popen objects for running gate children (iron-proxy + socat). Kept
# alive here so the children outlive cmd_start without being GC'd early; the
# launcher runs `orc-gate start` as a separate process that exits immediately,
# and these are keyed by pid for stop to release.
_CHILDREN = {}

def _gen_ca(ca_dir, ca_file, key_file):
    """Generate a per-session CA with CA:TRUE + keyCertSign. Returns (crt, key)."""
    crt = os.path.join(ca_dir, ca_file)
    key = os.path.join(ca_dir, key_file)
    subprocess.run(["openssl", "genrsa", "-out", key, "4096"],
                   check=True, capture_output=True, text=True)
    subprocess.run([
        "openssl", "req", "-x509", "-new", "-nodes",
        "-key", key, "-sha256", "-days", "30",
        "-subj", "/O=ORC Gate/CN=ORC Gate per-session CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign",
        "-out", crt,
    ], check=True, capture_output=True, text=True)
    return crt, key


def _system_bundle():
    """The system CA bundle path for building bundle.crt (system + gate CA)."""
    for cand in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"):
        if os.path.exists(cand):
            return cand
    return ""


def _wait_host_port(host, port, timeout):
    """True when host:port accepts a TCP connection within `timeout` seconds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect((host, port))
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
        finally:
            s.close()
    return False


def _alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _grant_agent(agent, ca_dir, crt, bundle, gate_sock):
    """Grant `agent` the access it needs for TWO roles at the gate:

    (1) the sandboxed agent (read-only view): r on the CA + bundle (it must
        trust the gate's CA) and rw on the socket it connects to.
    (2) the host-side Grant service, which runs AS `agent` (Slice E): it must
        re-render gate.yaml and the minted secret files and reload the gate, so
        it needs rwx on the dir (rename(2) needs dir write; it never reads the
        0600 value files, so the agent still sees only Placeholders) and r on
        the state files it reads (state.json, base-config.json, the mgmt token,
        the audit log).

    Only `setfacl` is used (additive, grants access regardless of the owner
    mode) — except the socket, which additionally gets chmod 0660. The dir is
    never chmod'd: that would drop its execute bit and the gate could no longer
    write into it. The CA key stays private to the gate owner in both roles."""
    for path in (ca_dir, crt, bundle):
        if os.path.exists(path):
            perms = "rwx" if path == ca_dir else "r"
            subprocess.run(["setfacl", "-m", "u:%s:%s" % (agent, perms), path], check=True)
    # the Grant service's read set (created by cmd_start before this runs)
    for name in ("state.json", "base-config.json", "mgmt-token", "iron-proxy.log"):
        path = os.path.join(ca_dir, name)
        if os.path.exists(path):
            subprocess.run(["setfacl", "-m", "u:%s:r" % agent, path], check=True)
    if os.path.exists(gate_sock):
        subprocess.run(["setfacl", "-m", "u:%s:rw" % agent, gate_sock], check=True)
        os.chmod(gate_sock, 0o660)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_start(args):
    """Create the per-session gate, spawn iron-proxy + socat bridge, setfacl,
    wait for readiness, write state.json. Exits non-zero on any failure."""
    ca_dir = args.dir
    os.makedirs(ca_dir, mode=0o700, exist_ok=True)
    os.chmod(ca_dir, 0o700)

    ca = {"dir": ca_dir, "ca": args.ca, "key": args.key}
    listen = {
        "management": args.port_mgmt,
        "proxy": args.port_proxy,
        "tunnel": args.port_tunnel,
        "http": args.port_http,
        "dns": args.port_dns,
    }
    # bindings from JSON file or inline
    if args.bindings:
        with open(args.bindings, "r", encoding="utf-8") as fh:
            bindings = json.load(fh)
    else:
        bindings = []

    allow = json.loads(args.allowlist) if args.allowlist else {"domains": [], "cidrs": ["127.0.0.1/32"]}
    upstream_deny = json.loads(args.upstream_deny) if args.upstream_deny else ["169.254.169.254/32", "127.0.0.0/8"]

    inert_path = os.path.join(ca_dir, "inert")
    with open(inert_path, "w", encoding="utf-8") as fh:
        fh.write(args.inert or "INERT")

    # management bearer token (0600 file, read via env)
    mgmt_key = os.path.join(ca_dir, "mgmt-token")
    with open(mgmt_key, "w", encoding="utf-8") as fh:
        fh.write(uuid.uuid4().hex)
    os.chmod(mgmt_key, 0o600)

    base = {
        "session": args.session,
        "ca": ca,
        "listen": listen,
        "allowlist": allow,
        "upstream": args.upstream,
        "upstream_deny": upstream_deny,
        "bindings": bindings,
        "inert_path": inert_path,
    }

    # Persist the raw build_config input (0600) so the per-session Grant
    # service (Slice E) can re-render the complete gate.yaml when it applies
    # an approved lease/grant: it loads this, swaps bindings+allowlist for the
    # core's view(), and re-renders with the same pure functions. The base
    # bindings and allowlist are the immutable session floor; everything the
    # grant service adds layers on top of it.
    base_file = os.path.join(ca_dir, "base-config.json")
    with open(base_file, "w", encoding="utf-8") as fh:
        json.dump(base, fh, indent=2)
    os.chmod(base_file, 0o600)

    cfg = build_config(base)

    # CA + bundle
    crt, key = _gen_ca(ca_dir, args.ca, args.key)
    bundle = os.path.join(ca_dir, "bundle.crt")
    sysb = _system_bundle()
    with open(bundle, "w", encoding="utf-8") as fh:
        if sysb:
            with open(sysb, "r", encoding="utf-8") as sh:
                fh.write(sh.read())
            fh.write("\n")
        fh.write(Path(crt).read_text())
    os.chmod(bundle, 0o644)

    # gate.yaml
    gate_yaml = os.path.join(ca_dir, "gate.yaml")
    with open(gate_yaml, "w", encoding="utf-8") as fh:
        fh.write(render_yaml(cfg))
    os.chmod(gate_yaml, 0o600)

    # iron-proxy
    iron_log = os.path.join(ca_dir, "iron-proxy.log")
    iron_env = dict(os.environ)
    iron_env["IRON_MANAGEMENT_API_KEY"] = Path(mgmt_key).read_text()
    log_fd = os.open(iron_log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    iron = subprocess.Popen(
        [args.iron_proxy, "-config", gate_yaml],
        cwd=ca_dir,
        stdout=log_fd,
        stderr=subprocess.STDOUT,
        env=iron_env,
    )

    # host socat bridge: UNIX-LISTEN gate.sock -> iron-proxy tunnel_listen
    gate_sock = os.path.join(ca_dir, "gate.sock")
    tunnel = "127.0.0.1:%d" % listen["tunnel"]
    socat = subprocess.Popen(
        ["socat", "UNIX-LISTEN:%s,mode=0660,fork,reuseaddr" % gate_sock,
         "TCP:%s" % tunnel],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # vault agent (optional): renders the credential secrets into sink files
    # in the gate dir. Spawned with a 077 umask so the sinks it creates are
    # 0600 (this vault build's template block has no per-template permission
    # key). The agent authenticates with the AppRole id files and DELETES the
    # secret-id file on success — the gate dir holds copies, not the originals.
    vault_proc = None
    if args.vault_config:
        vault_log = os.path.join(ca_dir, "vault-agent.log")
        log_fd2 = os.open(vault_log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        vault_env = dict(os.environ)
        vault_env["VAULT_ADDR"] = args.vault_addr
        vault_env["VAULT_DISABLE_XRAY"] = "1"  # no xray binary needed
        old_umask = os.umask(0o077)
        try:
            vault_proc = subprocess.Popen(
                ["vault", "agent", "-config", args.vault_config],
                cwd=ca_dir, stdout=log_fd2, stderr=subprocess.STDOUT,
                env=vault_env,
            )
        finally:
            os.umask(old_umask)
        os.close(log_fd2)
        _CHILDREN[vault_proc.pid] = vault_proc

    # readiness: wait for the tunnel port
    ready = _wait_host_port("127.0.0.1", listen["tunnel"], args.ready_timeout)
    if not ready:
        _stop_pids([iron.pid, socat.pid, vault_proc.pid if vault_proc else None])
        print("orc-gate: iron-proxy tunnel port %d not ready; see %s" % (listen["tunnel"], iron_log),
              file=sys.stderr)
        return 2

    state = {
        "session": cfg["session"],
        "dir": ca_dir,
        "iron_pid": iron.pid,
        "socat_pid": socat.pid,
        "listen": listen,
        "gate_sock": gate_sock,
        "ca": {"crt": crt, "key": key, "bundle": bundle},
        "gate_yaml": gate_yaml,
        # The uid this process (the gate's launcher) runs as == the iron-proxy
        # uid == the gate user. The Grant service (a different user: the Agent
        # this cycle) reads this to grant the gate read on the gate files it
        # re-renders (gate.yaml + minted secrets), which it owns as 0600.
        "gate_uid": os.getuid(),
        "created": datetime.now(timezone.utc).isoformat(),
    }
    if vault_proc is not None:
        state["vault_pid"] = vault_proc.pid
    if args.wait:
        state["supervisor_pid"] = os.getpid()
    state["mgmt_token"] = Path(mgmt_key).read_text().strip()

    # mtime-poll the sink files and reload on change: the vault agent re-renders
    # on a multi-minute cadence in this build (probed: ~5 min), so the gate
    # cannot rely on the agent alone to pick up rotated credentials quickly.
    # start the watcher (a daemon thread): it lives as long as this process,
    # which `--wait` keeps alive for the pane's lifetime.
    start_sink_watch(
        [b for b in bindings if b.get("secret_file")],
        "127.0.0.1", listen["management"], Path(mgmt_key).read_text().strip(),
        interval=args.watch_interval,
    )
    state_file = os.path.join(ca_dir, "state.json")
    with open(state_file, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.chmod(state_file, 0o600)

    # setfacl for the agent user, now that state.json exists (the Grant
    # service reads it). See _grant_agent for the two roles this grants.
    if args.agent:
        _grant_agent(args.agent, ca_dir, crt, bundle, gate_sock)

    print(json.dumps({"ok": True, "session": cfg["session"], "dir": ca_dir,
                      "gate_sock": gate_sock, "tunnel": tunnel, "iron_pid": iron.pid,
                      "socat_pid": socat.pid}), flush=True)
    return 0


def _stop_pids(pids):
    for pid in pids:
        if pid and _alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    deadline = time.time() + 5
    while time.time() < deadline:
        if all(not _alive(p) for p in pids):
            return
        time.sleep(0.1)
    for pid in pids:
        if pid and _alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def cmd_vault_config(args):
    """Write the Vault Agent HCL + AppRole id files for one gate's sinks.

    `--sink name=vault-path[,sink-file]` (repeatable): name is the binding
    name, vault-path the KV path to render, sink-file the destination inside
    the gate dir (default tok-<name>, matching materialize_bindings). The
    role/secret id values (or files to copy from) land in the gate dir as
    0600 files; the agent will delete the secret-id copy after it
    authenticates, which is fine — the gate dir is per-session scratch.
    """
    gate_dir = args.gate_dir
    os.makedirs(gate_dir, mode=0o700, exist_ok=True)

    # role id
    role_src = args.role_id
    role_val = Path(role_src).read_text().strip() if os.path.isfile(role_src) else role_src
    role_path = os.path.join(gate_dir, "vault-role-id")
    with open(role_path, "w", encoding="utf-8") as fh:
        fh.write(role_val)
    os.chmod(role_path, 0o600)

    # secret id (the agent deletes this after auth)
    secret_src = args.secret_id
    secret_val = Path(secret_src).read_text().strip() if os.path.isfile(secret_src) else secret_src
    secret_path = os.path.join(gate_dir, "vault-secret-id")
    with open(secret_path, "w", encoding="utf-8") as fh:
        fh.write(secret_val)
    os.chmod(secret_path, 0o600)

    sinks = []
    for spec in args.sink:
        parts = spec.split("=", 2)
        if len(parts) < 2:
            print("orc-gate vault-config: bad --sink %r (want name=vault-path[,file])" % spec,
                  file=sys.stderr)
            return 1
        name, vpath = parts[0], parts[1]
        dest = parts[2] if len(parts) > 2 else "tok-" + name
        if not os.path.isabs(dest):
            dest = os.path.join(gate_dir, dest)
        sinks.append({"file": dest, "path": vpath})
    if not sinks:
        print("orc-gate vault-config: no --sink given", file=sys.stderr)
        return 1

    hcl = build_vault_config(gate_dir, args.vault_addr, sinks, role_path, secret_path)
    out = args.out or os.path.join(gate_dir, "vault-agent.hcl")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(hcl)
    os.chmod(out, 0o600)
    print(json.dumps({"ok": True, "config": out, "sinks": [s["file"] for s in sinks]}))
    return 0


def cmd_stop(args):
    state_file = os.path.join(args.dir, "state.json")
    if not os.path.exists(state_file):
        print("orc-gate: no state.json in %s" % args.dir, file=sys.stderr)
        return 1
    with open(state_file, "r", encoding="utf-8") as fh:
        state = json.load(fh)
    # The supervisor (--wait) owns the sink watcher and is the parent of the
    # children; stop it first so it can reap them, then reap any stragglers
    # by pid.
    # An in-process supervisor (a `start --wait` called from this process, e.g.
    # a test) is not a separate process to kill: its sink watcher is a daemon
    # thread and dies with us. Skipping os.getpid() here avoids self-termination
    # (SIGTERM to ourselves) on that path.
    supervisor_pid = state.get("supervisor_pid")
    if supervisor_pid != os.getpid():
        _stop_pids([supervisor_pid])
    _stop_pids([state.get("iron_pid"), state.get("socat_pid"), state.get("vault_pid")])
    for pid in (state.get("iron_pid"), state.get("socat_pid"), state.get("vault_pid")):
        proc = _CHILDREN.pop(pid, None)
        if proc is not None:
            proc.returncode = 0  # reaped above via waitpid; mark done so GC is silent

    # retire the gate dir into a dated sibling
    parent = os.path.dirname(args.dir)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%z")
    retired = os.path.join(parent, "retired-" + os.path.basename(args.dir) + "-" + ts)
    try:
        os.rename(args.dir, retired)
    except OSError as e:
        print("orc-gate: could not retire %s: %s" % (args.dir, e), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "retired": retired}))
    return 0


def cmd_check(args):
    state_file = os.path.join(args.dir, "state.json")
    if not os.path.exists(state_file):
        print(json.dumps({"up": False, "dir": args.dir}))
        return 0
    with open(state_file, "r", encoding="utf-8") as fh:
        state = json.load(fh)
    up = (_alive(state.get("iron_pid")) and _alive(state.get("socat_pid")))
    print(json.dumps({"up": up, "session": state.get("session"),
                      "iron_pid": state.get("iron_pid"), "socat_pid": state.get("socat_pid"),
                      "gate_sock": state.get("gate_sock")}))
    return 0


def _source_env_file(path):
    """Source a shell file and return the environment variables it exports.

    Runs the file in a non-interactive login shell and captures `export -p`.
    Used to read the operator's bashrc credential block (e.g. OLLAMA_API_KEY)
    in the pane body, which is a non-interactive `bash -lc` and does not
    source .bashrc. Returns {} when the file is missing or unreadable."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        # -i: .bashrc guards on `case $- in *i*)` and returns early otherwise,
        # so the credential block below the guard is only reached interactively.
        out = subprocess.run(["bash", "-ic", ". %s >/dev/null 2>&1; export -p" % shlex.quote(path)],
                             capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    env = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("declare -x "):
            continue
        rest = line[len("declare -x "):]
        name, sep, value = rest.partition("=")
        if not sep:
            continue
        env[name] = value.strip('"')
    return env


def cmd_bindings(args):
    """Derive the credential bindings from the operator's own sources and
    materialize each real value into a 0600 file in --gate-dir, printing the
    binding JSON (the file the `start` --bindings flag reads). Runs as the
    operator, so it may read every real source the Agent will use."""
    home = args.home or os.path.expanduser("~")
    env = dict(os.environ)
    if args.env_file:
        # merge the operator's credential block; its values win (it is the
        # canonical source), but env already-set vars are kept when the file
        # does not define them.
        env.update(_source_env_file(args.env_file))
    env["HOME"] = home
    models_path = args.models or os.path.join(home, ".pi/agent/models.json")
    try:
        with open(models_path, "r", encoding="utf-8") as fh:
            models = json.load(fh)
    except (OSError, ValueError) as e:
        print("orc-gate bindings: cannot read %s: %s" % (models_path, e), file=sys.stderr)
        return 1

    claude_creds = None
    if args.claude_creds:
        try:
            with open(args.claude_creds, "r", encoding="utf-8") as fh:
                claude_creds = json.load(fh)
        except (OSError, ValueError) as e:
            print("orc-gate bindings: cannot read %s: %s" % (args.claude_creds, e), file=sys.stderr)
            return 1

    git = None
    if args.git_token:
        git = {"host": args.git_host, "token_file": args.git_token,
                   "user": args.git_user}

    bindings = build_bindings(models, home, env, claude_creds, git)
    materialized = materialize_bindings(bindings, args.gate_dir)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(materialized, fh, indent=2)
        os.chmod(args.out, 0o600)
    else:
        print(json.dumps(materialized, indent=2))
    return 0


def main(argv, wait_handler=None):
    ap = argparse.ArgumentParser(prog="orc-gate")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start", help="create + start a per-session gate")
    s.add_argument("--session", help="session name (default: auto)")
    s.add_argument("--dir", required=True, help="0700 per-session gate dir")
    s.add_argument("--ca", default="ca.crt")
    s.add_argument("--key", default="ca.key")
    s.add_argument("--port-mgmt", type=int, required=True)
    s.add_argument("--port-proxy", type=int, required=True)
    s.add_argument("--port-tunnel", type=int, required=True)
    s.add_argument("--port-http", type=int, required=True)
    s.add_argument("--port-dns", type=int, required=True)
    s.add_argument("--bindings", help="path to a JSON bindings file")
    s.add_argument("--allowlist", help="JSON {domains:[], cidrs:[]}")
    s.add_argument("--upstream", default="http://127.0.0.1:18480")
    s.add_argument("--upstream-deny", default=None,
                   help="JSON list of CIDRs to deny as upstream; default [169.254.169.254/32, 127.0.0.0/8]")
    s.add_argument("--inert", default="INERT", help="inert sentinel value")
    s.add_argument("--agent", help="agent user for setfacl")
    s.add_argument("--iron-proxy", default="iron-proxy")
    s.add_argument("--ready-timeout", type=float, default=10.0)
    s.add_argument("--vault-config", help="Vault Agent HCL to run (renders secret sinks); implies starting vault agent")
    s.add_argument("--vault-addr", default="http://127.0.0.1:8200")
    s.add_argument("--wait", action="store_true",
                   help="stay alive hosting the sink mtime watcher (the launcher runs this in the background)")
    s.add_argument("--watch-interval", type=float, default=15.0,
                   help="seconds between sink mtime polls (default 15)")
    s.set_defaults(func=cmd_start)

    t = sub.add_parser("stop", help="stop + retire a gate")
    t.add_argument("--dir", required=True)
    t.set_defaults(func=cmd_stop)

    v = sub.add_parser("vault-config", help="write a Vault Agent HCL for the gate sinks")
    v.add_argument("--gate-dir", required=True)
    v.add_argument("--vault-addr", default="http://127.0.0.1:8200")
    v.add_argument("--role-id", required=True, help="AppRole role id (or a file to copy from)")
    v.add_argument("--secret-id", required=True, help="AppRole secret id (or a file to copy from)")
    v.add_argument("--sink", action="append", default=[],
                   help="name=vault-path[,sink-file] (repeatable)")
    v.add_argument("--out", help="write the HCL here (default: <gate-dir>/vault-agent.hcl)")
    v.set_defaults(func=cmd_vault_config)

    k = sub.add_parser("check", help="report gate state")
    k.add_argument("--dir", required=True)
    k.set_defaults(func=cmd_check)

    b = sub.add_parser("bindings", help="derive + materialize credential bindings")
    b.add_argument("--gate-dir", required=True, help="0700 gate dir; tok-<name> files land here")
    b.add_argument("--models", help="models.json (default ~/.pi/agent/models.json)")
    b.add_argument("--home", help="operator home (default $HOME)")
    b.add_argument("--claude-creds", help="~/.claude/.credentials.json (default: skip the Claude binding)")
    b.add_argument("--git-token", help="Git PAT file (default: skip the push binding)")
    b.add_argument("--git-host", default="git.example.com")
    b.add_argument("--git-user", default="git")
    b.add_argument("--out", help="write the binding JSON here (default: stdout)")
    b.add_argument("--env-file", help="shell file to source for env vars (e.g. ~/.bashrc)")
    b.set_defaults(func=cmd_bindings)

    args = ap.parse_args(argv)
    rc = args.func(args)
    # --wait: the launcher runs `start --wait` in the background so the process
    # stays alive hosting the sink watcher. In-process callers (tests) pass
    # wait_handler to block without a signal loop; a plain CLI call blocks on
    # SIGTERM/SIGINT via the handler set inside cmd_start.
    if args.cmd == "start" and getattr(args, "wait", False) and rc == 0:
        if wait_handler is not None:
            wait_handler()
        else:
            _block_until_term()
    return rc


def _block_until_term():
    stop = {"stop": False}

    def _term(signum, frame):
        stop["stop"] = True

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    while not stop["stop"]:
        time.sleep(0.5)
        for pid, proc in list(_CHILDREN.items()):
            proc.poll()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
