"""cage.config -- the constrained-TOML loader and Config.

Forcecage's install config (``forcecage.toml``) is a small, deliberately
constrained TOML subset so the cage stays stdlib-only on Python 3.9 (``tomllib``
is 3.11+). The subset covers everything the config needs: tables
(``[t]`` / ``[t.sub]``), basic and literal strings, integers, booleans, one-
dimensional arrays of scalars, and ``#`` comments. Anything outside the subset
raises :class:`ConfigError` naming the line -- fail closed, never a guess.

The value model maps straight onto a :class:`Config` (``from_dict``); a
``forcecage run`` resolves the file via ``find_config`` ($FORCECAGE_CONFIG,
then ./forcecage.toml, then the XDG config dir) and CLI flags override any
field.
"""

import os

# basic-string escapes we understand (basic TOML has more; we fail closed on
# the rest rather than mis-decoding them)
_ESCAPES = {"n": "\n", "t": "\t", "\\": "\\", '"': '"'}


class ConfigError(Exception):
    """A forcecage.toml line is outside the supported subset or malformed."""


# ---------------------------------------------------------------------------
# the constrained-TOML parser
# ---------------------------------------------------------------------------

def parse_toml(text):
    """Parse the constrained TOML subset into a nested dict.

    Top-level keys (no preceding table header) land in the root dict, exactly
    as in real TOML. Tables nest via dotted headers.
    """
    data = {}
    current = data
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith("[["):
            raise ConfigError("line %d: array-of-tables [[...]] is not supported" % lineno)
        if line.startswith("["):
            current = _into_table(data, line, lineno)
            continue
        if "=" not in line:
            raise ConfigError("line %d: expected 'key = value' (got %r)" % (lineno, line))
        key, _, val = line.partition("=")
        key = key.strip()
        if not _valid_key(key):
            raise ConfigError("line %d: invalid key %r" % (lineno, key))
        current[key] = _parse_value(val.strip(), lineno)
    return data


def _into_table(data, line, lineno):
    body = line[1:]
    if not body.endswith("]"):
        raise ConfigError("line %d: table header missing closing bracket: %r" % (lineno, line))
    body = body[:-1].strip()
    cur = data
    for seg in body.split("."):
        seg = seg.strip()
        if not seg or not _valid_key(seg):
            raise ConfigError("line %d: bad table name %r" % (lineno, body))
        if seg in cur:
            if not isinstance(cur[seg], dict):
                raise ConfigError("line %d: %r already set as a non-table value" % (lineno, seg))
            cur = cur[seg]
        else:
            cur[seg] = {}
            cur = cur[seg]
    return cur


def _valid_key(key):
    # bare keys: letters, digits, underscore, hyphen (quoted keys are not in
    # the subset and fail here)
    return bool(key) and all(c.isalnum() or c in "_-" for c in key)


def _strip_comment(line):
    """Return the line up to the first # that is outside any string."""
    out = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == '"':
            out.append(c); i += 1
            while i < n:
                c2 = line[i]
                out.append(c2)
                if c2 == "\\" and i + 1 < n:
                    out.append(line[i + 1]); i += 2
                    continue
                if c2 == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "'":
            out.append(c); i += 1
            while i < n:
                c2 = line[i]
                out.append(c2)
                if c2 == "'":
                    i += 1
                    break
                i += 1
            continue
        if c == "#":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _parse_value(s, lineno):
    if not s:
        raise ConfigError("line %d: empty value" % lineno)
    if s[0] == '"' or s[0] == "'":
        return _parse_string(s, lineno)
    if s[0] == "[":
        return _parse_array(s, lineno)
    if s in ("true", "false"):
        return s == "true"
    if s.lstrip("-").isdigit():
        return int(s)
    raise ConfigError("line %d: unsupported value %r" % (lineno, s))


def _parse_string(s, lineno):
    quote = s[0]
    if len(s) < 2 or s[-1] != quote:
        raise ConfigError("line %d: unterminated string %r" % (lineno, s))
    body = s[1:-1]
    if quote == "'":
        return body
    out = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            e = body[i + 1]
            if e not in _ESCAPES:
                raise ConfigError("line %d: unsupported escape \\%s" % (lineno, e))
            out.append(_ESCAPES[e])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _parse_array(s, lineno):
    if not (s.startswith("[") and s.endswith("]")):
        raise ConfigError("line %d: bad array %r" % (lineno, s))
    inner = s[1:-1].strip()
    if not inner:
        return []
    return [_parse_value(p.strip(), lineno) for p in _split_top_level(inner, ",")]


def _split_top_level(s, sep):
    parts, cur = [], []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            cur.append(c); i += 1
            while i < n:
                c2 = s[i]
                cur.append(c2)
                if c2 == "\\" and i + 1 < n:
                    cur.append(s[i + 1]); i += 2
                    continue
                if c2 == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "'":
            cur.append(c); i += 1
            while i < n:
                c2 = s[i]
                cur.append(c2)
                if c2 == "'":
                    i += 1
                    break
                i += 1
            continue
        if c == sep:
            parts.append("".join(cur)); cur = []
            i += 1
            continue
        cur.append(c); i += 1
    parts.append("".join(cur))
    return [p for p in parts if p.strip()]


# ---------------------------------------------------------------------------
# the Config
# ---------------------------------------------------------------------------

def _expand(p):
    return os.path.expanduser(p) if p else p


class Config:
    """The resolved install settings (config file + defaults; CLI overrides
    happen at the call site, not here)."""

    def __init__(self):
        self.agent_user = "agent"
        self.run_dir = "/run/forcecage"
        self.state_dir = "~/.local/state/forcecage"
        self.iron_proxy = "iron-proxy"
        self.iron_proxy_sha256 = ""
        self.allowlist_domains = []
        self.allowlist_cidrs = ["127.0.0.1/32"]
        self.upstream_deny = ["169.254.169.254/32", "127.0.0.0/8"]
        self.port_mgmt = 0
        self.port_proxy = 0
        self.port_tunnel = 0
        self.port_http = 0
        self.port_dns = 0
        self.ready_timeout = 30.0
        self.grant_catalog = ""
        self.minter_kind = "file"
        self.vault_address = ""
        self.vault_role_id_file = ""
        self.vault_secret_id_file = ""
        self.canaries_file = "~/.local/state/forcecage/tripwire/canaries.json"
        self.exposure_dir = "~/.local/state/forcecage/tripwire/exposure"

    @classmethod
    def from_dict(cls, d):
        d = d or {}
        fc = d.get("forcecage", {}) or {}
        gate = d.get("gate", {}) or {}
        minter = d.get("minter", {}) or {}
        tw = d.get("tripwire", {}) or {}
        cfg = cls()
        cfg.agent_user = fc.get("agent_user", cfg.agent_user)
        cfg.run_dir = _expand(fc.get("run_dir", cfg.run_dir))
        cfg.state_dir = _expand(fc.get("state_dir", cfg.state_dir))
        cfg.iron_proxy = gate.get("iron_proxy", cfg.iron_proxy)
        cfg.iron_proxy_sha256 = gate.get("iron_proxy_sha256", cfg.iron_proxy_sha256)
        cfg.allowlist_domains = list(gate.get("allowlist_domains", cfg.allowlist_domains))
        cfg.allowlist_cidrs = list(gate.get("allowlist_cidrs", cfg.allowlist_cidrs))
        cfg.upstream_deny = list(gate.get("upstream_deny", cfg.upstream_deny))
        for name in ("mgmt", "proxy", "tunnel", "http", "dns"):
            setattr(cfg, "port_" + name, int(gate.get("port_" + name, getattr(cfg, "port_" + name))))
        cfg.ready_timeout = float(gate.get("ready_timeout", cfg.ready_timeout))
        cfg.grant_catalog = _expand(gate.get("grant_catalog", cfg.grant_catalog))
        kind = minter.get("kind", cfg.minter_kind)
        if kind not in ("file", "vault"):
            raise ConfigError("minter.kind must be 'file' or 'vault' (got %r)" % kind)
        cfg.minter_kind = kind
        v = minter.get("vault", {}) or {}
        cfg.vault_address = v.get("address", cfg.vault_address)
        cfg.vault_role_id_file = _expand(v.get("role_id_file", cfg.vault_role_id_file))
        cfg.vault_secret_id_file = _expand(v.get("secret_id_file", cfg.vault_secret_id_file))
        cfg.canaries_file = _expand(tw.get("canaries_file", cfg.canaries_file))
        cfg.exposure_dir = _expand(tw.get("exposure_dir", cfg.exposure_dir))
        return cfg


def load_config(path):
    """Read and parse a forcecage.toml at ``path`` into a Config."""
    with open(path) as f:
        return Config.from_dict(parse_toml(f.read()))


def find_config(cwd=None, env=None):
    """Locate forcecage.toml: $FORCECAGE_CONFIG, then ./forcecage.toml, then the
    XDG config dir. Returns the path or None (the caller applies defaults)."""
    env = os.environ if env is None else env
    cwd = cwd if cwd is not None else os.getcwd()
    explicit = env.get("FORCECAGE_CONFIG")
    if explicit:
        return explicit
    local = os.path.join(cwd, "forcecage.toml")
    if os.path.isfile(local):
        return local
    xdg = env.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    xdg_path = os.path.join(xdg, "forcecage", "forcecage.toml")
    if os.path.isfile(xdg_path):
        return xdg_path
    return None
