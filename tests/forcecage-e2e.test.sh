#!/usr/bin/env bash
# Forcecage end-to-end: the REAL chain, not stubs.
#
# Drives `forcecage run` against a FAKE model upstream, through the real
#   sudo -n -u agent -> agent_pane -> cage.sandbox -> bwrap (--unshare-all)
#   -> in-Sandbox socat forwarder -> ro-bound gate.sock -> host socat
#   -> iron-proxy (per-session Egress gate) -> fake upstream.
#
# Proves:
#   - the agent process runs AS the agent user            (USER=agent)
#   - the agent runs INSIDE bwrap                         (PID 1 = bwrap, /tmp tmpfs)
#   - model egress goes ONLY through the gate             (upstream sees the REAL value,
#                                                          which only the gate can swap in)
#   - the gate swaps the Placeholder for the real value   (upstream log)
#   - the real value appears in NO agent-side output
#
# This is a host-integration test: it needs the `agent` user, bwrap,
# passwordless sudo, socat, curl, openssl, setfacl, python3 and an iron-proxy
# binary. It SKIPS (exit 0) when any prerequisite is absent, so it runs green
# on hosts without the cage host-changes.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
SRC="$REPO_ROOT/src"
FIX="$REPO_ROOT/tests/fixtures/fake-model.py"
PID=$$
FAILED=0

pass() { printf 'ok   - %s\n' "$1"; }
fail() { printf 'FAIL - %s\n' "$1" >&2; FAILED=1; }
skip() { printf 'SKIP - %s\n' "$1"; exit 0; }

id -u agent >/dev/null 2>&1 || skip "no 'agent' user (cage host-change not applied)"
command -v bwrap  >/dev/null 2>&1 || skip "no bwrap"
sudo -n -u agent true 2>/dev/null    || skip "no passwordless sudo to agent"
command -v socat  >/dev/null 2>&1 || skip "no socat"
command -v curl   >/dev/null 2>&1 || skip "no curl"
command -v openssl >/dev/null 2>&1 || skip "no openssl"
command -v setfacl >/dev/null 2>&1 || skip "no setfacl"

# iron-proxy: operator-provided path, then PATH, then a known install location.
IRON="${FORCECAGE_E2E_IRON_PROXY:-}"
[ -n "$IRON" ] || IRON="$(command -v iron-proxy 2>/dev/null || true)"
[ -n "$IRON" ] || for c in \
    "$HOME/.local/state/forcecage/iron-proxy/iron-proxy" \
    /usr/local/bin/iron-proxy; do
  [ -x "$c" ] && { IRON="$c"; break; }
done
[ -n "$IRON" ] && [ -x "$IRON" ] || skip "iron-proxy not found (set FORCECAGE_E2E_IRON_PROXY)"

ROOT="$(mktemp -d /tmp/fc-e2e-XXXXXX)"   # operator scratch (logs, toml, bindings)
AGENT_ROOT="$ROOT/agent"     # agent-owned + world-writable: clone, staged cage, fake agent
STATE="$ROOT/state"          # operator-owned: the gate
OUT="$ROOT/out"
mkdir -p "$OUT" "$STATE"
chmod 755 "$ROOT"   # the operator's 0700 mktemp root would hide everything from the Agent
chmod 755 "$STATE"  # the Agent reaches the 0700 gate dir (ACL'd by the gate) through here
# The Agent cannot traverse the operator's home, so $AGENT_ROOT is agent-owned AND
# world-writable: the operator stages the cage package + fake agent there, the Agent
# creates its clone there. 0777 on a temp dir torn down in cleanup is fine.
sudo -n mkdir -p -m 777 "$AGENT_ROOT"
sudo -n chown agent:agent "$AGENT_ROOT"

UP_PORT=$(( 40000 + RANDOM % 1000 ))
UP_IP=127.0.0.2
REAL_VALUE="FCREALVALUE-${PID}"
PLACEHOLDER="Placeholder-fc-e2e"
BINDINGS="$OUT/bindings.json"
TOKEN_FILE="$OUT/token"

cleanup() {
  [ -n "${FAKE_PID:-}" ] && kill "$FAKE_PID" 2>/dev/null
  if [ -d "$STATE/gate" ]; then
    PYTHONPATH="$SRC" "$PYTHON" -m cage gate stop --dir "$STATE/gate" >/dev/null 2>&1 || true
  fi
  if [ "$FAILED" = 1 ]; then
    echo "e2e: FAILED - preserving artifacts (ROOT=$ROOT)" >&2
  else
    sudo -n rm -rf "$AGENT_ROOT" 2>/dev/null
    rm -rf "$ROOT" 2>/dev/null
  fi
}
trap cleanup EXIT

# the credential binding: the gate swaps Placeholder -> the token file's value.
printf '%s' "$REAL_VALUE" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
printf '[{"host":"%s","secret_file":"%s","placeholder":"%s","match_headers":["Authorization"]}]' \
  "$UP_IP" "$TOKEN_FILE" "$PLACEHOLDER" > "$BINDINGS"

CLONE="$AGENT_ROOT/clone"
PKG_ROOT="$AGENT_ROOT/cage-src"
mkdir -p "$CLONE"
# the clone is the Agent's WORKDIR (the real launcher flow creates it with
# `sudo -n -u agent mkdir`), so it must be Agent-writable: the in-Sandbox agent
# and the agent-side pane both write here (the agent's output, and the
# agent_pane's `<clone>/.forcec-pane/halt` marker). Agent-owned AND world-
# writable so the operator can stage the fake agent into it before the run.
sudo -n chown agent:agent "$CLONE"
sudo -n chmod 777 "$CLONE"
# the fake agent binary lives INSIDE the clone: in the Sandbox /tmp is a fresh
# tmpfs (the operator's paths vanish), and the clone is the one rw bind that
# carries through at the same path. In a real deployment the agent binary sits
# under a bound system dir (/usr), so this is just the e2e's stand-in for that.
# stage an agent-readable copy of the cage package (the Agent cannot read the
# operator's checkout; the hop's PYTHONPATH points here).
mkdir -p "$PKG_ROOT"
cp -R "$SRC/cage" "$PKG_ROOT/cage"
sudo -n chown -R agent:agent "$PKG_ROOT"

FAKE_LOG="$OUT/fake-model.log"
: > "$FAKE_LOG"

echo "=== forcecage e2e (pid $PID, upstream $UP_IP:$UP_PORT) ==="

# fake model upstream
FAKE_MODEL_LOG="$FAKE_LOG" "$PYTHON" "$FIX" "$UP_IP" "$UP_PORT" >"$OUT/fake-model-out.log" 2>&1 &
FAKE_PID=$!
for _ in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/$UP_IP/$UP_PORT") 2>/dev/null; then exec 3>&- 3<&-; break; fi
  sleep 0.2
done
(exec 3<>"/dev/tcp/$UP_IP/$UP_PORT") 2>/dev/null || { fail "fake upstream not ready on $UP_IP:$UP_PORT"; exit 1; }
exec 3>&- 3<&-

# forcecage.toml
TOML="$OUT/forcecage.toml"
printf '{"kinds":[{"id":"fc-e2e","label":"e2e lease kind"}]}' > "$OUT/catalog.json"
chmod 644 "$OUT/catalog.json"
cat > "$TOML" <<TOML
[forcecage]
agent_user = "agent"
state_dir = "$STATE"
[gate]
iron_proxy = "$IRON"
grant_catalog = "$OUT/catalog.json"
allowlist_cidrs = ["127.0.0.0/8"]
upstream_deny = []
TOML

# the fake agent binary (agent-owned, in the clone): records its identity, does
# a model egress through the proxy carrying the Placeholder, records the HTTP
# code, and writes the response body to $HOME (the Sandbox tmpfs home).
cat > "$OUT/fake-pi" <<FAKE
#!/usr/bin/env bash
{
  printf 'USER=%s\n' "\$(id -un)"
  printf 'PROC1=%s\n' "\$(cat /proc/1/comm 2>/dev/null || echo none)"
  printf 'TMP_MNT=%s\n' "\$(awk '\$2=="/tmp"{print \$3}' /proc/mounts 2>/dev/null || echo none)"
  code=\$(curl -s --max-time 20 -o "\$HOME/resp.txt" -w '%{http_code}' \\
    -H 'Authorization: Bearer $PLACEHOLDER' \\
    -X POST http://$UP_IP:$UP_PORT/v1/chat/completions -d '{}')
  printf 'EGRESS_HTTP=%s\n' "\$code"
}
FAKE
sudo -n cp "$OUT/fake-pi" "$CLONE/pi"
sudo -n chown agent:agent "$CLONE/pi"
sudo -n chmod 755 "$CLONE/pi"

pre_swaps=$(grep -c "Bearer $REAL_VALUE" "$FAKE_LOG" 2>/dev/null); pre_swaps=${pre_swaps:-0}
echo "--- run ---"
PYTHONPATH="$SRC" FORCECAGE_CONFIG="$TOML" FORCECAGE_PKG_ROOT="$PKG_ROOT" \
  "$PYTHON" -m cage run --bindings "$BINDINGS" pi "$CLONE" "$CLONE/pi" -- -p hello \
  >"$OUT/agent-stdout.log" 2>"$OUT/agent-stderr.log"
RC=$?
echo "run exit: $RC"
if [ "$RC" != 0 ]; then
  echo "--- agent stdout ---"; cat "$OUT/agent-stdout.log"
  echo "--- agent stderr ---"; cat "$OUT/agent-stderr.log"
  echo "--- gate log ---"; [ -f "$STATE/gate/iron-proxy.log" ] && cat "$STATE/gate/iron-proxy.log"
fi

AGENT_OUT="$OUT/agent-stdout.log"
[ "$RC" = 0 ] || fail "forcecage run exited $RC (want 0)"
grep -q '^USER=agent$' "$AGENT_OUT" || fail "agent process is not running as 'agent'"
grep -q '^PROC1=bwrap$' "$AGENT_OUT" || fail "PID 1 is not bwrap (not in the Sandbox)"
grep -q '^TMP_MNT=tmpfs$' "$AGENT_OUT" || fail "/tmp is not a bwrap tmpfs"

post_swaps=$(grep -c "Bearer $REAL_VALUE" "$FAKE_LOG" 2>/dev/null); post_swaps=${post_swaps:-0}
[ "$post_swaps" -gt "$pre_swaps" ] || fail "upstream saw no new REAL value this run (egress did not go through the gate)"
grep -q '^EGRESS_HTTP=200$' "$AGENT_OUT" || fail "model egress did not return 200 via the gate"

if grep -rF "$REAL_VALUE" "$AGENT_OUT" "$OUT/agent-stderr.log" "$CLONE" 2>/dev/null | grep -qF "$REAL_VALUE"; then
  fail "the REAL value leaked into an agent-side output"
fi
pass "agent runs as agent, in bwrap, egress only via the gate, no real value in agent output"

[ "$FAILED" = 0 ] || exit 1
echo "ALL PASS"
