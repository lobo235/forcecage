"""orc-grant — the per-session Grant service (Slice E).

The host-side companion to the per-session Egress gate. It APPLIES, EXPIRES
and ALERTS; it never asks the operator. The escalation gateway (a fake in
tests) is the only approval channel: it reads the agent's requests and writes
decisions back, both as files in the per-session grant dir. The grant service
turns those into gate changes (credential leases, egress grants) and watches
the gate audit for a Canary or the misdirect sentinel, which are a Halt.

Design (designed twice, see sandbox-cycle): a PURE core
(``step`` / ``GrantCore``) — no clock, no I/O, no randomness, ids from a
deterministic counter — with THIN I/O adapters around it (the ``serve`` loop,
the agent/approver file queue, the gate re-render, Vault, alert). Every event
and effect name is a CONTEXT.md glossary word. Labels, never values, cross any
boundary the agent can read.

Python stdlib only. Importable: tests load this file via importlib and drive
the pure core directly (the orc-gate.test.py style) or run the loop against a
real gate dir with fakes.
"""

import dataclasses
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# catalog: a reviewed Lease kind is frozen data, not logic
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LeaseKind:
    """A reviewed catalog entry for one credential kind.

    An approval binds only to an existing kind. A request no kind matches
    becomes a Prepared change adding one (operator-side); the service only
    reports it (denied, reason ``no-such-kind:<id>``).
    """

    id: str                # machine id, e.g. "git-push"
    label: str             # human label shown to agent/operator
    bound_host: Optional[str]  # the only host the credential is injected for
                              # (None: the agent holds it, e.g. its own login)
    shared: bool           # True = the original behind a Placeholder (KV shared)
    halts_on_leak: bool    # True for the agent's own Codex login (ADR-0044)
    rotatable: bool        # True for minted kinds (a Leak report re-mints it)
    match_headers: tuple   # e.g. ("Authorization",)
    vault: dict            # {"mode": "dynamic"|"shared", "path": ...}


def load_catalog(text):
    """Parse + validate a catalog JSON document -> {id: LeaseKind}.

    Raises ValueError on a malformed / duplicate / empty catalog so a bad
    reviewed artifact fails at boot, not mid-lease.
    """
    doc = json.loads(text)
    kinds = []
    seen = set()
    for entry in doc.get("kinds", []):
        kid = entry["id"]
        if kid in seen:
            raise ValueError("duplicate lease kind id: %s" % kid)
        seen.add(kid)
        kinds.append(LeaseKind(
            id=kid,
            label=entry.get("label", kid),
            bound_host=entry.get("bound_host"),
            shared=bool(entry.get("shared", False)),
            halts_on_leak=bool(entry.get("halts_on_leak", False)),
            rotatable=bool(entry.get("rotatable", True)),
            match_headers=tuple(entry.get("match_headers", ("Authorization",))),
            vault=dict(entry.get("vault", {"mode": "dynamic", "path": None})),
        ))
    if not kinds:
        raise ValueError("catalog has no kinds")
    return {k.id: k for k in kinds}


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------


@dataclass
class PendingRequest:
    request_id: str
    kind: str                    # "lease" | "egress"
    lease_kind: Optional[str]    # lease: the kind id
    destination: Optional[str]   # egress: the destination label
    reason: str


@dataclass
class EgressGrant:
    grant_id: str
    destination: str             # a domain or cidr — a label, the allowlist unit
    expires_at: str
    status: str = "active"


@dataclass
class Lease:
    lease_id: str
    kind: str                    # lease-kind id
    request_id: str              # the original lease request
    reason: str
    placeholder: Optional[str]   # current Placeholder label (never a value)
    secret_name: Optional[str]   # "tok-<lease_id>", stable across rotations
    status: str                 # "pending-mint" | "active" | "rotating"
    expires_at: str
    rotations: int = 0
    leak_request_id: Optional[str] = None  # a Leak report awaiting re-mint


@dataclass
class Canary:
    canary_id: str
    lease_id: str
    placeholder: str            # the retired Placeholder (a label)
    secret_name: str            # "can-<lease_id>"
    expires_at: str             # the source lease's expiry at rotation time


@dataclass
class GrantState:
    session: str
    seq: int = 0
    now: str = "1970-01-01T00:00:00Z"
    pending: dict = field(default_factory=dict)    # request_id -> PendingRequest
    grants: dict = field(default_factory=dict)     # grant_id -> EgressGrant
    leases: dict = field(default_factory=dict)     # lease_id -> Lease
    canaries: dict = field(default_factory=dict)   # canary_id -> Canary
    halted: bool = False
    halt_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# events (each names one source)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LeaseRequested:
    request_id: str
    lease_kind: str
    reason: str
    now: str


@dataclass(frozen=True)
class EgressRequested:
    request_id: str
    destination: str
    reason: str
    now: str


@dataclass(frozen=True)
class LeakReported:
    request_id: str
    label: str                  # a Placeholder label OR a kind label (codex-login)
    now: str
    note: str = ""


@dataclass(frozen=True)
class LeaseApproved:
    request_id: str
    lease_kind: str
    expires_at: str
    reason: str = ""


@dataclass(frozen=True)
class LeaseDenied:
    request_id: str
    reason: str = ""


@dataclass(frozen=True)
class EgressApproved:
    request_id: str
    destination: str
    expires_at: str


@dataclass(frozen=True)
class EgressDenied:
    request_id: str
    reason: str = ""


@dataclass(frozen=True)
class LeaseIssued:
    lease_id: str
    placeholder: str            # loop-generated label, never a value
    secret_name: str


@dataclass(frozen=True)
class LeaseIssueFailed:
    lease_id: str
    label: str


@dataclass(frozen=True)
class LeaseRevoked:
    lease_id: str


@dataclass(frozen=True)
class LeaseRevokeFailed:
    lease_id: str
    label: str


@dataclass(frozen=True)
class AuditEntry:
    file_role: str              # "lease" | "canary" | "inert"
    file_id: Optional[str]      # lease_id or canary_id (None for inert)
    host: str
    ts: str


@dataclass(frozen=True)
class ExpiryDue:
    item_id: str                # "L<n>" | "G<n>" | "C<n>"
    now: str


@dataclass(frozen=True)
class SessionEnded:
    now: str


# ---------------------------------------------------------------------------
# effects (every effect routes to exactly one owner)
# ---------------------------------------------------------------------------


@dataclass
class MintLease:
    lease_id: str
    kind: str
    secret_name: str
    expires_at: str


@dataclass
class RotateLease:
    lease_id: str
    kind: str
    secret_name: str            # "tok-<lease_id>" (overwritten with the new value)
    canary_secret_name: str     # "can-<lease_id>" (the Canary marker)
    expires_at: str


@dataclass
class RevokeLease:
    lease_id: str
    secret_name: str
    shared: bool
    kind: str


@dataclass
class GateConfigChanged:
    reason: str


@dataclass
class ScheduleExpiry:
    item_id: str
    at: str


@dataclass
class CancelExpiry:
    item_id: str


@dataclass
class RaiseHaltAlert:
    kind: str                   # "canary" | "misdirect" | "codex-login-leak"
    placeholder: Optional[str]
    host: str


@dataclass
class NotifyAlert:
    kind: str
    label: str


@dataclass
class SignalPaneHalt:
    reason: str


@dataclass
class ReplyToAgent:
    request_id: str
    status: str                 # "pending"|"granted"|"denied"|"rotated"|"halt"|"rejected"
    placeholder: Optional[str] = None
    reason: Optional[str] = None
    expiry: Optional[str] = None
    existing_id: Optional[str] = None


@dataclass
class PublishPlaceholders:
    pass


# ---------------------------------------------------------------------------
# the pure transition function
# ---------------------------------------------------------------------------


def _alloc(state, prefix):
    state.seq += 1
    return "%s%d" % (prefix, state.seq)


def _replies_for_pendings(state, status):
    """On a Halt, close every open request so the agent's polls terminate."""
    return [ReplyToAgent(rid, status) for rid in list(state.pending)]


def step(state, event, catalog):
    """The single entry point. Deterministic: same (state, event) always
    yields the same effects. Mutates and returns ``state``; returns
    ``(state, effects)``. ``now`` is carried by the event (the adapter's
    clock), never read here.
    """
    state.now = getattr(event, "now", state.now) or state.now
    fx = []

    if isinstance(event, LeaseRequested):
        kind = catalog.get(event.lease_kind)
        if kind is None:
            fx.append(ReplyToAgent(event.request_id, "denied",
                                   reason="no-such-kind:%s" % event.lease_kind))
            fx.append(NotifyAlert("unknown-kind", event.lease_kind))
            return state, fx
        # one live lease per kind
        for lease in state.leases.values():
            if lease.kind == event.lease_kind and lease.status in ("active", "rotating"):
                fx.append(ReplyToAgent(event.request_id, "denied",
                                       reason="already-active:%s" % lease.lease_id))
                return state, fx
        # dedup: a pending request for the same kind re-points to it
        for req in state.pending.values():
            if req.kind == "lease" and req.lease_kind == event.lease_kind:
                fx.append(ReplyToAgent(event.request_id, "pending",
                                       existing_id=req.request_id))
                return state, fx
        state.pending[event.request_id] = PendingRequest(
            event.request_id, "lease", event.lease_kind, None, event.reason)
        fx.append(ReplyToAgent(event.request_id, "pending"))
        return state, fx

    if isinstance(event, EgressRequested):
        for req in state.pending.values():
            if req.kind == "egress" and req.destination == event.destination:
                fx.append(ReplyToAgent(event.request_id, "pending",
                                       existing_id=req.request_id))
                return state, fx
        state.pending[event.request_id] = PendingRequest(
            event.request_id, "egress", None, event.destination, event.reason)
        fx.append(ReplyToAgent(event.request_id, "pending"))
        return state, fx

    if isinstance(event, LeaseApproved):
        req = state.pending.pop(event.request_id, None)
        if req is None or req.kind != "lease":
            # an approval without a matching pending request is accepted
            # (operator-initiated) if it names a known kind
            if event.lease_kind not in catalog:
                fx.append(NotifyAlert("approval-no-kind", event.lease_kind))
                return state, fx
        kind = catalog[event.lease_kind]
        lease_id = _alloc(state, "L")
        secret_name = "tok-" + lease_id
        state.leases[lease_id] = Lease(
            lease_id=lease_id, kind=event.lease_kind,
            request_id=event.request_id, reason=event.reason or (req.reason if req else ""),
            placeholder=None, secret_name=secret_name, status="pending-mint",
            expires_at=event.expires_at)
        fx.append(MintLease(lease_id, event.lease_kind, secret_name, event.expires_at))
        return state, fx

    if isinstance(event, LeaseDenied):
        if state.pending.pop(event.request_id, None) is not None:
            fx.append(ReplyToAgent(event.request_id, "denied", reason=event.reason or "denied"))
        return state, fx

    if isinstance(event, EgressApproved):
        req = state.pending.pop(event.request_id, None)
        grant_id = _alloc(state, "G")
        state.grants[grant_id] = EgressGrant(
            grant_id=grant_id, destination=event.destination,
            expires_at=event.expires_at)
        fx.append(GateConfigChanged("grant"))
        fx.append(ScheduleExpiry(grant_id, event.expires_at))
        fx.append(ReplyToAgent(event.request_id, "granted", expiry=event.expires_at))
        return state, fx

    if isinstance(event, EgressDenied):
        if state.pending.pop(event.request_id, None) is not None:
            fx.append(ReplyToAgent(event.request_id, "denied", reason=event.reason or "denied"))
        return state, fx

    if isinstance(event, LeaseIssued):
        lease = state.leases.get(event.lease_id)
        if lease is None:
            return state, fx
        was_rotating = lease.status == "rotating"
        lease.status = "active"
        lease.placeholder = event.placeholder
        lease.secret_name = event.secret_name
        if was_rotating:
            lease.rotations += 1
            # expires_at is unchanged (ADR: re-mint the SAME access and expiry)
        if was_rotating:
            reply_id = lease.leak_request_id or lease.request_id
            lease.leak_request_id = None
            fx.append(ReplyToAgent(reply_id, "rotated", placeholder=event.placeholder))
        else:
            fx.append(ReplyToAgent(lease.request_id, "granted",
                                   placeholder=event.placeholder))
        fx.append(PublishPlaceholders())
        fx.append(GateConfigChanged("lease-active" if not was_rotating else "rotation-done"))
        fx.append(ScheduleExpiry(lease.lease_id, lease.expires_at))
        return state, fx

    if isinstance(event, LeaseIssueFailed):
        lease = state.leases.pop(event.lease_id, None)
        if lease is not None:
            fx.append(ReplyToAgent(lease.request_id, "denied", reason=event.label))
            fx.append(NotifyAlert("issue-failed", event.label))
        return state, fx

    if isinstance(event, LeakReported):
        if state.halted:
            fx.append(ReplyToAgent(event.request_id, "halt"))
            return state, fx
        label = event.label
        # (a) a live lease's Placeholder
        for lease in state.leases.values():
            if lease.placeholder == label and lease.status in ("active", "rotating"):
                kind = catalog[lease.kind]
                if kind.halts_on_leak:
                    # the agent's own Codex login: no rotation, a Halt
                    state.halted = True
                    state.halt_reason = "codex-login-leak"
                    fx.append(RaiseHaltAlert("codex-login-leak", label, "-"))
                    fx.append(SignalPaneHalt("codex-login-leak"))
                    fx.append(ReplyToAgent(event.request_id, "halt"))
                    fx.extend(_replies_for_pendings(state, "halt"))
                    return state, fx
                if kind.rotatable:
                    lease.status = "rotating"
                    lease.leak_request_id = event.request_id
                    canary_id = _alloc(state, "C")
                    state.canaries[canary_id] = Canary(
                        canary_id=canary_id, lease_id=lease.lease_id,
                        placeholder=label, secret_name="can-" + lease.lease_id,
                        expires_at=lease.expires_at)
                    fx.append(RotateLease(lease.lease_id, lease.kind,
                                          "tok-" + lease.lease_id,
                                          "can-" + lease.lease_id,
                                          lease.expires_at))
                    fx.append(ScheduleExpiry(canary_id, lease.expires_at))
                    fx.append(PublishPlaceholders())
                    fx.append(GateConfigChanged("rotation-start"))
                    fx.append(ReplyToAgent(event.request_id, "pending"))
                    return state, fx
                # a shared, non-rotatable, non-halt kind: no rotation, notify
                fx.append(ReplyToAgent(event.request_id, "rejected",
                                       reason="no-rotation"))
                fx.append(NotifyAlert("leak-no-rotation", label))
                return state, fx
        # (b) a canary Placeholder: the agent admits the Canary left -> Halt
        for canary in state.canaries.values():
            if canary.placeholder == label:
                state.halted = True
                state.halt_reason = "canary"
                fx.append(RaiseHaltAlert("canary", label, "-"))
                fx.append(SignalPaneHalt("canary"))
                fx.append(ReplyToAgent(event.request_id, "halt"))
                fx.extend(_replies_for_pendings(state, "halt"))
                return state, fx
        # (c) a kind label (the agent's own login, no Placeholder)
        kind = catalog.get(label)
        if kind is not None and kind.halts_on_leak:
            state.halted = True
            state.halt_reason = "codex-login-leak"
            fx.append(RaiseHaltAlert("codex-login-leak", label, "-"))
            fx.append(SignalPaneHalt("codex-login-leak"))
            fx.append(ReplyToAgent(event.request_id, "halt"))
            fx.extend(_replies_for_pendings(state, "halt"))
            return state, fx
        # unknown label
        fx.append(ReplyToAgent(event.request_id, "rejected", reason="unknown-label"))
        fx.append(NotifyAlert("unknown-label", label))
        return state, fx

    if isinstance(event, LeaseRevoked):
        state.leases.pop(event.lease_id, None)
        fx.append(GateConfigChanged("lease-revoked"))
        return state, fx

    if isinstance(event, LeaseRevokeFailed):
        fx.append(NotifyAlert("revoke-failed", event.label))
        return state, fx

    if isinstance(event, AuditEntry):
        if state.halted:
            return state, fx
        if event.file_role == "canary":
            canary = state.canaries.get(event.file_id)
            placeholder = canary.placeholder if canary else None
            state.halted = True
            state.halt_reason = "canary"
            fx.append(RaiseHaltAlert("canary", placeholder, event.host))
            fx.append(SignalPaneHalt("canary"))
            fx.extend(_replies_for_pendings(state, "halt"))
            return state, fx
        if event.file_role == "inert":
            state.halted = True
            state.halt_reason = "misdirect"
            fx.append(RaiseHaltAlert("misdirect", None, event.host))
            fx.append(SignalPaneHalt("misdirect"))
            fx.extend(_replies_for_pendings(state, "halt"))
            return state, fx
        # a live lease's real value on its host: normal traffic
        return state, fx

    if isinstance(event, ExpiryDue):
        prefix = event.item_id[0]
        if prefix == "G":
            if event.item_id in state.grants:
                del state.grants[event.item_id]
                fx.append(GateConfigChanged("grant-expired"))
        elif prefix == "L":
            lease = state.leases.get(event.item_id)
            if lease is not None:
                kind = catalog[lease.kind]
                fx.append(RevokeLease(lease.lease_id,
                                      lease.secret_name or ("tok-" + lease.lease_id),
                                      kind.shared, lease.kind))
        elif prefix == "C":
            if event.item_id in state.canaries:
                del state.canaries[event.item_id]
                fx.append(GateConfigChanged("canary-expired"))
                fx.append(PublishPlaceholders())
        return state, fx

    if isinstance(event, SessionEnded):
        for lease in list(state.leases.values()):
            if lease.status in ("active", "rotating", "pending-mint"):
                kind = catalog[lease.kind]
                fx.append(RevokeLease(lease.lease_id,
                                      lease.secret_name or ("tok-" + lease.lease_id),
                                      kind.shared, lease.kind))
        state.leases.clear()
        state.canaries.clear()
        state.grants.clear()
        state.pending.clear()
        fx.append(GateConfigChanged("session-ended"))
        fx.append(PublishPlaceholders())
        return state, fx

    return state, fx


# ---------------------------------------------------------------------------
# the wrapper: keeps step's purity, exposes the gate view
# ---------------------------------------------------------------------------


class GrantCore:
    """A thin wrapper over ``step``. The loop feeds events, reads effects, and
    calls ``view`` to rebuild the gate config. ``view`` and ``file_roles`` are
    labels only.
    """

    def __init__(self, catalog, session, base_allowlist):
        self.catalog = catalog
        self.base_allowlist = dict(base_allowlist)
        self.state = GrantState(session=session)

    def step(self, event):
        _, effects = step(self.state, event, self.catalog)
        return effects

    def view(self):
        """The gate's desired world: bindings (secret_name form) + allowlist.

        Base bindings/allowlist are the session floor; active leases add a real
        binding on their bound host, canaries add a host-* binding to the
        Canary marker, active egress grants add their destination. The loop
        resolves ``secret_name`` -> a path in the gate dir before rendering.
        """
        bindings = []
        for lease in self.state.leases.values():
            if lease.status == "active" and lease.placeholder:
                kind = self.catalog[lease.kind]
                bindings.append({
                    "host": kind.bound_host,
                    "placeholder": lease.placeholder,
                    "match_headers": list(kind.match_headers),
                    "secret_name": "tok-" + lease.lease_id,
                })
        for canary in self.state.canaries.values():
            lease = self.state.leases.get(canary.lease_id)
            kind = self.catalog.get(lease.kind if lease else canary.lease_id) \
                or self._kind_for_canary(canary)
            bindings.append({
                "host": "*",
                "placeholder": canary.placeholder,
                "match_headers": list(kind.match_headers),
                "secret_name": canary.secret_name,
            })
        domains = set(self.base_allowlist.get("domains", []))
        cidrs = set(self.base_allowlist.get("cidrs", []))
        for grant in self.state.grants.values():
            if "/" in grant.destination:
                cidrs.add(grant.destination)
            else:
                domains.add(grant.destination)
        return {
            "bindings": bindings,
            "allowlist": {"domains": sorted(domains), "cidrs": sorted(cidrs)},
        }

    def _kind_for_canary(self, canary):
        # a canary outlives its lease record on expiry; fall back to the
        # match_headers recorded when the canary was created (default below)
        return LeaseKind(id="canary", label="canary", bound_host=None,
                         shared=False, halts_on_leak=False, rotatable=False,
                         match_headers=("Authorization",), vault={})

    def file_roles(self):
        """secret_name -> (role, item_id) so the loop maps an audit line's
        swapped file to a verdict. The inert path is the loop's (base config).
        """
        roles = {}
        for lease in self.state.leases.values():
            roles["tok-" + lease.lease_id] = ("lease", lease.lease_id)
        for canary in self.state.canaries.values():
            roles[canary.secret_name] = ("canary", canary.canary_id)
        return roles


# ---------------------------------------------------------------------------
# placeholder label generation (loop-side; the core stays deterministic)
# ---------------------------------------------------------------------------


def make_placeholder(kind_id):
    return "Placeholder-%s-%s" % (kind_id, uuid.uuid4().hex[:8])


def canary_marker(lease_id):
    return "Canary-%s" % lease_id


# ---------------------------------------------------------------------------
# the Vault backend (Slice F): the real minter/revolver the serve loop uses
# ---------------------------------------------------------------------------


class VaultMinter:
    """The real Vault backend for the grant service (Slice F).

    One AppRole login is cached in a token file (0600, in the grant dir);
    when less than 10% of the token's TTL remains (60 s floor) the minter
    re-logs in. A dynamic kind mints a single KV v2 entry at the kind's path
    (the KV mount here has no per-entry TTL; the loop's ExpiryDue timer and
    the leak rotation retire the lease and delete the entry). A shared kind
    reads its KV value and
    is never revoked.

    The vault CLI is invoked with an isolated HOME so the minter never reads
    a login from the surrounding environment's ~/.vault-token.
    """

    def __init__(self, addr, role_id_file, secret_id_file, token_dir,
                 run_cli=None, now=None):
        self.addr = addr
        self.role_id_file = role_id_file
        self.secret_id_file = secret_id_file
        self.token_dir = token_dir
        self.token_file = os.path.join(token_dir, "vault-token.json")
        self._run_cli = run_cli  # injectable: (args, token) -> (rc, out, err)
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
            raise RuntimeError("vault login failed: %s" % (err or out).strip())
        lines = [l for l in out.splitlines() if l.strip()]
        token = lines[-1] if lines else ""
        if not token:
            raise RuntimeError("vault login returned no token")
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
            if age < max(60.0, float(rec.get("ttl") or 0) * 0.9):
                return token
        self._login()
        with open(self.token_file, encoding="utf-8") as fh:
            return json.load(fh)["token"]

    # -- the interface the loop uses -----------------------------------------

    def issue(self, kind, lease_id, expires_at):
        if kind.vault.get("mode") == "shared":
            return self.read_shared(kind)
        value = "grant-%s-%s" % (lease_id, uuid.uuid4().hex)
        # The KV mount here (Vault 2.1.2) has no per-entry TTL; the loop's
        # ExpiryDue timer and the leak rotation retire the lease and delete
        # the entry. Vault holds the value until we tell it to forget.
        rc, out, err = self._vault(["kv", "put", kind.vault["path"],
                                    "value=" + value], self._auth())
        if rc != 0:
            raise RuntimeError("vault kv put %s: %s"
                               % (kind.vault["path"], (err or out).strip()))
        return value

    def read_shared(self, kind):
        rc, out, err = self._vault(["kv", "get", "-field=value", kind.vault["path"]],
                                   self._auth())
        if rc != 0:
            raise RuntimeError("vault kv get %s: %s"
                               % (kind.vault["path"], (err or out).strip()))
        lines = [l for l in out.splitlines() if l.strip()]
        return lines[-1] if lines else ""

    def revoke(self, kind, lease_id):
        if kind.vault.get("mode") == "shared":
            return
        rc, out, err = self._vault(["kv", "metadata", "delete", kind.vault["path"]],
                                   self._auth())
        if rc != 0:
            raise RuntimeError("vault kv delete %s: %s"
                               % (kind.vault["path"], (err or out).strip()))


# ---------------------------------------------------------------------------
# the loop: thin I/O adapter around the pure core
# ---------------------------------------------------------------------------

import heapq
import os as _os
from datetime import datetime, timezone


def _parse_ts(s):
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)


class GrantLoop:
    """The single-writer loop. Each ``tick`` claims new files from the agent and
    approver queues, tails the gate audit, fires due expiries, feeds the pure
    core, and dispatches the resulting effects (pipelines run inline; every
    ``GateConfigChanged`` re-renders gate.yaml + reloads immediately so the
    ordering is correct). The core is the only writer of grant state; the loop
    is the only writer of files.
    """

    def __init__(self, gate_dir, catalog, vault=None, alert=None, mgmt=None,
                 clock=None, tick_interval=0.5, halt_file=None, agent_pid=None,
                 grant_dir=None):
        self.gate_dir = gate_dir
        self.grant_dir = grant_dir or os.path.join(gate_dir, "grant")
        self.vault = vault
        self.alert = alert
        self.mgmt = mgmt
        self.clock = clock or (lambda: datetime.now(timezone.utc).isoformat())
        self.tick_interval = tick_interval
        # Two halt outputs: a diagnostic record always written into the grant
        # dir (tests + post-mortem), and the tripwire halt marker the pane
        # reads to exit 3 (written only when a path is supplied).
        self.halt_record = os.path.join(self.grant_dir, "halt.json")
        self.halt_marker = halt_file
        self.agent_pid = agent_pid
        self.stop = False

        # gate state + base config (the session floor the service layers on)
        with open(os.path.join(gate_dir, "state.json"), encoding="utf-8") as fh:
            self.gate_state = json.load(fh)
        with open(os.path.join(gate_dir, "base-config.json"), encoding="utf-8") as fh:
            self.base = json.load(fh)
        self.core = G = GrantCore(catalog, self.gate_state.get("session", ""),
                                  self.base.get("allowlist", {"domains": [], "cidrs": []}))
        self.gate_yaml = self.gate_state.get("gate_yaml") or os.path.join(gate_dir, "gate.yaml")
        self.inert_path = self.base.get("inert_path", os.path.join(gate_dir, "inert"))
        self.mgmt_host = "127.0.0.1"
        self.mgmt_port = self.gate_state.get("listen", {}).get("management")
        self.mgmt_token = self.gate_state.get("mgmt_token")
        # The gate's uid (recorded by orc-gate). The Grant service runs as the
        # Agent user and owns the gate files it writes as 0600, so the gate
        # (a different user) can't read them without an ACL. Fall back to the
        # gate dir's owner (the pane body creates the dir as the gate user) for
        # a state.json written before gate_uid was recorded.
        self.gate_uid = self.gate_state.get("gate_uid") or os.stat(gate_dir).st_uid

        self._audit_offset = 0
        self._timers = []  # heap of (parsed_at, seq, item_id)
        self._timer_seq = 0
        self._halted_signaled = False

        # ensure the file-queue layout exists
        for sub, mode in (("in-agent", 0o770), ("in-host", 0o700), ("out", 0o775)):
            p = os.path.join(self.grant_dir, sub)
            os.makedirs(p, mode=mode, exist_ok=True)
            os.chmod(p, mode)
        os.chmod(self.grant_dir, 0o700)

    # -- queue claim/retire ---------------------------------------------------

    def _claim(self, subdir, name):
        """Atomically claim an inbound file (rename); return its new path or
        None if another writer won the race."""
        src = os.path.join(self.grant_dir, subdir, name)
        dst = os.path.join(self.grant_dir, subdir, ".%s.processing" % name)
        try:
            os.rename(src, dst)
            return dst
        except FileNotFoundError:
            return None

    def _retire(self, path, bucket):
        d = os.path.join(self.grant_dir, bucket)
        os.makedirs(d, mode=0o700, exist_ok=True)
        try:
            os.rename(path, os.path.join(d, os.path.basename(path)))
        except OSError:
            pass

    def _collect_inbound(self, subdir, builder):
        """Claim + parse every fresh file in subdir; return core events."""
        events = []
        d = os.path.join(self.grant_dir, subdir)
        for name in sorted(os.listdir(d)):
            if name.startswith(".") or not name.endswith(".json"):
                continue
            claimed = self._claim(subdir, name)
            if claimed is None:
                continue
            try:
                with open(claimed, encoding="utf-8") as fh:
                    doc = json.load(fh)
                event = builder(doc)
                if event is not None:
                    events.append(event)
                self._retire(claimed, ".done-%s" % subdir)
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                self._retire(claimed, ".bad-%s" % subdir)
                if self.alert:
                    self.alert.notify("bad-%s" % subdir, str(e))
        return events

    def _agent_event(self, doc):
        t = doc.get("type")
        now = self.clock()
        if t == "lease":
            return LeaseRequested(doc["id"], doc["kind"],
                                    doc.get("reason", ""), now)
        if t == "egress":
            return EgressRequested(doc["id"], doc["destination"],
                                     doc.get("reason", ""), now)
        if t == "leak":
            return LeakReported(doc["id"], doc["label"], now,
                                  doc.get("note", ""))
        return None

    def _approver_event(self, doc):
        t = doc.get("type")
        now = self.clock()
        if t == "decision":
            req = doc.get("request")
            if doc.get("verdict") == "approve":
                if doc.get("kind"):
                    return LeaseApproved(req, doc["kind"], doc["expiry"],
                                           doc.get("reason", ""))
                return EgressApproved(req, doc["destination"], doc["expiry"])
            return LeaseDenied(req, doc.get("reason", "")) if doc.get("kind") is not None \
                else EgressDenied(req, doc.get("reason", ""))
        if t == "grant":
            # operator-initiated egress grant (no agent request)
            return EgressApproved("grant-" + doc["destination"], doc["destination"],
                                    doc["expiry"])
        return None

    # -- audit tail -----------------------------------------------------------

    def _collect_audit(self):
        events = []
        log = os.path.join(self.gate_dir, "iron-proxy.log")
        if not os.path.exists(log):
            return events
        size = os.path.getsize(log)
        if size < self._audit_offset:
            self._audit_offset = 0  # log rotated/truncated
        with open(log, "rb") as fh:
            if self._audit_offset:
                fh.seek(self._audit_offset)
            data = fh.read()
            self._audit_offset = fh.tell()
        roles = self.core.file_roles()
        for line in data.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            if o.get("msg") != "request":
                continue
            for t in o.get("request_transforms", []):
                swapped = t.get("annotations", {}).get("swapped", [])
                for sw in swapped:
                    # The audit names the secret ENTRY used (a path), never its value.
                    entry = sw.get("secret", "")
                    if entry == self.inert_path or entry.endswith("/inert"):
                        events.append(AuditEntry("inert", None,
                                                    o.get("audit", {}).get("host", ""),
                                                    o.get("time", self.clock())))
                    else:
                        role = roles.get(os.path.basename(entry))
                        if role:
                            events.append(AuditEntry(role[0], role[1],
                                                        o.get("audit", {}).get("host", ""),
                                                        o.get("time", self.clock())))
        return events

    def _collect_timers(self):
        events = []
        now = _parse_ts(self.clock())
        while self._timers and self._timers[0][0] <= now:
            _, _, item_id = heapq.heappop(self._timers)
            events.append(ExpiryDue(item_id, self.clock()))
        return events

    # -- effect dispatch ------------------------------------------------------

    def _process_event(self, event):
        queue = [event]
        while queue:
            ev = queue.pop(0)
            for fx in self.core.step(ev):
                if isinstance(fx, (MintLease, RotateLease, RevokeLease)):
                    result = self._run_pipeline(fx)
                    if result is not None:
                        queue.append(result)
                else:
                    self._dispatch(fx)

    def _dispatch(self, fx):
        if isinstance(fx, GateConfigChanged):
            self._render_gate()
        elif isinstance(fx, ScheduleExpiry):
            self._timer_seq += 1
            heapq.heappush(self._timers, (_parse_ts(fx.at), self._timer_seq, fx.item_id))
        elif isinstance(fx, CancelExpiry):
            self._timers = [t for t in self._timers if t[2] != fx.item_id]
            heapq.heapify(self._timers)
        elif isinstance(fx, RaiseHaltAlert):
            if self.alert:
                self.alert.halt(fx)
        elif isinstance(fx, NotifyAlert):
            if self.alert:
                self.alert.notify(fx.kind, fx.label)
        elif isinstance(fx, SignalPaneHalt):
            self._signal_halt(fx.reason)
        elif isinstance(fx, ReplyToAgent):
            self._reply(fx)
        elif isinstance(fx, PublishPlaceholders):
            self._publish_placeholders()

    def _signal_halt(self, reason):
        doc = {"reason": reason, "ts": self.clock()}
        tmp = self.halt_record + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        os.replace(tmp, self.halt_record)
        os.chmod(self.halt_record, 0o600)
        if self.halt_marker:
            with open(self.halt_marker, "w", encoding="utf-8") as fh:
                fh.write(reason + "\n")
        # Stop the agent. The pane runs it in its own process group, so kill the
        # whole tree (the bwrap wrapper and the agent beneath it); fall back to
        # a plain kill if the pid is not a group leader.
        if self.agent_pid:
            try:
                os.killpg(self.agent_pid, 15)
            except (OSError, AttributeError):
                try:
                    os.kill(self.agent_pid, 15)
                except OSError:
                    pass

    def _reply(self, fx):
        doc = {"id": fx.request_id, "status": fx.status}
        if fx.placeholder:
            doc["placeholder"] = fx.placeholder
        if fx.reason:
            doc["reason"] = fx.reason
        if fx.expiry:
            doc["expiry"] = fx.expiry
        if fx.existing_id:
            doc["request"] = fx.existing_id
        path = _reply_path(self.gate_dir, fx.request_id)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        os.replace(tmp, path)
        os.chmod(path, 0o644)

    def _publish_placeholders(self):
        # In-place write (same inode, no tmp+rename): the Sandbox bwrap file
        # bind holds one inode, so a rename would leave the Sandbox looking at
        # the previous file forever. A torn read only costs one extra poll
        # (the readers retry).
        live = [l.placeholder for l in self.core.state.leases.values()
                if l.placeholder and l.status == "active"]
        canaries = [c.placeholder for c in self.core.state.canaries.values()]
        path = os.path.join(self.grant_dir, "placeholders.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"live": live, "canaries": canaries}, fh)
        os.chmod(path, 0o644)

    # -- gate re-render -------------------------------------------------------

    def _grant_gate_read(self, path):
        """Grant the gate (a different user: the operator this cycle, a dedicated
        gate uid in production) read on a file the Grant service just wrote.

        The service runs as the Agent user and creates these files as 0600, so
        the gate — which re-reads gate.yaml on every reload and the minted secret
        values on every swap — cannot open them ("permission denied", reload
        rejected; the lease/canary binding never takes effect). An additive ACL
        for the gate uid is the same mechanism _grant_agent uses for the agent's
        own access, and it raises the mask so the entry is effective under the
        0600 owner mode. Best-effort: a failure means the next reload is
        rejected, which is itself visible; log it rather than kill the loop."""
        try:
            subprocess.run(
                ["setfacl", "-m", "u:%d:r" % self.gate_uid, path],
                check=True, capture_output=True, text=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            detail = (getattr(exc, "stderr", "") or str(exc)).strip()
            print("orc-grant: could not grant the gate (uid %d) read on %s: %s"
                  % (self.gate_uid, path, detail), file=sys.stderr)

    def _render_gate(self):
        view = self.core.view()
        base = dict(self.base)
        bindings = list(base.get("bindings", []))
        for b in view["bindings"]:
            bindings.append({
                "host": b["host"],
                "placeholder": b["placeholder"],
                "match_headers": list(b["match_headers"]),
                "secret_file": os.path.join(self.gate_dir, b["secret_name"]),
            })
        base["bindings"] = bindings
        base["allowlist"] = view["allowlist"]
        cfg = _GATE.build_config(base)
        text = _GATE.render_yaml(cfg)
        tmp = self.gate_yaml + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, self.gate_yaml)
        os.chmod(self.gate_yaml, 0o600)
        self._grant_gate_read(self.gate_yaml)
        self._reload()

    def _reload(self):
        if self.mgmt is not None:
            self.mgmt.reload()
        elif self.mgmt_port and self.mgmt_token:
            _GATE._post_reload(self.mgmt_host, self.mgmt_port, self.mgmt_token)

    def _write_secret(self, name, value):
        path = os.path.join(self.gate_dir, name)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(value)  # no trailing newline (the iron-proxy gotcha)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        self._grant_gate_read(path)

    def _remove_secret(self, name):
        path = os.path.join(self.gate_dir, name)
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    # -- pipelines ------------------------------------------------------------

    def _run_pipeline(self, fx):
        try:
            if isinstance(fx, MintLease):
                return self._mint(fx)
            if isinstance(fx, RotateLease):
                return self._rotate(fx)
            if isinstance(fx, RevokeLease):
                return self._revoke(fx)
        except Exception as e:  # a failed pipeline is a result event, not a crash
            label = "%s: %s" % (type(fx).__name__, e)
            if isinstance(fx, RevokeLease):
                return LeaseRevokeFailed(fx.lease_id, label)
            return LeaseIssueFailed(fx.lease_id, label)
        return None

    def _issue_value(self, kind, expires_at, lease_id):
        if kind.vault.get("mode") == "dynamic":
            return self.vault.issue(kind, lease_id, expires_at)
        return self.vault.read_shared(kind)

    def _mint(self, fx):
        kind = self.core.catalog[fx.kind]
        value = self._issue_value(kind, fx.expires_at, fx.lease_id)
        self._write_secret(fx.secret_name, value)
        return LeaseIssued(fx.lease_id, make_placeholder(fx.kind), fx.secret_name)

    def _rotate(self, fx):
        kind = self.core.catalog[fx.kind]
        if not kind.shared:
            self.vault.revoke(kind, fx.lease_id)
        self._write_secret(fx.canary_secret_name, canary_marker(fx.lease_id))
        value = self._issue_value(kind, fx.expires_at, fx.lease_id)  # SAME access + expiry
        self._write_secret(fx.secret_name, value)
        return LeaseIssued(fx.lease_id, make_placeholder(fx.kind), fx.secret_name)

    def _revoke(self, fx):
        kind = self.core.catalog[fx.kind]
        if not fx.shared:
            self.vault.revoke(kind, fx.lease_id)
        self._remove_secret(fx.secret_name)
        return LeaseRevoked(fx.lease_id)

    # -- state + tick ---------------------------------------------------------

    def _persist_state(self):
        import dataclasses as _dc
        doc = _dc.asdict(self.core.state)
        path = os.path.join(self.grant_dir, "state.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, default=str)
        os.replace(tmp, path)
        os.chmod(path, 0o600)

    def tick(self):
        if self.stop:
            return
        events = []
        events += self._collect_inbound("in-agent", self._agent_event)
        events += self._collect_inbound("in-host", self._approver_event)
        events += self._collect_audit()
        events += self._collect_timers()
        for event in events:
            self._process_event(event)
        self._persist_state()

    def run(self):
        self.tick()  # apply anything already queued
        while not self.stop:
            time.sleep(self.tick_interval)
            self.tick()

    def request_stop(self):
        self.stop = True

    def session_ended(self):
        self._process_event(SessionEnded(self.clock()))
        self._persist_state()


# import the gate module lazily (same repo, same loader the tests use)
_GATE = None

def _gate_module():
    global _GATE
    if _GATE is None:
        here = _os.path.dirname(_os.path.abspath(__file__))
        path = _os.path.join(here, "gate.py")
        loader = _im.SourceFileLoader("forcecage_gate_for_grant", path)
        spec = _iu.spec_from_loader("forcecage_gate_for_grant", loader)
        mod = _iu.module_from_spec(spec)
        loader.exec_module(mod)
        _GATE = mod
    return _GATE


# bind the gate module at import time (cheap, no side effects)
import importlib.machinery as _im
import importlib.util as _iu


def _bind_gate():
    global _GATE
    _GATE = _gate_module()


if not _GATE:
    try:
        _bind_gate()
    except Exception:
        pass  # the pure core is usable without the gate


# ---------------------------------------------------------------------------
# CLI: the narrow agent interface (labels, never values)
# ---------------------------------------------------------------------------

def _arg(flag, argv, i, required=True):
    if i + 1 >= len(argv):
        raise SystemExit("orc-grant: %s needs a value" % flag)
    if argv[i + 1].startswith("--"):
        if required:
            raise SystemExit("orc-grant: %s needs a value" % flag)
        return None, i + 1
    return argv[i + 1], i + 2


def _loop_from_dir(gate_dir, catalog_text=None, clock=None, vault=None, alert=None, mgmt=None,
                   halt_file=None, agent_pid=None, tick_interval=0.5):
    cat = load_catalog(catalog_text) if catalog_text else None
    if cat is None:
        with open(os.path.join(gate_dir, "grant", "catalog.json"), encoding="utf-8") as fh:
            cat = load_catalog(fh.read())
    return GrantLoop(gate_dir, cat, vault=vault, alert=alert, mgmt=mgmt, clock=clock,
                     halt_file=halt_file, agent_pid=agent_pid, tick_interval=tick_interval)


def _grant_dir(gate_dir):
    return os.path.join(gate_dir, "grant")


def _reply_path(gate_dir, rid):
    """The out/ reply file for a request id. Ids with path chars (e.g. the
    CIDR `grant-1.2.3.4/32`) are flattened to dashes so one component is a
    filename; the reply command and the loop must agree on this."""
    return os.path.join(_grant_dir(gate_dir), "out", rid.replace("/", "-") + ".json")


def _write_request_file(gate_dir, doc):
    """Write one agent request file into the in-agent queue. Labels only — no
    credential value may appear in doc."""
    for k, v in doc.items():
        if not isinstance(v, str):
            raise SystemExit("orc-grant: field %r must be a string" % k)
    d = _grant_dir(gate_dir)
    in_agent = os.path.join(d, "in-agent")
    os.makedirs(in_agent, mode=0o770, exist_ok=True)
    path = os.path.join(in_agent, doc["id"] + ".json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    os.replace(tmp, path)
    os.chmod(path, 0o644)
    return doc["id"]


def _new_request_id(prefix):
    return "%s-%s" % (prefix, uuid.uuid4().hex[:8])


def _wait_reply(gate_dir, rid, timeout=0.0, poll=0.2):
    """Optionally block until a FINAL reply lands (the agent CLI default is a
    short wait so the agent gets a synchronous answer against a fast fake
    approver). The service writes an interim ``pending`` reply the moment it
    picks up a request, then overwrites the same file with the terminal
    status (granted / denied / rotated / halt) once the pipeline finishes, so
    this loop keeps polling while the doc still says ``pending`` and returns
    the terminal doc. On timeout it returns the last known doc (which may
    still be ``pending``) or None if no reply ever landed."""
    if timeout <= 0:
        return None
    import time as _time
    deadline = _time.monotonic() + timeout
    path = os.path.join(_grant_dir(gate_dir), "out", rid + ".json")
    last = None
    while True:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                last = json.load(fh)
        if last is not None and last.get("status") != "pending":
            return last
        if _time.monotonic() >= deadline:
            return last
        _time.sleep(poll)


def _print_reply(rid, reply):
    if reply is None:
        print("pending %s" % rid)
        return 3
    status = reply.get("status", "?")
    line = "%s %s" % (status, rid)
    if reply.get("placeholder"):
        line += " " + reply["placeholder"]
    if reply.get("expiry"):
        line += " until " + reply["expiry"]
    if reply.get("reason"):
        line += " (" + reply["reason"] + ")"
    if reply.get("request"):
        line += " -> " + reply["request"]
    print(line)
    return 0 if status in ("granted", "rotated") else 1


def main(argv):
    if not argv:
        print(_usage(), file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]

    if cmd == "serve":
        gate_dir = catalog = None
        agent_pid = None
        halt_file = None
        vault_addr = role_id_file = secret_id_file = None
        i = 0
        while i < len(rest):
            if rest[i] == "--gate-dir":
                gate_dir, i = _arg("--gate-dir", rest, i)
            elif rest[i] == "--catalog":
                catalog, i = _arg("--catalog", rest, i)
            elif rest[i] == "--agent-pid":
                v, i = _arg("--agent-pid", rest, i)
                agent_pid = int(v)
            elif rest[i] == "--halt-file":
                halt_file, i = _arg("--halt-file", rest, i)
            elif rest[i] == "--vault-addr":
                vault_addr, i = _arg("--vault-addr", rest, i)
            elif rest[i] == "--vault-role-id-file":
                role_id_file, i = _arg("--vault-role-id-file", rest, i)
            elif rest[i] == "--vault-secret-id-file":
                secret_id_file, i = _arg("--vault-secret-id-file", rest, i)
            else:
                print("orc-grant: unknown serve arg %r" % rest[i], file=sys.stderr)
                return 2
        if (vault_addr is None) != (role_id_file is None) != (secret_id_file is None):
            print("orc-grant: serve needs all three of --vault-addr, --vault-role-id-file, "
                  "--vault-secret-id-file (or none)", file=sys.stderr)
            return 2
        if catalog and os.path.isfile(catalog):
            with open(catalog, encoding="utf-8") as fh:
                catalog = fh.read()
        if not gate_dir:
            print("orc-grant: serve needs --gate-dir", file=sys.stderr)
            return 2
        vault = None
        if vault_addr is not None:
            vault = VaultMinter(vault_addr, role_id_file, secret_id_file,
                                os.path.join(gate_dir, "grant"))
        loop = _loop_from_dir(gate_dir, catalog, vault=vault, halt_file=halt_file,
                              agent_pid=agent_pid)
        loop.run()
        return 0

    if cmd in ("request-lease", "request-egress", "leak"):
        gate_dir = None
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == "--gate-dir":
                gate_dir, i = _arg("--gate-dir", rest, i)
            elif a.startswith("--gate-dir="):
                gate_dir = a.split("=", 1)[1]; i += 1
            else:
                i += 1
        if not gate_dir:
            print("orc-grant: %s needs --gate-dir" % cmd, file=sys.stderr)
            return 2
        doc = None
        if cmd == "request-lease":
            kind = reason = None
            for a in rest:
                if a.startswith("--kind="):
                    kind = a.split("=", 1)[1]
                elif a.startswith("--reason="):
                    reason = a.split("=", 1)[1]
            if not kind:
                print("orc-grant: request-lease needs --kind", file=sys.stderr)
                return 2
            doc = {"id": _new_request_id("req"), "type": "lease",
                   "kind": kind, "reason": reason or ""}
        elif cmd == "request-egress":
            dest = reason = None
            for a in rest:
                if a.startswith("--destination="):
                    dest = a.split("=", 1)[1]
                elif a.startswith("--reason="):
                    reason = a.split("=", 1)[1]
            if not dest:
                print("orc-grant: request-egress needs --destination", file=sys.stderr)
                return 2
            doc = {"id": _new_request_id("req"), "type": "egress",
                   "destination": dest, "reason": reason or ""}
        else:  # leak
            label = note = None
            for a in rest:
                if a.startswith("--label="):
                    label = a.split("=", 1)[1]
                elif a.startswith("--note="):
                    note = a.split("=", 1)[1]
            if not label:
                print("orc-grant: leak needs --label", file=sys.stderr)
                return 2
            doc = {"id": _new_request_id("leak"), "type": "leak",
                   "label": label, "note": note or ""}
        rid = _write_request_file(gate_dir, doc)
        print(rid)
        return 0

    if cmd == "reply":
        rid = None
        gate_dir = None
        timeout = 0.0
        i = 0
        while i < len(rest):
            a = rest[i]
            if a in ("--id", "--gate-dir", "--timeout"):
                if a == "--id":
                    rid, i = _arg("--id", rest, i)
                elif a == "--gate-dir":
                    gate_dir, i = _arg("--gate-dir", rest, i)
                else:
                    timeout, i = float(_arg("--timeout", rest, i))
            elif a.startswith("--id="):
                rid = a.split("=", 1)[1]; i += 1
            elif a.startswith("--gate-dir="):
                gate_dir = a.split("=", 1)[1]; i += 1
            elif a.startswith("--timeout="):
                timeout = float(a.split("=", 1)[1]); i += 1
            else:
                break
        if not rid:
            print("orc-grant: reply needs --id", file=sys.stderr)
            return 2
        if not gate_dir:
            print("orc-grant: reply needs --gate-dir", file=sys.stderr)
            return 2
        reply = _wait_reply(gate_dir, rid, timeout=timeout)
        return _print_reply(rid, reply)

    print(_usage(), file=sys.stderr)
    return 2


def _usage():
    return """orc-grant — the per-session Grant service (Slice E).

Commands:
  serve --gate-dir DIR [--catalog FILE] [--agent-pid N] [--halt-file PATH]
      Run the grant loop (the launcher starts this, one per session).
      On a canary/misdirect Halt it writes PATH (the pane maps it to exit 3)
      and stops the agent process group named by --agent-pid.
  request-lease --gate-dir DIR --kind ID [--reason TEXT]
      Ask for a credential lease (prints the new request id).
  request-egress --gate-dir DIR --destination DEST [--reason TEXT]
      Ask for an egress grant (prints the new request id).
  leak --gate-dir DIR --label PLACEHOLDER [--note TEXT]
      Report a leaked Placeholder / Codex login (prints the request id).
  reply --gate-dir DIR --id RID
      Print the current status of a request (pending/granted/denied/...).
"""


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
