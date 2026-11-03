#!/usr/bin/env python3
"""Tests over bin/orc-grant's pure core (Slice E).

The per-session Grant service (ADR-0044): it APPLIES an approved Egress grant
or Credential lease, EXPIRES it, accepts a Leak report (revoke the Placeholder,
re-mint the SAME access and expiry under a new one, the old one becomes a
Canary until the lease expires), and watches the gate audit for a Canary or
the misdirect sentinel -> a Halt. It never asks the operator; the escalation
gateway (a fake here) is the only approval channel.

The core is pure: ``step(state, event, catalog) -> (state, effects)`` — no
clock, no I/O, no randomness, ids from a deterministic counter. These tests
drive it directly with fakes injected as events (the orc-gate.test.py style).
The loop/CLI and the file-queue transport are covered in the loop tests below.
"""
import importlib.machinery
import importlib.util
import os
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "src" / "cage" / "grant.py"
    loader = importlib.machinery.SourceFileLoader("forcecage_grant", str(path))
    spec = importlib.util.spec_from_loader("forcecage_grant", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


G = load_module()
GrantLoop = G.GrantLoop
canary_marker = G.canary_marker


def catalog():
    return G.load_catalog("""{
      "kinds": [
        {"id": "git-push", "label": "Git push",
         "bound_host": "git.example.com",
         "match_headers": ["Authorization"],
         "vault": {"mode": "dynamic", "path": "secret/gate/git-push"}},
        {"id": "example-api-shared", "label": "example-api shared",
         "bound_host": "litellm.example.com",
         "shared": true,
         "rotatable": false,
         "match_headers": ["Authorization"],
         "vault": {"mode": "shared", "path": "secret/gate/example-api"}},
        {"id": "codex-login", "label": "Codex login",
         "shared": true, "halts_on_leak": true, "rotatable": false,
         "match_headers": [],
         "vault": {"mode": "shared", "path": null}}
      ]
    }""")


class Feed:
    """A tiny event feeder that records every effect, like the loop would."""

    def __init__(self, core):
        self.core = core
        self.fx = []

    def feed(self, event):
        self.fx.extend(self.core.step(event))
        return self.fx


# --- catalog ---------------------------------------------------------------


class Catalog(unittest.TestCase):
    def test_loads_and_validates(self):
        cat = catalog()
        self.assertEqual(set(cat), {"git-push", "example-api-shared", "codex-login"})
        self.assertTrue(cat["codex-login"].halts_on_leak)
        self.assertFalse(cat["example-api-shared"].rotatable)
        self.assertTrue(cat["example-api-shared"].shared)

    def test_duplicate_id_rejected(self):
        with self.assertRaises(ValueError):
            G.load_catalog('{"kinds": [{"id": "a"}, {"id": "a"}]}')

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            G.load_catalog('{"kinds": []}')


# --- lease request lifecycle ----------------------------------------------


class LeaseLifecycle(unittest.TestCase):
    def test_unknown_kind_denied(self):
        core = G.GrantCore(catalog(), session="s",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeaseRequested("R1", "nope", "reason", "t0"))
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "denied"
                            and e.reason == "no-such-kind:nope" for e in f.fx))

    def test_request_then_approve_then_issue(self):
        core = G.GrantCore(catalog(), session="s",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeaseRequested("R1", "git-push", "push a branch", "t0"))
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "pending"
                            for e in f.fx))
        self.assertIn("R1", core.state.pending)

        f.fx.clear()
        f.feed(G.LeaseApproved("R1", "git-push", "t+1h"))
        self.assertTrue(any(isinstance(e, G.MintLease) for e in f.fx))
        lease = list(core.state.leases.values())[0]
        self.assertEqual(lease.status, "pending-mint")

        f.fx.clear()
        f.feed(G.LeaseIssued(lease.lease_id, "PLC-aaa", "tok-" + lease.lease_id))
        self.assertEqual(lease.status, "active")
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "granted"
                            and e.placeholder == "PLC-aaa" for e in f.fx))
        self.assertTrue(any(isinstance(e, G.GateConfigChanged) for e in f.fx))
        self.assertTrue(any(isinstance(e, G.ScheduleExpiry)
                            and e.item_id == lease.lease_id for e in f.fx))

    def test_denied_reply(self):
        core = G.GrantCore(catalog(), session="s",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeaseRequested("R1", "git-push", "r", "t0"))
        f.feed(G.LeaseDenied("R1", "nope"))
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "denied"
                            and e.reason == "nope" for e in f.fx))
        self.assertNotIn("R1", core.state.pending)

    def test_one_live_lease_per_kind(self):
        core = G.GrantCore(catalog(), session="s",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeaseRequested("R1", "git-push", "r", "t0"))
        f.feed(G.LeaseApproved("R1", "git-push", "t+1h"))
        lease = list(core.state.leases.values())[0]
        f.feed(G.LeaseIssued(lease.lease_id, "PLC-aaa", "tok-" + lease.lease_id))

        f.fx.clear()
        f.feed(G.LeaseRequested("R2", "git-push", "again", "t1"))
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "denied"
                            and e.reason.startswith("already-active") for e in f.fx))

    def test_duplicate_pending_request_repoints(self):
        core = G.GrantCore(catalog(), session="s",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeaseRequested("R1", "git-push", "r", "t0"))
        f.fx.clear()
        f.feed(G.LeaseRequested("R2", "git-push", "r2", "t1"))
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "pending"
                            and e.existing_id == "R1" for e in f.fx))


# --- the ADR-0044 leak story ----------------------------------------------


class LeakRotationCore(unittest.TestCase):
    """report -> revoke + re-mint SAME access/expiry under a new Placeholder
    -> old one becomes a Canary until the lease expires -> the Canary in the
    audit is a Halt (once) -> expiry revokes the credential and drops the
    Canary. A Codex-login leak report halts instead of rotating."""

    def test_leak_remint_canary_expiry(self):
        core = G.GrantCore(catalog(), session="it",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)

        f.feed(G.LeaseRequested("R1", "git-push", "push a branch", "t0"))
        f.feed(G.LeaseApproved("R1", "git-push", "t+1h"))
        lease = list(core.state.leases.values())[0]
        f.feed(G.LeaseIssued(lease.lease_id, "PLC-aaa", "tok-" + lease.lease_id))
        granted = next(e for e in f.fx if isinstance(e, G.ReplyToAgent)
                       and e.status == "granted")
        self.assertEqual(granted.placeholder, "PLC-aaa")

        # the agent reports a leak -> rotate: SAME lease, SAME expiry
        f.fx.clear()
        f.feed(G.LeakReported("R2", "PLC-aaa", "t+2m", "sent it to pastebin"))
        self.assertEqual(lease.status, "rotating")
        rot = next(e for e in f.fx if isinstance(e, G.RotateLease))
        self.assertEqual((rot.lease_id, rot.expires_at), (lease.lease_id, "t+1h"))
        self.assertEqual(len(core.state.canaries), 1)
        canary = list(core.state.canaries.values())[0]
        self.assertEqual(canary.placeholder, "PLC-aaa")
        self.assertEqual(canary.expires_at, "t+1h")
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "pending"
                            for e in f.fx))

        # the re-mint lands -> the agent gets the new Placeholder
        f.fx.clear()
        f.feed(G.LeaseIssued(lease.lease_id, "PLC-bbb", "tok-" + lease.lease_id))
        self.assertEqual(lease.status, "active")
        self.assertEqual(lease.placeholder, "PLC-bbb")
        self.assertEqual(lease.rotations, 1)
        self.assertEqual(lease.expires_at, "t+1h")  # the invariant
        rot_reply = next(e for e in f.fx if isinstance(e, G.ReplyToAgent)
                         and e.status == "rotated")
        self.assertEqual(rot_reply.placeholder, "PLC-bbb")

        # the Canary leaves -> exactly ONE Halt (the latch)
        f.fx.clear()
        f.feed(G.AuditEntry("canary", canary.canary_id, "pastebin.example", "t+5m"))
        f.feed(G.AuditEntry("canary", canary.canary_id, "pastebin.example", "t+6m"))
        self.assertEqual([e.kind for e in f.fx if isinstance(e, G.RaiseHaltAlert)],
                         ["canary"])
        self.assertEqual(len([e for e in f.fx if isinstance(e, G.SignalPaneHalt)]), 1)
        self.assertTrue(core.state.halted)

        # expiry revokes the live credential; the Canary dies on its OWN timer
        f.fx.clear()
        f.feed(G.ExpiryDue(lease.lease_id, "t+1h"))
        self.assertTrue(any(isinstance(e, G.RevokeLease) for e in f.fx))
        f.feed(G.LeaseRevoked(lease.lease_id))
        self.assertNotIn(lease.lease_id, core.state.leases)
        f.fx.clear()
        f.feed(G.ExpiryDue(canary.canary_id, "t+1h"))
        self.assertEqual(core.state.canaries, {})

    def test_codex_login_leak_halts(self):
        core = G.GrantCore(catalog(), session="it",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeakReported("R9", "codex-login", "t0", "sent my login"))
        self.assertEqual([e.kind for e in f.fx if isinstance(e, G.RaiseHaltAlert)],
                         ["codex-login-leak"])
        self.assertTrue(core.state.halted)
        self.assertFalse(any(isinstance(e, G.RotateLease) for e in f.fx))
        self.assertTrue(any(isinstance(e, G.SignalPaneHalt) for e in f.fx))

    def test_leak_of_a_canary_label_halts(self):
        core = G.GrantCore(catalog(), session="it",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeaseRequested("R1", "git-push", "r", "t0"))
        f.feed(G.LeaseApproved("R1", "git-push", "t+1h"))
        lease = list(core.state.leases.values())[0]
        f.feed(G.LeaseIssued(lease.lease_id, "PLC-aaa", "tok-" + lease.lease_id))
        f.feed(G.LeakReported("R2", "PLC-aaa", "t1", "leaked it"))
        f.feed(G.LeaseIssued(lease.lease_id, "PLC-bbb", "tok-" + lease.lease_id))
        canary = list(core.state.canaries.values())[0]

        f.fx.clear()
        f.feed(G.LeakReported("R3", canary.placeholder, "t2", "I sent the old one"))
        self.assertEqual([e.kind for e in f.fx if isinstance(e, G.RaiseHaltAlert)],
                         ["canary"])
        self.assertTrue(core.state.halted)

    def test_leak_unknown_label_rejected(self):
        core = G.GrantCore(catalog(), session="it",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeakReported("R1", "Placeholder-nope-123", "t0"))
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "rejected"
                            and e.reason == "unknown-label" for e in f.fx))
        self.assertFalse(core.state.halted)

    def test_shared_non_rotatable_leak_no_rotation(self):
        core = G.GrantCore(catalog(), session="it",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeaseRequested("R1", "example-api-shared", "r", "t0"))
        f.feed(G.LeaseApproved("R1", "example-api-shared", "t+1h"))
        lease = list(core.state.leases.values())[0]
        f.feed(G.LeaseIssued(lease.lease_id, "PLC-example-api", "tok-" + lease.lease_id))

        f.fx.clear()
        f.feed(G.LeakReported("R2", "PLC-example-api", "t1", "went to a log"))
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "rejected"
                            and e.reason == "no-rotation" for e in f.fx))
        self.assertTrue(any(isinstance(e, G.NotifyAlert)
                            and e.kind == "leak-no-rotation" for e in f.fx))
        self.assertFalse(core.state.halted)
        self.assertEqual(lease.status, "active")


# --- audit detection --------------------------------------------------------


class AuditDetection(unittest.TestCase):
    def _halted_core(self):
        core = G.GrantCore(catalog(), session="it",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeaseRequested("R1", "git-push", "r", "t0"))
        f.feed(G.LeaseApproved("R1", "git-push", "t+1h"))
        lease = list(core.state.leases.values())[0]
        f.feed(G.LeaseIssued(lease.lease_id, "PLC-aaa", "tok-" + lease.lease_id))
        return core, f, lease

    def test_inert_swap_halts_misdirect(self):
        core, f, lease = self._halted_core()
        f.fx.clear()
        f.feed(G.AuditEntry("inert", None, "elsewhere.example", "t1"))
        self.assertEqual([e.kind for e in f.fx if isinstance(e, G.RaiseHaltAlert)],
                         ["misdirect"])
        self.assertTrue(core.state.halted)

    def test_live_lease_swap_is_normal(self):
        core, f, lease = self._halted_core()
        f.fx.clear()
        f.feed(G.AuditEntry("lease", lease.lease_id, "git.example.com", "t1"))
        self.assertFalse(core.state.halted)
        self.assertEqual(f.fx, [])

    def test_halt_is_terminal(self):
        core, f, lease = self._halted_core()
        f.feed(G.AuditEntry("inert", None, "x.example", "t1"))
        f.fx.clear()
        f.feed(G.AuditEntry("inert", None, "y.example", "t2"))
        self.assertEqual([e.kind for e in f.fx if isinstance(e, G.RaiseHaltAlert)],
                         [])  # the latch: one Halt


# --- egress grants ----------------------------------------------------------


class EgressGrant(unittest.TestCase):
    def test_request_approve_expire(self):
        core = G.GrantCore(catalog(), session="s",
                           base_allowlist={"domains": ["base.example"],
                                           "cidrs": ["127.0.0.1/32"]})
        f = Feed(core)
        f.feed(G.EgressRequested("R1", "example.com", "need it", "t0"))
        self.assertIn("R1", core.state.pending)
        f.fx.clear()
        f.feed(G.EgressApproved("R1", "example.com", "t+1h"))
        grant = list(core.state.grants.values())[0]
        self.assertTrue(any(isinstance(e, G.GateConfigChanged) for e in f.fx))
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "granted"
                            for e in f.fx))
        view = core.view()
        self.assertIn("example.com", view["allowlist"]["domains"])
        self.assertIn("base.example", view["allowlist"]["domains"])

        f.fx.clear()
        f.feed(G.ExpiryDue(grant.grant_id, "t+1h"))
        self.assertNotIn(grant.grant_id, core.state.grants)
        self.assertNotIn("example.com", core.view()["allowlist"]["domains"])

    def test_denied(self):
        core = G.GrantCore(catalog(), session="s",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.EgressRequested("R1", "example.com", "r", "t0"))
        f.feed(G.EgressDenied("R1", "not now"))
        self.assertTrue(any(isinstance(e, G.ReplyToAgent) and e.status == "denied"
                            for e in f.fx))
        self.assertEqual(core.state.grants, {})

    def test_cidr_grant_lands_in_cidrs(self):
        core = G.GrantCore(catalog(), session="s",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.EgressApproved("R1", "192.0.2.0/24", "t+1h"))  # operator-initiated
        self.assertIn("192.0.2.0/24", core.view()["allowlist"]["cidrs"])


# --- view + file_roles -------------------------------------------------------


class View(unittest.TestCase):
    def test_view_bindings_and_canaries(self):
        core = G.GrantCore(catalog(), session="s",
                           base_allowlist={"domains": [], "cidrs": ["127.0.0.1/32"]})
        f = Feed(core)
        f.feed(G.LeaseRequested("R1", "git-push", "r", "t0"))
        f.feed(G.LeaseApproved("R1", "git-push", "t+1h"))
        lease = list(core.state.leases.values())[0]
        f.feed(G.LeaseIssued(lease.lease_id, "PLC-aaa", "tok-" + lease.lease_id))

        view = core.view()
        b = view["bindings"][0]
        self.assertEqual(b["host"], "git.example.com")
        self.assertEqual(b["placeholder"], "PLC-aaa")
        self.assertEqual(b["secret_name"], "tok-" + lease.lease_id)

        # rotate: the old placeholder is retired, the canary binding appears
        f.feed(G.LeakReported("R2", "PLC-aaa", "t1", "leak"))
        view = core.view()
        self.assertTrue(any(x["secret_name"] == "can-" + lease.lease_id
                            and x["host"] == "*"
                            and x["placeholder"] == "PLC-aaa" for x in view["bindings"]))
        self.assertFalse(any(x["placeholder"] == "PLC-aaa" and x["host"] != "*"
                             for x in view["bindings"]))

        roles = core.file_roles()
        self.assertEqual(roles["tok-" + lease.lease_id], ("lease", lease.lease_id))
        canary = list(core.state.canaries.values())[0]
        self.assertEqual(roles["can-" + lease.lease_id],
                         ("canary", canary.canary_id))


# --- session end -------------------------------------------------------------


class SessionEnd(unittest.TestCase):
    def test_session_ended_revokes_everything(self):
        core = G.GrantCore(catalog(), session="s",
                           base_allowlist={"domains": [], "cidrs": []})
        f = Feed(core)
        f.feed(G.LeaseRequested("R1", "git-push", "r", "t0"))
        f.feed(G.LeaseApproved("R1", "git-push", "t+1h"))
        lease = list(core.state.leases.values())[0]
        f.feed(G.LeaseIssued(lease.lease_id, "PLC-aaa", "tok-" + lease.lease_id))
        f.feed(G.EgressApproved("R2", "example.com", "t+1h"))

        f.fx.clear()
        f.feed(G.SessionEnded("t9"))
        self.assertTrue(any(isinstance(e, G.RevokeLease) for e in f.fx))
        self.assertEqual(core.state.leases, {})
        self.assertEqual(core.state.grants, {})
        self.assertEqual(core.view()["bindings"], [])


# --- loop + file queue (thin I/O adapter) ---------------------------------

import json as _json
import tempfile


class FakeVault:
    def __init__(self):
        self.minted = []
        self.revoked = []
        self.n = 0

    def issue(self, kind, lease_id, expires_at):
        self.n += 1
        self.minted.append((kind.id, lease_id, expires_at))
        return "val-%d" % self.n

    def read_shared(self, kind):
        self.minted.append((kind.id, "shared"))
        return "shared-" + kind.id

    def revoke(self, kind, lease_id):
        self.revoked.append((kind.id, lease_id))


class FakeMgmt:
    def __init__(self):
        self.reloads = 0

    def reload(self):
        self.reloads += 1


class FakeAlert:
    def __init__(self):
        self.halts = []
        self.notifies = []

    def halt(self, fx):
        self.halts.append(fx)

    def notify(self, kind, label):
        self.notifies.append((kind, label))


class Clock:
    def __init__(self, t="2026-11-01T10:00:00+00:00"):
        self.t = t

    def __call__(self):
        return self.t

    def advance_to(self, t):
        self.t = t


def make_gate_dir(tmp):
    """A minimal fake gate dir: state.json, base-config.json, inert, gate.yaml."""
    g = tempfile.mkdtemp(prefix="gate-", dir=tmp)
    inert = os.path.join(g, "inert")
    with open(inert, "w") as fh:
        fh.write("INERT")
    base = {
        "session": "it", "ca": {"dir": g, "ca": "ca.crt", "key": "ca.key"},
        "listen": {"management": 12345, "proxy": 1, "tunnel": 2, "http": 3},
        "allowlist": {"domains": [], "cidrs": ["127.0.0.1/32"]},
        "upstream": "http://127.0.0.1:9", "bindings": [], "inert_path": inert,
    }
    with open(os.path.join(g, "base-config.json"), "w") as fh:
        _json.dump(base, fh)
    with open(os.path.join(g, "state.json"), "w") as fh:
        _json.dump({"session": "it", "listen": {"management": 12345},
                    "mgmt_token": "tkn"}, fh)
    with open(os.path.join(g, "gate.yaml"), "w") as fh:
        fh.write("# initial\n")
    return g


class LoopBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.gate_dir = make_gate_dir(self._tmp.name)
        self.clock = Clock()
        self.vault = FakeVault()
        self.mgmt = FakeMgmt()
        self.alert = FakeAlert()
        self.loop = GrantLoop(self.gate_dir, catalog(), vault=self.vault,
                              alert=self.alert, mgmt=self.mgmt, clock=self.clock,
                              tick_interval=0.01)

    def tearDown(self):
        self._tmp.cleanup()

    def agent(self, doc):
        p = os.path.join(self.gate_dir, "grant", "in-agent",
                         os.path.basename(doc["id"])) + ".json"
        with open(p, "w") as fh:
            _json.dump(doc, fh)

    def host(self, doc):
        name = doc.get("request") or doc.get("destination", "x")
        p = os.path.join(self.gate_dir, "grant", "in-host", name) + ".json"
        with open(p, "w") as fh:
            _json.dump(doc, fh)

    def out(self, rid):
        p = os.path.join(self.gate_dir, "grant", "out", rid + ".json")
        with open(p, encoding="utf-8") as fh:
            return _json.load(fh)

    def placeholders(self):
        with open(os.path.join(self.gate_dir, "grant", "placeholders.json"),
                  encoding="utf-8") as fh:
            return _json.load(fh)

    def gate_yaml(self):
        with open(os.path.join(self.gate_dir, "gate.yaml"), encoding="utf-8") as fh:
            return fh.read()

    def audit(self, secret, host="127.0.0.1:1"):
        line = _json.dumps({"msg": "request", "time": self.clock.t,
                            "audit": {"host": host},
                            "request_transforms": [{"name": "secrets",
                                                    "action": "allow",
                                                    "annotations": {"swapped": [
                                                        {"secret": secret,
                                                         "locations": ["header:Authorization"]}]}}]})
        with open(os.path.join(self.gate_dir, "iron-proxy.log"), "a") as fh:
            fh.write(line + "\n")

    def grant_a_lease(self, rid="R1", placeholder_wait=True):
        """Request -> approve -> issued; returns the loop state lease."""
        self.agent({"id": rid, "type": "lease", "kind": "git-push",
                    "reason": "push a branch"})
        self.loop.tick()
        self.assertEqual(self.out(rid)["status"], "pending")
        self.host({"id": rid, "type": "decision", "request": rid, "verdict": "approve",
                   "kind": "git-push", "expiry": "2026-11-01T11:00:00+00:00"})
        self.loop.tick()
        return list(self.loop.core.state.leases.values())[0]


class LeaseRoundTrip(LoopBase):
    def test_request_approve_issue(self):
        lease = self.grant_a_lease()
        self.assertEqual(lease.status, "active")
        self.assertEqual(self.out("R1")["status"], "granted")
        self.assertEqual(self.out("R1")["placeholder"], lease.placeholder)
        with open(os.path.join(self.gate_dir, lease.secret_name), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "val-1")
        self.assertGreaterEqual(self.mgmt.reloads, 1)
        self.assertIn(lease.placeholder, self.gate_yaml())
        self.assertIn(lease.secret_name, self.gate_yaml())
        self.assertEqual(self.placeholders()["live"], [lease.placeholder])

    def test_denied(self):
        self.agent({"id": "R1", "type": "lease", "kind": "git-push", "reason": "r"})
        self.loop.tick()
        self.host({"id": "R1", "type": "decision", "request": "R1", "verdict": "deny",
                   "kind": "git-push", "reason": "nope"})
        self.loop.tick()
        self.assertEqual(self.out("R1")["status"], "denied")
        self.assertEqual(self.out("R1")["reason"], "nope")


class LeakRotationLoop(LoopBase):
    def test_leak_remint_canary_files(self):
        lease = self.grant_a_lease()
        old = lease.placeholder
        self.agent({"id": "R2", "type": "leak", "label": old, "note": "leaked"})
        self.loop.tick()
        self.assertEqual(lease.status, "active")
        self.assertNotEqual(lease.placeholder, old)
        self.assertEqual(lease.rotations, 1)
        self.assertEqual(self.out("R2")["status"], "rotated")
        self.assertEqual(self.out("R2")["placeholder"], lease.placeholder)
        canary = list(self.loop.core.state.canaries.values())[0]
        with open(os.path.join(self.gate_dir, canary.secret_name), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), canary_marker(lease.lease_id))
        self.assertEqual(self.placeholders()["live"], [lease.placeholder])
        self.assertEqual(self.placeholders()["canaries"], [old])
        self.assertIn(old, self.gate_yaml())


class AuditHaltLoop(LoopBase):
    def test_canary_in_audit_halts(self):
        self.grant_a_lease()
        lease = list(self.loop.core.state.leases.values())[0]
        self.agent({"id": "R3", "type": "leak", "label": lease.placeholder, "note": "x"})
        self.loop.tick()
        canary = list(self.loop.core.state.canaries.values())[0]
        self.audit(os.path.join(self.gate_dir, canary.secret_name), "pastebin.example")
        self.loop.tick()
        self.assertTrue(self.loop.core.state.halted)
        with open(os.path.join(self.gate_dir, "grant", "halt.json"), encoding="utf-8") as fh:
            self.assertEqual(_json.load(fh)["reason"], "canary")
        self.assertEqual(self.alert.halts[0].kind, "canary")

    def test_inert_in_audit_halts(self):
        self.grant_a_lease()
        self.audit(os.path.join(self.gate_dir, "inert"), "elsewhere.example")
        self.loop.tick()
        self.assertTrue(self.loop.core.state.halted)
        with open(os.path.join(self.gate_dir, "grant", "halt.json"), encoding="utf-8") as fh:
            self.assertEqual(_json.load(fh)["reason"], "misdirect")

    def test_halt_closes_pending_requests(self):
        self.grant_a_lease()
        self.agent({"id": "R5", "type": "egress", "destination": "example.com",
                    "reason": "r"})
        self.loop.tick()
        self.assertEqual(self.out("R5")["status"], "pending")
        self.audit(os.path.join(self.gate_dir, "inert"), "elsewhere.example")
        self.loop.tick()
        self.assertEqual(self.out("R5")["status"], "halt")


class ExpiryLoop(LoopBase):
    def test_egress_expiry(self):
        self.host({"id": "example.com", "type": "grant", "destination": "example.com",
                   "expiry": "2026-11-01T11:00:00+00:00"})
        self.loop.tick()
        self.assertIn("example.com", self.gate_yaml())
        self.clock.advance_to("2026-11-01T11:00:01+00:00")
        self.loop.tick()
        self.assertNotIn("example.com", self.gate_yaml())

    def test_lease_expiry_revokes(self):
        lease = self.grant_a_lease()
        self.clock.advance_to("2026-11-01T11:00:01+00:00")
        self.loop.tick()
        self.assertNotIn(lease.lease_id, self.loop.core.state.leases)
        self.assertIn(("git-push", lease.lease_id), self.vault.revoked)
        self.assertFalse(os.path.exists(os.path.join(self.gate_dir, lease.secret_name)))


class QueueHygiene(LoopBase):
    def test_bad_json_retired_and_notified(self):
        p = os.path.join(self.gate_dir, "grant", "in-agent", "R9.json")
        with open(p, "w") as fh:
            fh.write("not json")
        self.loop.tick()
        self.assertFalse(os.path.exists(p))
        self.assertTrue(any(k == "bad-in-agent" for k, _ in self.alert.notifies))

    def test_state_persisted(self):
        self.grant_a_lease()
        with open(os.path.join(self.gate_dir, "grant", "state.json"), encoding="utf-8") as fh:
            doc = _json.load(fh)
        self.assertEqual(doc["session"], "it")
        self.assertIn(list(doc["leases"].values())[0]["secret_name"],
                      ["tok-" + k for k in doc["leases"]])

    def test_session_ended_revokes(self):
        self.grant_a_lease()
        lease = list(self.loop.core.state.leases.values())[0]
        self.host({"id": "example.com", "type": "grant", "destination": "example.com",
                   "expiry": "2026-11-01T11:00:00+00:00"})
        self.loop.tick()
        self.loop.session_ended()
        self.assertEqual(self.loop.core.state.leases, {})
        self.assertFalse(os.path.exists(os.path.join(self.gate_dir, lease.secret_name)))
        self.assertIn(("git-push", lease.lease_id), self.vault.revoked)
        self.assertEqual(self.placeholders()["live"], [])
        self.assertNotIn("example.com", self.gate_yaml())


class Cli(LoopBase):
    """Drive the real agent-facing CLI (main()) end to end against the loop."""

    def test_request_lease_and_reply(self):
        G.main(["request-lease", "--gate-dir", self.gate_dir,
                "--kind=git-push", "--reason=push a branch"])
        req_dir = os.path.join(self.gate_dir, "grant", "in-agent")
        names = [n for n in os.listdir(req_dir) if n.endswith(".json")]
        self.assertEqual(len(names), 1)
        with open(os.path.join(req_dir, names[0]), encoding="utf-8") as fh:
            doc = _json.load(fh)
        self.assertEqual(doc["type"], "lease")
        self.assertEqual(doc["kind"], "git-push")
        self.loop.tick()
        rid = doc["id"]
        self.assertEqual(self.out(rid)["status"], "pending")

    def test_reply_cli_waits_past_interim_pending(self):
        # The service writes an interim "pending" reply the moment it picks up
        # a request, then overwrites the same file with the terminal status
        # once the mint pipeline finishes. A first-existence check returns the
        # interim "pending" (the e2e's Vault mint is wider than the CLI's poll,
        # so the agent egressed an empty lease); the CLI must skip it.
        G.main(["request-lease", "--gate-dir", self.gate_dir,
                "--kind=git-push", "--reason=push a branch"])
        req_dir = os.path.join(self.gate_dir, "grant", "in-agent")
        names = [n for n in os.listdir(req_dir) if n.endswith(".json")]
        with open(os.path.join(req_dir, names[0]), encoding="utf-8") as fh:
            doc = _json.load(fh)
        rid = doc["id"]
        self.loop.tick()  # the service writes the interim "pending" reply
        self.assertEqual(self.out(rid)["status"], "pending")

        def approve():
            self.host({"id": rid, "type": "decision", "request": rid,
                       "verdict": "approve", "kind": "git-push",
                       "expiry": "2026-11-01T11:00:00+00:00"})
            time.sleep(0.3)  # the mint takes longer than one poll interval
            self.loop.tick()  # mint -> the "granted" reply overwrites it

        thread = threading.Thread(target=approve)
        thread.start()
        try:
            reply = G._wait_reply(self.gate_dir, rid, timeout=5.0, poll=0.05)
        finally:
            thread.join()
        self.assertEqual(reply["status"], "granted")

    def test_reply_cli_pending_until_timeout(self):
        # A request nobody approves stays interim "pending"; the CLI must
        # return that doc at the deadline, not None.
        out = os.path.join(self.gate_dir, "grant", "out")
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "R-forever.json"), "w") as fh:
            _json.dump({"id": "R-forever", "status": "pending"}, fh)
        reply = G._wait_reply(self.gate_dir, "R-forever", timeout=0.3, poll=0.05)
        self.assertEqual(reply["status"], "pending")

    def test_leak_request_via_cli(self):
        self.agent({"id": "R1", "type": "lease", "kind": "git-push", "reason": "r"})
        self.loop.tick()
        self.host({"id": "R1", "type": "decision", "request": "R1", "verdict": "approve",
                   "kind": "git-push", "expiry": "2026-11-01T11:00:00+00:00"})
        self.loop.tick()
        lease = list(self.loop.core.state.leases.values())[0]
        old = lease.placeholder
        G.main(["leak", "--gate-dir", self.gate_dir, "--label=" + old])
        self.loop.tick()
        self.assertNotEqual(lease.placeholder, old)  # rotated to a new one
        self.assertEqual(lease.rotations, 1)

    def test_argument_validation(self):
        self.assertEqual(G.main(["request-lease", "--gate-dir", self.gate_dir]), 2)
        self.assertEqual(G.main(["leak", "--gate-dir", self.gate_dir]), 2)
        self.assertEqual(G.main(["nonsense"]), 2)
        self.assertEqual(G.main([]), 2)





# --- integration: the grant loop against a REAL gate -----------------------

import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request


def load_gate_module():
    path = ROOT / "src" / "cage" / "gate.py"
    loader = importlib.machinery.SourceFileLoader("forcecage_gate_it", str(path))
    spec = importlib.util.spec_from_loader("forcecage_gate_it", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


GATE = load_gate_module()


def _start_echo(ip, port):
    return GATE.__dict__.get("_start_echo", None) or _echo_popen(ip, port)


def _echo_popen(ip, port):
    script = (
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
    return subprocess.Popen([sys.executable, "-c", script, str(port), ip],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _proxy_get(proxy, target, token):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    req = urllib.request.Request(target, headers={"Authorization": "Bearer " + token})
    try:
        return opener.open(req, timeout=5).read().decode()
    except urllib.error.HTTPError as e:
        return e.read().decode()


class GrantIntegration(unittest.TestCase):
    """A real iron-proxy gate + the grant loop against it: the loop re-renders
    gate.yaml, reloads the live gate, and the transform pipeline actually swaps
    the minted values. The audit log is the real one; the Canary and the
    misdirect sentinel are detected from it. Fake values only, loopback
    upstreams, masked output. Skipped when the iron-proxy binary is missing.
    """

    IRON = (
        os.environ.get("FORCECAGE_GRANT_TEST_IRON_PROXY")
        or shutil.which("iron-proxy")
        or os.path.expanduser("~/.local/state/forcecage/iron-proxy/iron-proxy"))

    def setUp(self):
        if not os.path.exists(self.IRON):
            raise unittest.SkipTest("iron-proxy binary not found: %s" % self.IRON)
        self._tmp = tempfile.TemporaryDirectory()
        self.ups = [_echo_popen("127.0.0.2", 18960), _echo_popen("127.0.0.3", 18961),
                 _echo_popen("127.0.0.4", 18962)]
        time.sleep(0.4)
        base = os.path.join(self._tmp.name, "it")
        os.makedirs(base)
        real_file = os.path.join(base, "base-tok")
        with open(real_file, "wb") as fh:
            fh.write(b"BASE-VALUE-0001")
        bindings = [{"name": "base", "host": "127.0.0.2",
                     "secret_file": real_file, "placeholder": "Placeholder-base",
                     "match_headers": ["Authorization"]}]
        bf = os.path.join(base, "bindings.json")
        with open(bf, "w") as fh:
            _json.dump(bindings, fh)
        self.gate_dir = os.path.join(base, "gate")
        rc = GATE.main([
            "start", "--session", "grant-it", "--dir", self.gate_dir,
            "--port-mgmt", "28960", "--port-proxy", "28961",
            "--port-tunnel", "28962", "--port-http", "28963", "--port-dns", "28964",
            "--bindings", bf,
            "--allowlist", '{"domains": [], "cidrs": ["127.0.0.2/32", "127.0.0.3/32"]}',
            "--upstream", "http://127.0.0.2:18960", "--upstream-deny", "[]",
            "--inert", "INERT-GRANT-XYZ", "--iron-proxy", self.IRON,
        ])
        self.assertEqual(rc, 0, "gate start failed")
        self.proxy = "http://127.0.0.1:28963"
        cat = G.load_catalog(_json.dumps({
            "kinds": [
                {"id": "git-push", "bound_host": "127.0.0.2",
                 "match_headers": ["Authorization"],
                 "vault": {"mode": "dynamic", "path": "secret/gate/fp"}},
            ]}))
        self.clock = Clock()
        self.vault = FakeVault()
        self.loop = GrantLoop(self.gate_dir, cat, vault=self.vault,
                              clock=self.clock, tick_interval=0.01)

    def tearDown(self):
        try:
            GATE.main(["stop", "--dir", self.gate_dir])
        except Exception:
            pass
        for p in self.ups:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                pass
        self._tmp.cleanup()

    def _agent(self, doc):
        d = os.path.join(self.gate_dir, "grant", "in-agent")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, doc["id"] + ".json"), "w") as fh:
            _json.dump(doc, fh)

    def _host(self, doc):
        d = os.path.join(self.gate_dir, "grant", "in-host")
        os.makedirs(d, exist_ok=True)
        name = (doc.get("request") or doc.get("destination", "x")).replace("/", "-")
        with open(os.path.join(d, name + ".json"), "w") as fh:
            _json.dump(doc, fh)

    def _grant_lease(self, expiry="2026-11-01T10:05:00+00:00"):
        self._agent({"id": "R1", "type": "lease", "kind": "git-push",
                     "reason": "push a branch"})
        self.loop.tick()
        self._host({"id": "R1", "type": "decision", "request": "R1",
                    "verdict": "approve", "kind": "git-push", "expiry": expiry})
        self.loop.tick()
        return list(self.loop.core.state.leases.values())[0]

    def test_lease_swap_on_real_gate(self):
        lease = self._grant_lease()
        # the minted value is what the gate now swaps for the new placeholder
        body = _proxy_get(self.proxy, "http://127.0.0.2:18960/", lease.placeholder)
        self.assertIn("val-1", body, body)
        self.assertNotIn(lease.placeholder, body, body)
        # the base binding still works (the session floor is untouched)
        body = _proxy_get(self.proxy, "http://127.0.0.2:18960/", "Placeholder-base")
        self.assertIn("BASE-VALUE-0001", body, body)

    def test_egress_grant_allowlist_real(self):
        # 127.0.0.4 is not in the base allowlist
        before = _proxy_get(self.proxy, "http://127.0.0.4:18962/", "x")
        self.assertNotIn("auth", before, before)
        self._host({"id": "127.0.0.4/32", "type": "grant", "destination": "127.0.0.4/32",
                    "expiry": "2026-11-01T10:05:00+00:00"})
        self.loop.tick()
        after = _proxy_get(self.proxy, "http://127.0.0.4:18962/", "x")
        self.assertIn("auth", after, after)
        # expiry removes it again
        self.clock.advance_to("2026-11-01T10:06:00+00:00")
        self.loop.tick()
        gone = _proxy_get(self.proxy, "http://127.0.0.4:18962/", "x")
        self.assertNotIn("auth", gone, gone)

    def test_canary_real_audit_halts(self):
        lease = self._grant_lease()
        old = lease.placeholder
        self._agent({"id": "R2", "type": "leak", "label": old, "note": "leaked"})
        self.loop.tick()
        self.assertNotEqual(lease.placeholder, old)  # rotated
        # the old placeholder now resolves to the Canary marker file; a real
        # request carrying it puts the Canary file in the real audit log
        body = _proxy_get(self.proxy, "http://127.0.0.2:18960/", old)
        self.assertIn("Canary-L1", body, body)
        self.loop.tick()
        self.assertTrue(self.loop.core.state.halted)
        with open(os.path.join(self.gate_dir, "grant", "halt.json"), encoding="utf-8") as fh:
            self.assertEqual(_json.load(fh)["reason"], "canary")

    def test_misdirect_real_audit_halts(self):
        lease = self._grant_lease()
        # the live lease placeholder on a host it is not bound for: the gate
        # swaps the inert sentinel, and the real audit names it
        body = _proxy_get(self.proxy, "http://127.0.0.3:18961/", lease.placeholder)
        self.assertIn("INERT-GRANT-XYZ", body, body)
        self.loop.tick()
        self.assertTrue(self.loop.core.state.halted)
        with open(os.path.join(self.gate_dir, "grant", "halt.json"), encoding="utf-8") as fh:
            self.assertEqual(_json.load(fh)["reason"], "misdirect")


# ---------------------------------------------------------------------------
# VaultMinter unit tests (Slice F): the AppRole cache and the KV plumbing,
# against an injected CLI — no vault needed.
# ---------------------------------------------------------------------------


class _FakeVaultCli:
    def __init__(self):
        self.token = "hvs.UNIT-TOKEN-1"
        self.calls = []   # (args, token)
        self.now = 1000.0

    def __call__(self, args, token):
        self.calls.append((args, token))
        if args[0] == "write" and len(args) > 2 and args[2] == "auth/approle/login":
            return 0, self.token, ""
        if args[:2] == ["token", "lookup"]:
            return 0, '{"created_time": %d, "ttl": 300}' % int(self.now), ""
        if args[:2] == ["kv", "put"]:
            return 0, "", ""
        if args[:2] == ["kv", "get"]:
            return 0, "SHARED-VALUE-UNIT", ""
        if args[:3] == ["kv", "metadata", "delete"]:
            return 0, "", ""
        return 1, "", "unknown: " + " ".join(args)


class VaultMinterTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = self._tmp.name
        self.cli = _FakeVaultCli()
        with open(os.path.join(self.base, "role-id"), "w") as fh:
            fh.write("role-1\n")
        with open(os.path.join(self.base, "secret-id"), "w") as fh:
            fh.write("sec-1\n")
        self.cat = G.load_catalog(_json.dumps({
            "kinds": [
                {"id": "dyn", "vault": {"mode": "dynamic", "path": "secret/gate/dyn"}},
                {"id": "shr", "shared": True, "rotatable": False,
                 "vault": {"mode": "shared", "path": "secret/gate/shr"}},
            ]}))
        self.m = G.VaultMinter("http://127.0.0.1:9999",
                               os.path.join(self.base, "role-id"),
                               os.path.join(self.base, "secret-id"),
                               self.base, run_cli=self.cli,
                               now=lambda: self.cli.now)

    def tearDown(self):
        self._tmp.cleanup()

    def _logins(self):
        return sum(1 for args, _ in self.cli.calls
                   if len(args) > 2 and args[2] == "auth/approle/login")

    def test_login_cached_across_ops(self):
        self.m.issue(self.cat["dyn"], "L1", "2026-11-01T10:00:00+00:00")
        self.m.issue(self.cat["dyn"], "L2", "2026-11-01T10:00:00+00:00")
        self.assertEqual(self._logins(), 1)
        tf = os.path.join(self.base, "vault-token.json")
        self.assertEqual(stat.S_IMODE(os.stat(tf).st_mode), 0o600)

    def test_relogin_when_token_near_expiry(self):
        self.m.issue(self.cat["dyn"], "L1", "2026-11-01T10:00:00+00:00")
        self.assertEqual(self._logins(), 1)
        self.cli.now += 280  # ttl 300, refresh at 90% = 270 s
        self.m.issue(self.cat["dyn"], "L2", "2026-11-01T10:00:00+00:00")
        self.assertEqual(self._logins(), 2)

    def test_relogin_when_token_file_missing(self):
        self.m.issue(self.cat["dyn"], "L1", "2026-11-01T10:00:00+00:00")
        os.remove(os.path.join(self.base, "vault-token.json"))
        value = self.m.read_shared(self.cat["shr"])
        self.assertEqual(self._logins(), 2)
        self.assertEqual(value, "SHARED-VALUE-UNIT")

    def test_issue_dynamic_kv_put(self):
        from datetime import datetime, timezone, timedelta
        expires = (datetime.fromtimestamp(self.cli.now, tz=timezone.utc)
                   + timedelta(seconds=120)).isoformat()
        value = self.m.issue(self.cat["dyn"], "L1", expires)
        self.assertTrue(value.startswith("grant-L1-"), value)
        put = [a for a, _ in self.cli.calls if a[:2] == ["kv", "put"]]
        self.assertEqual(len(put), 1)
        # the KV mount here (Vault 2.1.2) has no per-entry TTL; expiry is the
        # loop's job (ExpiryDue timer + leak rotation), so no -ttl flag
        self.assertNotIn("-ttl=120s", put[0])
        self.assertIn("secret/gate/dyn", put[0])

    def test_read_shared_kv_get(self):
        value = self.m.read_shared(self.cat["shr"])
        self.assertEqual(value, "SHARED-VALUE-UNIT")
        get = [a for a, _ in self.cli.calls if a[:2] == ["kv", "get"]]
        self.assertEqual(get[0][:2], ["kv", "get"])
        self.assertIn("-field=value", get[0])
        self.assertIn("secret/gate/shr", get[0])

    def test_revoke_dynamic_only(self):
        before = len(self.cli.calls)
        self.m.revoke(self.cat["shr"], "L1")
        self.assertEqual(len(self.cli.calls), before)  # shared: no KV write
        self.m.revoke(self.cat["dyn"], "L1")
        dele = [a for a, _ in self.cli.calls if a[:3] == ["kv", "metadata", "delete"]]
        self.assertEqual(dele[0][-1], "secret/gate/dyn")


# ---------------------------------------------------------------------------
# Slice F end to end: a real vault dev server (AppRole) + a real iron-proxy
# gate + the real GrantLoop with the real VaultMinter. The minter logs in
# once, mints the dynamic lease into a KV entry (Vault-side TTL), reads the
# shared kind, revokes on expiry and re-mints on rotation.
# ---------------------------------------------------------------------------


def _vault_cli(base, args, addr, token):
    env = {**os.environ, "VAULT_ADDR": addr, "VAULT_TOKEN": token,
           "HOME": str(base)}
    p = subprocess.run(["vault"] + args, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr


def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class GrantVaultIntegration(unittest.TestCase):
    IRON = (
        os.environ.get("FORCECAGE_GRANT_TEST_IRON_PROXY")
        or shutil.which("iron-proxy")
        or os.path.expanduser("~/.local/state/forcecage/iron-proxy/iron-proxy"))

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.IRON):
            raise unittest.SkipTest("iron-proxy binary not found: %s" % cls.IRON)
        if shutil.which("vault") is None:
            raise unittest.SkipTest("vault CLI not on PATH")
        cls.base = Path("/tmp/sbx-grant-vault")
        cls.base.mkdir(parents=True, exist_ok=True)
        cls.root = "dev-token-grant-%d" % os.getpid()
        cls.vport = _free_port()
        cls.addr = "http://127.0.0.1:%d" % cls.vport
        log = open(cls.base / "vault.log", "wb")
        cls.vault = subprocess.Popen(
            ["vault", "server", "-dev", "-dev-no-store-token",
             "-dev-listen-address=127.0.0.1:%d" % cls.vport,
             "-dev-root-token-id=%s" % cls.root],
            stdout=log, stderr=subprocess.STDOUT, env={**os.environ, "HOME": str(cls.base)})
        # token lookup proves the OUR root token is valid on the port (a
        # `status` would pass against any server squatting on it)
        ready = False
        for _ in range(60):
            rc, out, err = _vault_cli(cls.base, ["token", "lookup"], cls.addr, cls.root)
            if rc == 0:
                ready = True
                break
            time.sleep(0.25)
        if not ready:
            cls.vault.terminate()
            try:
                cls.vault.wait(timeout=5)
            except Exception:
                pass
            raise unittest.SkipTest("vault dev server did not become ready")
        try:
            rc, out, err = _vault_cli(cls.base, ["auth", "enable", "approle"], cls.addr, cls.root)
            assert rc == 0, out + err
            pol = cls.base / "grant-policy.hcl"
            pol.write_text(
                'path "secret/data/gate/*" { capabilities = ["create", "read", "update", "delete"] }\n'
                'path "secret/metadata/gate/*" { capabilities = ["create", "read", "update", "delete"] }\n')
            rc, out, err = _vault_cli(cls.base, ["policy", "write", "grant-mint", str(pol)], cls.addr, cls.root)
            assert rc == 0, out + err
            rc, out, err = _vault_cli(cls.base,
                ["kv", "put", "secret/gate/example-api", "value=SHARED-VALUE-0001"], cls.addr, cls.root)
            assert rc == 0, out + err
            rc, out, err = _vault_cli(cls.base,
                ["write", "auth/approle/role/grant-mint", "token_ttl=5m", "token_max_ttl=5m",
                 "token_policies=grant-mint", "secret_id_ttl=5m", "secret_id_num_uses=0"],
                cls.addr, cls.root)
            assert rc == 0, out + err
            rc, out, err = _vault_cli(cls.base, ["read", "-field=role_id", "auth/approle/role/grant-mint/role-id"], cls.addr, cls.root)
            assert rc == 0, out + err
            cls.role_id = out.strip()
            rc, out, err = _vault_cli(cls.base, ["write", "-force", "-field=secret_id", "auth/approle/role/grant-mint/secret-id"], cls.addr, cls.root)
            assert rc == 0, out + err
            cls.secret_id = out.strip()
        except AssertionError:
            cls.vault.terminate()
            try:
                cls.vault.wait(timeout=5)
            except Exception:
                pass
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            cls.vault.terminate()
            cls.vault.wait(timeout=5)
        except Exception:
            pass

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ups = [_echo_popen("127.0.0.2", 18970), _echo_popen("127.0.0.3", 18971),
                    _echo_popen("127.0.0.4", 18972)]
        time.sleep(0.4)
        base = os.path.join(self._tmp.name, "it")
        os.makedirs(base)
        real_file = os.path.join(base, "base-tok")
        with open(real_file, "wb") as fh:
            fh.write(b"BASE-VALUE-0001")
        bindings = [{"name": "base", "host": "127.0.0.2",
                     "secret_file": real_file, "placeholder": "Placeholder-base",
                     "match_headers": ["Authorization"]}]
        bf = os.path.join(base, "bindings.json")
        with open(bf, "w") as fh:
            _json.dump(bindings, fh)
        self.gate_dir = os.path.join(base, "gate")
        rc = GATE.main([
            "start", "--session", "grant-vault-it", "--dir", self.gate_dir,
            "--port-mgmt", "28970", "--port-proxy", "28971", "--port-tunnel", "28972",
            "--port-http", "28973", "--port-dns", "28974",
            "--bindings", bf,
            "--allowlist", '{"domains": [], "cidrs": ["127.0.0.2/32", "127.0.0.3/32"]}',
            "--upstream", "http://127.0.0.2:18970", "--upstream-deny", "[]",
            "--inert", "INERT-GRANT-VAULT", "--iron-proxy", self.IRON,
        ])
        self.assertEqual(rc, 0, "gate start failed")
        self.proxy = "http://127.0.0.1:28973"
        cat = G.load_catalog(_json.dumps({
            "kinds": [
                {"id": "git-push", "bound_host": "127.0.0.2",
                 "match_headers": ["Authorization"],
                 "vault": {"mode": "dynamic", "path": "secret/gate/fp"}},
                {"id": "example-api-shared", "bound_host": "127.0.0.2", "shared": True,
                 "rotatable": False, "match_headers": ["Authorization"],
                 "vault": {"mode": "shared", "path": "secret/gate/example-api"}},
            ]}))
        grant_dir = os.path.join(self.gate_dir, "grant")
        os.makedirs(grant_dir, exist_ok=True)
        role = os.path.join(grant_dir, "role-id")
        sec = os.path.join(grant_dir, "secret-id")
        with open(role, "w") as fh:
            fh.write(self.role_id + "\n")
        with open(sec, "w") as fh:
            fh.write(self.secret_id + "\n")
        self.minter = G.VaultMinter(self.addr, role, sec, grant_dir)
        self.clock = Clock()
        self.loop = GrantLoop(self.gate_dir, cat, vault=self.minter,
                              clock=self.clock, tick_interval=0.01)

    def tearDown(self):
        try:
            GATE.main(["stop", "--dir", self.gate_dir])
        except Exception:
            pass
        for p in self.ups:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                pass
        self._tmp.cleanup()

    def _agent(self, doc):
        d = os.path.join(self.gate_dir, "grant", "in-agent")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, doc["id"] + ".json"), "w") as fh:
            _json.dump(doc, fh)

    def _host(self, doc):
        d = os.path.join(self.gate_dir, "grant", "in-host")
        os.makedirs(d, exist_ok=True)
        name = (doc.get("request") or doc.get("destination", "x")).replace("/", "-")
        with open(os.path.join(d, name + ".json"), "w") as fh:
            _json.dump(doc, fh)

    def _grant_lease(self, kind, expiry="2026-11-01T10:05:00+00:00"):
        self._agent({"id": "R1", "type": "lease", "kind": kind, "reason": "e2e"})
        self.loop.tick()
        self._host({"id": "R1", "type": "decision", "request": "R1",
                    "verdict": "approve", "kind": kind, "expiry": expiry})
        self.loop.tick()
        return list(self.loop.core.state.leases.values())[0]

    def test_shared_lease_mints_and_swaps(self):
        lease = self._grant_lease("example-api-shared")
        body = _proxy_get(self.proxy, "http://127.0.0.2:18970/", lease.placeholder)
        self.assertIn("SHARED-VALUE-0001", body, body)
        self.assertNotIn(lease.placeholder, body, body)

    def test_dynamic_lease_minted_in_vault(self):
        lease = self._grant_lease("git-push")
        rc, out, err = _vault_cli(self.base, ["kv", "get", "-field=value",
                                              "secret/gate/fp"], self.addr, self.root)
        self.assertEqual(rc, 0, err)
        value = out.strip().splitlines()[-1]
        self.assertTrue(value.startswith("grant-"), value)
        body = _proxy_get(self.proxy, "http://127.0.0.2:18970/", lease.placeholder)
        self.assertIn(value, body, body)
        self.assertNotIn(lease.placeholder, body, body)

    def test_dynamic_lease_expiry_removes_vault_entry(self):
        lease = self._grant_lease("git-push", "2026-11-01T10:05:00+00:00")
        self.clock.advance_to("2026-11-01T10:06:00+00:00")
        self.loop.tick()
        rc, out, err = _vault_cli(self.base, ["kv", "get", "secret/gate/fp"],
                                  self.addr, self.root)
        self.assertNotEqual(rc, 0, "vault entry survived expiry: %s" % out)
        # the binding is gone: the placeholder now passes through unswapped
        body = _proxy_get(self.proxy, "http://127.0.0.2:18970/", lease.placeholder)
        self.assertIn(lease.placeholder, body, body)

    def test_leak_rotation_replaces_vault_entry(self):
        lease = self._grant_lease("git-push")
        old_placeholder = lease.placeholder  # capture: the loop mutates leases in place
        rc, out, err = _vault_cli(self.base, ["kv", "get", "-field=value",
                                              "secret/gate/fp"], self.addr, self.root)
        value1 = out.strip().splitlines()[-1]
        self._agent({"id": "R2", "type": "leak", "label": old_placeholder,
                     "note": "leaked"})
        self.loop.tick()
        lease2 = list(self.loop.core.state.leases.values())[0]
        self.assertNotEqual(lease2.placeholder, old_placeholder)
        rc, out, err = _vault_cli(self.base, ["kv", "get", "-field=value",
                                              "secret/gate/fp"], self.addr, self.root)
        value2 = out.strip().splitlines()[-1]
        self.assertNotEqual(value1, value2)
        body = _proxy_get(self.proxy, "http://127.0.0.2:18970/", lease2.placeholder)
        self.assertIn(value2, body, body)

    def test_token_file_cached_and_refreshed(self):
        self._grant_lease("git-push")
        tf = os.path.join(self.gate_dir, "grant", "vault-token.json")
        self.assertTrue(os.path.exists(tf))
        self.assertEqual(stat.S_IMODE(os.stat(tf).st_mode), 0o600)
        os.remove(tf)
        # a rotation re-mints and must re-login to Vault with the AppRole
        lease = list(self.loop.core.state.leases.values())[0]
        self._agent({"id": "R2", "type": "leak", "label": lease.placeholder,
                     "note": "leaked"})
        self.loop.tick()
        self.assertTrue(os.path.exists(tf), "rotation failed to re-login")


class ServeEntryTest(unittest.TestCase):
    """The serve entry point's loop construction (the pane starts this).

    Regression guard: a duplicate ``_loop_from_dir`` with the old signature
    (no ``halt_file``/``agent_pid``) shadowed the real one, so the serve
    handler's keyword call raised TypeError and every pane's grant service
    died before its first tick -- a Canary or misdirected-Placeholder audit
    line then had nothing to watch. The e2e (tests/orc-sandbox-e2e.test.sh,
    sections 3-4) exercises this path against a live gate; this pins the
    construction contract itself.
    """

    def test_loop_from_dir_accepts_serve_kwargs(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            gate = make_gate_dir(tmp.name)
            halt = os.path.join(tmp.name, "halt")
            cat = '{"kinds": [{"id": "e2e", "label": "e2e", "shared": true, "bound_host": "h1", "match_headers": ["Authorization"], "vault": {"mode": "shared", "path": "secret/gate/e2e"}}]}'
            loop = G._loop_from_dir(gate, cat, halt_file=halt, agent_pid=4242)
            self.assertIsInstance(loop, GrantLoop)
            self.assertEqual(loop.halt_marker, halt)
            self.assertEqual(loop.agent_pid, 4242)
            loop.request_stop()
        finally:
            tmp.cleanup()

    def test_run_survives_its_first_sleep(self):
        # Regression guard: the loop's sleep was ``_os.sleep`` (the os module
        # has no sleep), so run() ticked once at startup and then died on the
        # first sleep -- a pane's grant service watched nothing after startup,
        # and a Canary or misdirected-Placeholder audit line went unhalting.
        # run() here must complete at least two ticks (i.e. survive one sleep)
        # before honoring request_stop.
        tmp = tempfile.TemporaryDirectory()
        try:
            gate = make_gate_dir(tmp.name)
            halt = os.path.join(tmp.name, "halt")
            cat = '{"kinds": [{"id": "e2e", "label": "e2e", "shared": true, "bound_host": "h1", "match_headers": ["Authorization"], "vault": {"mode": "shared", "path": "secret/gate/e2e"}}]}'
            loop = G._loop_from_dir(gate, cat, halt_file=halt, agent_pid=4242,
                                    tick_interval=0.05)
            import threading as _threading
            errors = []

            def _runner():
                try:
                    loop.run()
                except Exception as e:  # noqa: BLE001 - the test's job is to see it
                    errors.append(e)

            th = _threading.Thread(target=_runner)
            th.start()
            import time as _time
            _time.sleep(0.2)  # ~3-4 ticks at 0.05s
            loop.request_stop()
            th.join(5)
            self.assertFalse(th.is_alive(), "run() did not stop")
            self.assertEqual(errors, [],
                             "run() died mid-loop: %r" % (errors,))
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
