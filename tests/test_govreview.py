"""End-to-end test suite (stdlib unittest). Run: python -m unittest -v"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from govreview import authorization as A
from govreview.canon import canonical_json, digest_of
from govreview import credential as C
from govreview import ledger as L
from govreview import schema, synthetic
from govreview.concurrency import run_reproduction, thread_ids_are_real
from govreview.delegation import assess_independence, nearest_common_delegator
from govreview.impact import (TOTAL_RECORDS, analyze_impact, build_records,
                              verify_full_set)
from govreview.smallmodel import D_STEPS, U_STEPS, enumerate_interleavings, \
    interleavings


class TempBundle:
    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        p = Path(self._tmp.name)
        synthetic.generate_inputs(p)
        self.dir = p
        self.bundle = schema.load_bundle(p)
        self.ledger = L.Ledger(self.bundle.ledger)
        return self

    def __exit__(self, *a):
        self._tmp.cleanup()


class TestCanon(unittest.TestCase):
    def test_canonical_stable(self):
        a = {"b": 1, "a": [2, {"d": 4, "c": 3}]}
        b = {"a": [2, {"c": 3, "d": 4}], "b": 1}
        self.assertEqual(canonical_json(a), canonical_json(b))
        self.assertEqual(digest_of(a), digest_of(b))

    def test_unicode_preserved(self):
        s = canonical_json({"x": "解冻"})
        self.assertIn("解冻", s)


class TestDelegation(unittest.TestCase):
    def test_independent_chains(self):
        people = {p["id"]: schema.Person(**p) for p in synthetic.build_people()}
        self.assertTrue(assess_independence(people, "p-alice", "p-carol").independent)
        self.assertFalse(assess_independence(people, "p-alice", "p-amber").independent)
        self.assertFalse(assess_independence(people, "p-alice", "p-alice").independent)

    def test_strict_mode(self):
        people = {p["id"]: schema.Person(**p) for p in synthetic.build_people()}
        # alice and amber share chain-A and lineage: rejected both modes.
        self.assertFalse(assess_independence(people, "p-alice", "p-amber").independent)
        # alice(chain-A) vs carol(chain-C), disjoint lineage.
        self.assertTrue(assess_independence(
            people, "p-alice", "p-carol",
            mode="strict_no_common_delegator").independent)

    def test_lca(self):
        people = {p["id"]: schema.Person(**p) for p in synthetic.build_people()}
        self.assertEqual(nearest_common_delegator(people, "p-amber", "p-alice"),
                         "p-alice")
        self.assertIsNone(nearest_common_delegator(people, "p-alice", "p-carol"))


class TestLedger(unittest.TestCase):
    def test_watermarks_monotone(self):
        with TempBundle() as tb:
            seen = []
            for wm in tb.ledger.watermarks():
                view, _ = tb.ledger.replay(wm)
                st = view.states.get("acct-7")
                seen.append((wm, st.status, st.generation))
            statuses = [s for _, s, _ in seen]
            self.assertEqual(statuses[0], "ACTIVE")
            self.assertIn("FROZEN", statuses)
            self.assertEqual(statuses[-1], "DEACTIVATED")

    def test_stale_attempt_refused(self):
        with TempBundle() as tb:
            view, refusals = tb.ledger.replay()
            self.assertTrue(any("stale generation" in r for r in refusals))
            o = view.decision_outcomes["dec-stale"]
            self.assertEqual(o.effect, L.NOT_APPLIED_STALE)

    def test_deactivation_terminal(self):
        with TempBundle() as tb:
            view, _ = tb.ledger.replay()
            st = view.states["acct-7"]
            self.assertEqual(st.status, L.DEACTIVATED)
            o = view.decision_outcomes["dec-valid"]
            self.assertEqual(o.effect, L.NO_EFFECT_DEACTIVATED)


class TestAuthorization(unittest.TestCase):
    def test_valid_form_but_no_effect(self):
        with TempBundle() as tb:
            view, _ = tb.ledger.replay()
            ev = next(e for e in tb.bundle.ledger
                      if e["kind"] == "unfreeze_decided"
                      and e["decision"] == "dec-valid")
            st = view.states["acct-7"]
            v = A.evaluate_unfreeze(ev, st, tb.bundle)
            self.assertEqual(v.decision, A.APPROVE, v.reason_codes)

    def test_stale_rejected(self):
        with TempBundle() as tb:
            view, _ = tb.ledger.replay()
            ev = next(e for e in tb.bundle.ledger
                      if e["kind"] == "unfreeze_decided"
                      and e["decision"] == "dec-stale")
            v = A.evaluate_unfreeze(ev, view.states["acct-7"], tb.bundle)
            self.assertEqual(v.decision, A.REJECT)
            self.assertIn(A.STALE_GENERATION, v.reason_codes)
            self.assertIn(A.APPROVALS_NOT_INDEPENDENT, v.reason_codes)
            self.assertIn(A.TICKET_DIGEST_MISMATCH, v.reason_codes)
            # Approvals bind generation 1 == the event's own generation, so
            # there is no per-approval generation mismatch; the defect is that
            # the *whole decision* is stale.
            self.assertNotIn(A.APPROVAL_GENERATION_MISMATCH, v.reason_codes)


class TestCredential(unittest.TestCase):
    def _credentials(self, tb):
        view, _ = tb.ledger.replay()
        out = []
        for ev in tb.bundle.ledger:
            if ev["kind"] != "unfreeze_decided":
                continue
            v = A.evaluate_unfreeze(ev, view.states["acct-7"], tb.bundle)
            out.append((ev["decision"], C.build_credential(v)))
        return out

    def test_all_verify_and_minimal(self):
        with TempBundle() as tb:
            for name, cred in self._credentials(tb):
                res = C.verify_credential(cred, tb.bundle, tb.ledger)
                self.assertTrue(res.ok, (name, res.detail))
                mr = C.assert_minimal(cred, tb.bundle, tb.ledger)
                self.assertTrue(mr["minimal"], name)

    def test_tampering_rejected(self):
        with TempBundle() as tb:
            for name, cred in self._credentials(tb):
                tr = C.tamper_report(cred, tb.bundle, tb.ledger)
                self.assertTrue(all(t["rejected"] for t in tr), name)

    def test_credential_decision_matches(self):
        with TempBundle() as tb:
            creds = dict(self._credentials(tb))
            self.assertEqual(creds["dec-valid"]["decision"], "APPROVE")
            self.assertEqual(creds["dec-stale"]["decision"], "REJECT")


class TestConcurrency(unittest.TestCase):
    def test_reproduction(self):
        out = run_reproduction()
        self.assertEqual(out["worker_errors"], [])
        self.assertTrue(all(out["checks"].values()), out["checks"])
        self.assertTrue(thread_ids_are_real(out))

    def test_replay_of_captured_log(self):
        out = run_reproduction()
        led = L.Ledger(out["ledger_events"])
        state = led.replay()[0].states["acct-7"]
        self.assertEqual(state.status, L.DEACTIVATED)


class TestSmallModel(unittest.TestCase):
    def test_15_interleavings(self):
        self.assertEqual(len(list(interleavings(D_STEPS, U_STEPS))), 15)

    def test_invariants(self):
        e = enumerate_interleavings()
        self.assertEqual(e.total, 15)
        self.assertTrue(e.all_final_deactivated)
        self.assertTrue(e.all_stale_refused)
        self.assertTrue(e.all_effects_agree, e.mismatches)
        self.assertTrue(e.deterministic)
        self.assertTrue(e.durable_commit_always_present)


class TestImpact(unittest.TestCase):
    def test_60000(self):
        recs = build_records()
        self.assertEqual(len(recs), TOTAL_RECORDS)

    def test_partitions_and_verification(self):
        recs = build_records()
        imp = analyze_impact(recs)
        full = verify_full_set(recs)
        self.assertTrue(all(imp.checks.values()), imp.checks)
        self.assertTrue(full["three_methods_agree"])
        self.assertEqual(imp.total_records, 60000)
        self.assertEqual(sum(imp.org_partition_totals.values()), 60000)
        self.assertTrue(imp.affected_partitions)
        self.assertEqual(imp.affected_record_count, sum(imp.incremental.values()))


class TestInputGuards(unittest.TestCase):
    def test_rejects_outside_tree(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "accounts.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(schema.InputError):
                schema.assert_local_tree(p, [Path("/etc/passwd")])

    def test_rejects_network_path(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            with self.assertRaises(schema.InputError):
                schema.assert_local_tree(p, ["https://example.com/x.json"])

    def test_digest_mismatch_caught(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            synthetic.generate_inputs(p)
            doc = json.loads((p / "tickets.json").read_text(encoding="utf-8"))
            doc["tickets"][0]["digest"] = "sha256:" + "0" * 64
            (p / "tickets.json").write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(schema.InputError):
                schema.load_bundle(p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
