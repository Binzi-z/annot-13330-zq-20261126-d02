"""End-to-end integration test: builds the demo and asserts all checks pass.

Run via ``python -m unittest discover -s tests``.  Prints the report summary so
the console shows the concrete incident outcome.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from govreview.cli import cmd_demo, cmd_verify


class TestEndToEnd(unittest.TestCase):
    def test_demo_and_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "artifacts"
            rc = cmd_demo(out)
            self.assertEqual(rc, 0, "demo reported a failing check")

            res = json.loads((out / "RESULT.json").read_text(encoding="utf-8"))
            self.assertTrue(res["all_checks_pass"], res["checks"])

            # Every declared artifact exists and is in the manifest.
            manifest = json.loads(
                (out / "MANIFEST.json").read_text(encoding="utf-8"))
            listed = {e["path"] for e in manifest["entries"]}
            for name in ("REPORT.md", "RESULT.json", "watermarks.json",
                         "credentials.json", "concurrency.json",
                         "smallmodel.json", "impact.json",
                         "decision_log.jsonl"):
                self.assertIn(name, listed)
                self.assertTrue((out / name).is_file())

            # Credentials: one approval, one rejection, all minimal & tamper-safe.
            creds = json.loads(
                (out / "credentials.json").read_text(encoding="utf-8"))
            decisions = {c["decision"]: c for c in creds["credentials"]}
            self.assertEqual(decisions["dec-valid"]["verdict"]["decision"],
                             "APPROVE")
            self.assertEqual(decisions["dec-stale"]["verdict"]["decision"],
                             "REJECT")
            for name, c in decisions.items():
                self.assertTrue(c["verification"]["ok"], (name, c["verification"]))
                self.assertTrue(c["minimality"]["minimal"], name)
                self.assertTrue(all(t["rejected"] for t in c["tamper"]), name)

            # Concurrency reproduction hit all three hazards on real threads.
            conc = json.loads(
                (out / "concurrency.json").read_text(encoding="utf-8"))
            self.assertTrue(conc["all_checks_pass"], conc["checks"])
            workers = conc["worker_outcomes"]
            self.assertEqual(len({w["thread_ident"] for w in workers.values()}),
                             2)

            # Small model: 15 interleavings, all invariants hold.
            sm = json.loads(
                (out / "smallmodel.json").read_text(encoding="utf-8"))
            self.assertEqual(sm["total_interleavings"], 15)
            self.assertEqual(sm["deactivation_first"], 10)
            self.assertEqual(sm["unfreeze_first"], 5)
            self.assertTrue(sm["invariant_all_final_deactivated"])

            # Impact: 60k across 5 orgs x 4 partitions = 20 partitions.
            imp = json.loads(
                (out / "impact.json").read_text(encoding="utf-8"))
            self.assertEqual(imp["impact"]["total_records"], 60000)
            self.assertEqual(len(imp["impact"]["partition_counts"]), 20)
            self.assertEqual(sum(imp["impact"]["org_partition_totals"].values()),
                             60000)
            self.assertTrue(imp["full_set_verification"]["three_methods_agree"])

            # Print the human summary to the console (ASCII-safe for GBK).
            report = (out / "REPORT.md").read_text(encoding="utf-8")
            print("\n----- REPORT.md -----\n" + report.encode(
                "ascii", "replace").decode("ascii"))

    def test_verify_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "artifacts"
            self.assertEqual(cmd_demo(out), 0)
            # Verify re-checks the manifest hashes and re-runs the analysis.
            rc = cmd_verify(out, out)
            self.assertEqual(rc, 0)

    def test_verify_detects_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "artifacts"
            self.assertEqual(cmd_demo(out), 0)
            # Corrupt a credential artifact, then verify must flag it.
            p = out / "credentials.json"
            p.write_text(p.read_text(encoding="utf-8") + " ",
                         encoding="utf-8")
            rc = cmd_verify(out, out)
            self.assertNotEqual(rc, 0, "manifest tamper was not detected")


if __name__ == "__main__":
    unittest.main(verbosity=2)
