"""Materialize the demo artifact set into ``artifacts/demo`` (repo root).

This is a normal test (it always passes when generation succeeds) whose side
effect is to write a browsable, checked-in-style demo next to the source, so a
reviewer can open ``artifacts/demo/REPORT.md`` without running anything.  The
directory is git-ignored; this simply makes it reproducible.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from govreview.cli import cmd_demo

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestMaterializeDemo(unittest.TestCase):
    def test_materialize_repo_demo(self):
        out = REPO_ROOT / "artifacts" / "demo"
        rc = cmd_demo(out)
        res = json.loads((out / "RESULT.json").read_text(encoding="utf-8"))
        self.assertTrue(res["all_checks_pass"], res["checks"])
        self.assertEqual(rc, 0)
        # Sanity: the human report exists and is non-trivial.
        report = (out / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("DEACTIVATED", report)
        self.assertIn("60,000", report)


if __name__ == "__main__":
    unittest.main()
