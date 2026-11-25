"""Convenience entry point: build the demo, print a summary, run the tests.

    python run_all.py            # demo + summary
    python run_all.py --tests    # demo + unittest suite
"""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from govreview.cli import cmd_demo  # noqa: E402


def print_summary(out_dir: Path) -> None:
    import json
    res = json.loads((out_dir / "RESULT.json").read_text(encoding="utf-8"))
    s = res["summary"]
    lines = []
    lines.append("=" * 66)
    lines.append(" 离线安全复核 13330 — 结果摘要")
    lines.append("=" * 66)
    lines.append(f" 最终状态       : {s['final_status']} (generation {s['final_generation']})")
    lines.append(f" 胜出方         : {s['winner']}")
    lines.append(f" 形式合规解冻   : {s['form_valid_unfreezes']}")
    lines.append(f" 被拒决定       : {s['rejected_decisions']}")
    lines.append(f" 停用影响记录   : {s['effective_impact_records']}")
    lines.append(f" 影响分区       : {', '.join(s['effective_impact_partitions'])}")
    lines.append("-" * 66)
    lines.append(" 检查项:")
    for name, ok in res["checks"].items():
        lines.append(f"   {'PASS' if ok else 'FAIL'}  {name}")
    lines.append("-" * 66)
    lines.append(f" 总体: {'通过' if res['all_checks_pass'] else '未通过'}")
    lines.append(f" 产物目录: {out_dir}")
    lines.append(f" 报告: {out_dir / 'REPORT.md'}")
    lines.append("=" * 66)
    try:
        print("\n".join(lines))
    except UnicodeEncodeError:
        sys.stdout.buffer.write(
            ("\n".join(lines) + "\n").encode("utf-8"))
        sys.stdout.flush()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tests", action="store_true", help="also run unittest suite")
    ap.add_argument("--out", default="artifacts/demo")
    args = ap.parse_args(argv)

    out_dir = ROOT / args.out
    rc = cmd_demo(out_dir)
    print_summary(out_dir)

    if args.tests:
        print("\n Running unittest suite ...\n")
        loader = unittest.TestLoader()
        suite = loader.discover(str(ROOT / "tests"), pattern="test_*.py")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        if not result.wasSuccessful():
            return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
