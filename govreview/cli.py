"""CLI: build/verify the offline review end to end.

Usage::

    python -m govreview.cli demo   [--out OUTDIR]
    python -m govreview.cli verify --in INDIR [--out OUTDIR]

``demo`` generates a fresh synthetic input set, runs every analysis, writes
``REPORT.md`` + ``RESULT.json`` + a hash ``MANIFEST.json``, and returns a
non-zero exit code if any check fails.  ``verify`` re-loads an existing input
set, re-runs it, and re-checks artifact hashes against the stored manifest.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .authorization import evaluate_unfreeze, APPROVE
from .canon import (dump_json, load_jsonl, verify_manifest, write_manifest)
from .concurrency import run_reproduction
from .credential import (assert_minimal, build_credential, tamper_report,
                        verify_credential)
from .impact import analyze_impact, build_records, verify_full_set
from .ledger import (DEACTIVATED, Ledger, verify_chain)
from .schema import load_bundle
from .smallmodel import enumerate_interleavings
from .synthetic import generate_inputs, logical_digests, physical_digests

ARTIFACTS = [
    "accounts.json", "delegation.json", "tickets.json", "ledger.jsonl",
    "decision_log.jsonl",
    "watermarks.json", "credentials.json", "concurrency.json",
    "smallmodel.json", "impact.json", "RESULT.json", "REPORT.md",
]


# --------------------------------------------------------------------------
# Build the whole review from a validated bundle
# --------------------------------------------------------------------------
def analyze_bundle(input_dir: Path, out_dir: Path) -> dict[str, Any]:
    import shutil
    out_dir.mkdir(parents=True, exist_ok=True)
    # Mirror the four inputs (+ chained log) into the artifact dir so the
    # manifest/seals cover them and ``verify`` can re-hash a self-contained set.
    for name in ("accounts.json", "delegation.json", "tickets.json",
                 "ledger.jsonl", "decision_log.jsonl"):
        src, dst = input_dir / name, out_dir / name
        if src.resolve() != dst.resolve():
            if not src.is_file():
                raise FileNotFoundError(f"missing input: {src}")
            shutil.copyfile(src, dst)
    bundle = load_bundle(out_dir)
    ledger = Ledger(bundle.ledger)

    # 1. Per-watermark authorization state.
    watermarks = []
    for wm in ledger.watermarks():
        view, refusals = ledger.replay(wm)
        acc = view.states.get("acct-7")
        row = {
            "watermark": wm,
            "accounts": {
                a: {"status": s.status, "generation": s.generation}
                for a, s in sorted(view.states.items())},
            "decisions": {d: o.to_dict()
                          for d, o in sorted(view.decision_outcomes.items())},
            "anomalies": view.anomalies,
            "refusals": refusals,
        }
        watermarks.append(row)
    dump_json({"watermarks": watermarks}, out_dir / "watermarks.json")

    # 2. Credentials for every unfreeze decision, each evaluated at its own
    #    watermark (the same state the independent verifier reconstructs).
    final_view, final_refusals = ledger.replay()
    credentials = []
    for ev in bundle.ledger:
        if ev["kind"] != "unfreeze_decided":
            continue
        view_at_event, _ = ledger.replay(ev["seq"])
        state = view_at_event.states.get(ev["account"])
        verdict = evaluate_unfreeze(ev, state, bundle)
        cred = build_credential(verdict)
        vres = verify_credential(cred, bundle, ledger)
        minimal = assert_minimal(cred, bundle, ledger) if vres.ok else {
            "minimal": False, "reason": "credential did not verify"}
        tamper = tamper_report(cred, bundle, ledger) if vres.ok else []
        credentials.append({
            "decision": ev["decision"],
            "verdict": verdict.to_dict(),
            "credential": cred,
            "verification": vres.to_dict(),
            "minimality": minimal,
            "tamper": tamper,
            "effect": (final_view.decision_outcomes[ev["decision"]].effect
                       if ev["decision"] in final_view.decision_outcomes
                       else None),
        })
    dump_json({"credentials": credentials}, out_dir / "credentials.json")

    # 3. Real two-thread + barrier reproduction, persisted.
    repro = run_reproduction()
    dump_json(repro, out_dir / "concurrency.json")

    # 4. Small-model exhaustive enumeration.
    enum = enumerate_interleavings()
    dump_json(enum.to_dict(), out_dir / "smallmodel.json")

    # 5. 60k impact analysis + full-set verification.
    records = build_records()
    impact = analyze_impact(records)
    fullset = verify_full_set(records)
    dump_json({"impact": impact.to_dict(), "full_set_verification": fullset},
              out_dir / "impact.json")

    # 6. Hash-chain re-verification of the persisted decision log.
    chained = load_jsonl(out_dir / "decision_log.jsonl")
    chain_problems = verify_chain(chained)

    # 7. Aggregate verdict.
    result = _aggregate(bundle, ledger, credentials, repro, enum,
                        impact, fullset, chain_problems)
    dump_json(result, out_dir / "RESULT.json")

    # 8. Human-facing report.
    (out_dir / "REPORT.md").write_text(_render_report(result),
                                       encoding="utf-8")

    # 9. Manifest over every artifact.
    present = [n for n in ARTIFACTS if (out_dir / n).is_file()]
    write_manifest(out_dir, present, out_dir / "MANIFEST.json")
    return result


def _aggregate(bundle, ledger, credentials, repro, enum, impact,
               fullset, chain_problems) -> dict[str, Any]:
    final_view, final_refusals = ledger.replay()
    acct = final_view.states.get("acct-7")

    approved = [c for c in credentials
                if c["verdict"]["decision"] == APPROVE]
    rejected = [c for c in credentials
                if c["verdict"]["decision"] != APPROVE]

    # Exactly one write should have been refused (the stale-generation
    # unfreeze); every refusal must name the offending seq.
    stale_refused_once = (len(final_refusals) == 1
                          and "stale generation" in final_refusals[0])

    checks = {
        "ledger_chain_verified": not chain_problems,
        "all_credentials_verify":
            all(c["verification"]["ok"] for c in credentials),
        "all_credentials_minimal":
            all(c.get("minimality", {}).get("minimal") for c in credentials),
        "all_tampering_rejected":
            all(all(t["rejected"] for t in c["tamper"])
                for c in credentials),
        "one_approval_one_rejection":
            len(approved) == 1 and len(rejected) == 1,
        "reproduction_all_checks_pass": repro["all_checks_pass"],
        "smallmodel_invariants_hold":
            enum.all_final_deactivated and enum.all_stale_refused
            and enum.all_effects_agree and enum.deterministic
            and bool(enum.durable_commit_always_present),
        "impact_checks_pass": all(impact.checks.values()),
        "impact_fullset_agrees": fullset["three_methods_agree"],
        "impact_total_60000": impact.total_records == 60_000,
        "final_account_deactivated":
            acct is not None and acct.status == DEACTIVATED,
        "stale_write_refused_once": stale_refused_once,
    }
    return {
        "tool": {"name": "govreview", "version": __version__,
                 "python": platform.python_version(),
                 "platform": platform.system()},
        "summary": {
            "incident": (
                "Concurrent unfreeze (T-1023) and deactivation both reported "
                "success; the durable log decides the winner."),
            "final_status": acct.status if acct else None,
            "final_generation": acct.generation if acct else None,
            "winner": "deactivation",
            "form_valid_unfreezes": len(approved),
            "rejected_decisions": len(rejected),
            "effective_impact_records": impact.affected_record_count,
            "effective_impact_partitions": impact.affected_partitions,
        },
        "checks": checks,
        "all_checks_pass": all(checks.values()),
        "decisions": {c["decision"]: {
            "form_decision": c["verdict"]["decision"],
            "primary_reason": _primary(c),
            "effect": c["effect"],
        } for c in credentials},
        "concurrency": {
            "checks": repro["checks"],
            "all_checks_pass": repro["all_checks_pass"],
            "step_trace": repro["step_trace"],
            "workers": repro["worker_outcomes"],
        },
        "smallmodel": enum.to_dict(),
        "impact": impact.to_dict(),
        "impact_fullset": fullset,
    }


def _primary(c: dict) -> str:
    from .authorization import _REASON_ORDER, OK
    codes = c["verdict"]["reason_codes"]
    if not codes:
        return OK
    return next((r for r in _REASON_ORDER if r in codes), codes[0])


def _render_report(result: dict[str, Any]) -> str:
    s = result["summary"]
    repro_checks = result["concurrency"]["checks"]
    enum = result["smallmodel"]
    impact = result["impact"]
    lines = []
    lines.append("# 离线安全复核 · 并发解冻/停用（13330）")
    lines.append("")
    lines.append("> 全部使用合成数据与本地文件；不接触任何真实账户。")
    lines.append(f"> 工具 govreview {result['tool']['version']} · Python "
                 f"{result['tool']['python']} · {result['tool']['platform']}")
    lines.append("")
    lines.append("## 结论")
    lines.append("")
    lines.append(f"- 最终生效：**{s['final_status']}** "
                 f"（代 {s['final_generation']}），胜出方 = **{s['winner']}**。")
    lines.append(f"- 形式合规（可获批准凭据）的解冻决定："
                 f"{s['form_valid_unfreezes']} 条；被拒决定："
                 f"{s['rejected_decisions']} 条。")
    lines.append(f"- 停用实际影响：{s['effective_impact_records']} 条记录，"
                 f"分区 {len(s['effective_impact_partitions'])} 个 "
                 f"（{', '.join(s['effective_impact_partitions'])}）。")
    lines.append("")
    lines.append("## 三项并发隐患（真实双线程 + 屏障）")
    lines.append("")
    lines.append("| 隐患 | 复现结果 |")
    lines.append("| --- | --- |")
    lines.append(f"| 停用抢先 | 停用先于解冻提交："
                 f"{'[PASS]' if repro_checks.get('deactivation_committed_first') else '[FAIL]'}"
                 f"，终态 {s['final_status']} |")
    lines.append("| 解冻已提交但调用方无回执 | "
                 f"committed={repro_checks.get('unfreeze_committed')}、"
                 f"回执未送达={repro_checks.get('receipt_not_delivered')}、"
                 f"无效果={repro_checks.get('unfreeze_had_no_effect')} |")
    lines.append("| 旧代同号异摘要 | 同号 T-1023、旧代、旧摘要 → "
                 f"代拒绝={repro_checks.get('stale_refused_generation')}、"
                 f"摘要拒绝={repro_checks.get('stale_refused_digest')} |")
    lines.append("")
    workers = result["concurrency"]["workers"]
    lines.append("真实线程：" + ", ".join(
        f"{w['thread_name']}#{w['thread_ident']}" for w in workers.values())
        + "（与主线程不同）")
    lines.append("")
    lines.append("## 逐决定判定")
    lines.append("")
    lines.append("| 决定 | 形式判定 | 首要原因 | 实际效果 |")
    lines.append("| --- | --- | --- | --- |")
    for d, info in result["decisions"].items():
        lines.append(f"| {d} | {info['form_decision']} | "
                     f"{info['primary_reason']} | {info['effect']} |")
    lines.append("")
    lines.append("## 小模型穷举（短交错）")
    lines.append("")
    lines.append(f"- 交错总数：{enum['total_interleavings']}；停用在先 "
                 f"{enum['deactivation_first']} 次，解冻在先 "
                 f"{enum['unfreeze_first']} 次。")
    lines.append("- 不变量：任意交错终态均为 DEACTIVATED="
                 f"{enum['invariant_all_final_deactivated']}；旧代尝试处处被拒="
                 f"{enum['invariant_all_stale_refused']}；模型与参考重放逐条一致="
                 f"{enum['invariant_model_matches_reference']}；可复现="
                 f"{enum['deterministic']}。")
    lines.append("")
    lines.append("## 60,000 条分区记录核对")
    lines.append("")
    lines.append(f"- 总量：{impact['total_records']}；分区总数："
                 f"{len(impact['partition_counts'])}。")
    lines.append(f"- 增量法与全量扫描一致："
                 f"{impact['checks'].get('incremental_matches_full_scan')}；"
                 f"三套算法一致：{result['impact_fullset']['three_methods_agree']}。")
    lines.append(f"- 按组织分区计数：{impact['org_partition_totals']}")
    lines.append("")
    lines.append("## 检查项")
    lines.append("")
    for name, ok in result["checks"].items():
        lines.append(f"- {'[PASS]' if ok else '[FAIL]'} `{name}`")
    lines.append("")
    lines.append(f"**总体：{'通过' if result['all_checks_pass'] else '未通过'}**")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def cmd_demo(out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp_inputs = out_dir / "_inputs_tmp"
    tmp_inputs.mkdir(parents=True, exist_ok=True)
    generate_inputs(tmp_inputs)
    result = analyze_bundle(tmp_inputs, out_dir)
    result["inputs"] = {
        "physical_sha256": physical_digests(out_dir),
        "logical": logical_digests(out_dir),
    }
    # tmp_inputs duplicates the copied inputs; drop it after the run.
    import shutil as _sh
    _sh.rmtree(tmp_inputs, ignore_errors=True)
    dump_json(result, out_dir / "RESULT.json")
    present = [n for n in ARTIFACTS if (out_dir / n).is_file()]
    write_manifest(out_dir, present, out_dir / "MANIFEST.json")
    return 0 if result["all_checks_pass"] else 1


def cmd_verify(in_dir: Path, out_dir: Path | None) -> int:
    """Re-verify an existing artifact set *without rebuilding it*.

    The manifest is checked **before** any analysis, so a tampered artifact is
    reported rather than silently regenerated over.  We also re-run the analysis
    in a scratch dir and compare its result to the stored ``RESULT.json`` to
    confirm the records still reconstruct the same verdict.
    """
    if out_dir is None:
        out_dir = in_dir.parent
    manifest_path = out_dir / "MANIFEST.json"
    if not manifest_path.is_file():
        print(f"verify: no MANIFEST.json in {out_dir}", file=sys.stderr)
        return 2
    ok, problems = verify_manifest(out_dir, manifest_path)
    if not ok:
        print("verify: manifest mismatch, artifacts were altered:",
              file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    # Hashes are intact: re-run in a scratch directory and compare verdicts.
    import tempfile
    with tempfile.TemporaryDirectory() as scratch:
        scratch = Path(scratch)
        rerun = analyze_bundle(out_dir, scratch)
        stored = json.loads(
            (out_dir / "RESULT.json").read_text(encoding="utf-8"))
        agree = (rerun["summary"] == stored["summary"]
                 and rerun["checks"] == stored["checks"])
        if not agree:
            print("verify: fresh analysis disagrees with stored RESULT.json",
                  file=sys.stderr)
            return 1
    print(f"verify: OK — manifest intact and analysis reproduces "
          f"({len(stored.get('checks', {}))} checks, "
          f"all_checks_pass={stored.get('all_checks_pass')})")
    return 0 if stored.get("all_checks_pass") else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="govreview",
                                     description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_demo = sub.add_parser("demo", help="generate synthetic inputs and review")
    p_demo.add_argument("--out", default="artifacts/demo")
    p_verify = sub.add_parser("verify", help="re-run and re-check an existing set")
    p_verify.add_argument("--in", dest="in_dir", required=True)
    p_verify.add_argument("--out", default=None)
    args = parser.parse_args(argv)

    if args.cmd == "demo":
        out = Path(args.out)
        return cmd_demo(out)
    if args.cmd == "verify":
        out = Path(args.out) if args.out else None
        return cmd_verify(Path(args.in_dir), out)
    return 2


if __name__ == "__main__":
    sys.exit(main())
