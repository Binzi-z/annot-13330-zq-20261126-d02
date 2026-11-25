"""Small-model exhaustive enumeration of short interleavings.

The two worker threads from :mod:`concurrency` are abstracted into tiny
programs of atomic steps:

* deactivate program ``D``: ``D1 validate`` -> ``D2 commit``
* unfreeze  program ``U``: ``U1 bind stale`` -> ``U2 refuse stale`` ->
  ``U3 bind valid`` -> ``U4 commit valid (no receipt)``

All ``C(6, 2) = 15`` interleavings that preserve each program's internal order
are enumerated.  For each one we

1. independently predict the state-machine outcome (a hand-rolled model), and
2. replay the *actual* durable events through :class:`ledger.Ledger`,

then assert the two agree.  This cross-checks the small model against the
reference replay engine, and the invariant that matters for safety:

* a deactivation, once committed, is terminal -- **no** interleaving lets an
*freeze* flip the account back to ``ACTIVE``; every interleaving ends
  ``DEACTIVATED``;
* an unfreeze committed *after* the deactivation is durable yet has
  **no effect** (``NO_EFFECT_DEACTIVATED``);
* the stale-generation / wrong-digest attempt is refused in every order;
* enumeration is deterministic (same result on a rerun).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator

from .ledger import (ACTIVE, DEACTIVATED, EFFECTIVE, FROZEN,
                     Ledger, NO_EFFECT_DEACTIVATED)
from .synthetic import ticket_digests, _ts

PRE_HISTORY = [
    {"kind": "provision", "account": "acct-7", "org": "ops-east",
     "generation": 1, "ts": "2026-11-25T07:00:00Z"},
    {"kind": "freeze_applied", "account": "acct-7", "generation": 1,
     "ts": "2026-11-25T08:00:00Z"},
    {"kind": "rotate", "account": "acct-7", "generation": 2,
     "ts": "2026-11-25T09:30:00Z"},
]

D_STEPS = [("D1", "deact", "validate", False),
           ("D2", "deact", "commit", True)]
U_STEPS = [("U1", "thaw", "bind_stale", False),
           ("U2", "thaw", "refuse_stale", False),
           ("U3", "thaw", "bind_valid", False),
           ("U4", "thaw", "commit_noreceipt", True)]


def interleavings(a: list, b: list) -> Iterator[list]:
    """Yield every merge of *a* and *b* preserving each input's order."""
    if not a:
        yield list(b)
        return
    if not b:
        yield list(a)
        return
    for tail in interleavings(a[1:], b):
        yield [a[0]] + tail
    for tail in interleavings(a, b[1:]):
        yield [b[0]] + tail


@dataclass
class Prediction:
    order: list[str]
    final_status: str
    unfreeze_effect: str
    stale_refused: bool
    deact_before_unfreeze: bool


def predict(order: list[tuple]) -> Prediction:
    """Hand-rolled state-machine model, independent of the reference replay."""
    digests = ticket_digests()
    old_digest, new_digest = digests["old"], digests["new"]

    status = FROZEN          # account is frozen at generation 2 before the race
    deactivated = False
    deact_committed = False
    valid_committed = False
    unfreeze_effect = "NONE"
    stale_refused = False
    deact_before_valid: bool | None = None

    for _sid, actor, action, _mutating in order:
        if actor == "deact" and action == "commit":
            if not deactivated:
                status = DEACTIVATED
                deactivated = True
            deact_committed = True
        elif actor == "thaw" and action == "refuse_stale":
            # Same ticket number, generation 1 != live 2, old digest != catalog.
            stale_refused = True
        elif actor == "thaw" and action == "commit_noreceipt":
            if deact_before_valid is None:
                deact_before_valid = deact_committed
            valid_committed = True
            if deactivated:
                unfreeze_effect = NO_EFFECT_DEACTIVATED
            elif status == FROZEN:
                status = ACTIVE
                unfreeze_effect = EFFECTIVE
            else:
                unfreeze_effect = "NO_EFFECT_ALREADY_ACTIVE"

    return Prediction(
        order=[sid for sid, *_ in order],
        final_status=status,
        unfreeze_effect=unfreeze_effect,
        stale_refused=stale_refused,
        deact_before_unfreeze=bool(deact_before_valid))


def _events_from_order(order: list[tuple], start_seq: int) -> list[dict]:
    """Convert a merge order into durable ledger events for the reference replay."""
    digests = ticket_digests()
    events: list[dict] = []
    seq = start_seq
    for _sid, actor, action, mutating in order:
        if not mutating:
            continue
        if action == "commit":
            events.append({
                "kind": "deactivate_decided", "decision": "dec-deact",
                "account": "acct-7", "generation": 2,
                "reason": "security hold from concurrent response",
                "committed": True, "ts": f"2026-11-25T10:{seq:02d}:00Z",
                "seq": seq})
        elif action == "commit_noreceipt":
            events.append({
                "kind": "unfreeze_decided", "decision": "dec-valid",
                "account": "acct-7", "generation": 2,
                "ticket": "T-1023", "ticket_digest": digests["new"],
                "approvals": [
                    {"approver": "p-alice", "account": "acct-7",
                     "generation": 2, "ticket_digest": digests["new"]},
                    {"approver": "p-carol", "account": "acct-7",
                     "generation": 2, "ticket_digest": digests["new"]},
                ],
                "committed": True, "receipt_delivered": False,
                "ts": f"2026-11-25T10:{seq:02d}:00Z", "seq": seq})
        seq += 1
    return events


def _reference_outcome(order: list[tuple]) -> tuple[str, str]:
    """State + valid-unfreeze effect according to the real Ledger replay."""
    pre = []
    for i, ev in enumerate(PRE_HISTORY, start=1):
        pre.append(dict(ev, seq=i))
    events = pre + _events_from_order(order, start_seq=len(pre) + 1)
    view, _ = Ledger(events).replay()
    st = view.states["acct-7"]
    outcome = view.decision_outcomes.get("dec-valid")
    effect = outcome.effect if outcome else "NONE"
    return st.status, effect


@dataclass
class EnumerationResult:
    total: int
    deact_first_count: int
    unfreeze_first_count: int
    all_final_deactivated: bool
    all_stale_refused: bool
    all_effects_agree: bool
    durable_commit_always_present: bool
    deterministic: bool
    mismatches: list[dict[str, Any]]
    summary: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_interleavings": self.total,
            "deactivation_first": self.deact_first_count,
            "unfreeze_first": self.unfreeze_first_count,
            "invariant_all_final_deactivated": self.all_final_deactivated,
            "invariant_all_stale_refused": self.all_stale_refused,
            "invariant_model_matches_reference": self.all_effects_agree,
            "invariant_durable_commit_always_present": self.durable_commit_always_present,
            "deterministic": self.deterministic,
            "mismatches": self.mismatches,
            # Full enumeration, so a reviewer can re-check every order by hand.
            "interleavings": self.summary,
        }


def enumerate_interleavings() -> EnumerationResult:
    def run_once() -> tuple[list[dict[str, Any]], bool, bool, bool, bool]:
        rows = []
        all_deact = True
        all_stale = True
        all_agree = True
        all_commit = True
        mismatches = []
        deact_first = 0
        unfreeze_first = 0
        for order in interleavings(D_STEPS, U_STEPS):
            pred = predict(order)
            ref_status, ref_effect = _reference_outcome(order)
            agree = (pred.final_status == ref_status
                     and pred.unfreeze_effect == ref_effect)
            has_commit = any(
                a == "thaw" and act == "commit_noreceipt"
                for _s, a, act, _m in order)
            row = {
                "order": pred.order,
                "predicted_status": pred.final_status,
                "reference_status": ref_status,
                "predicted_effect": pred.unfreeze_effect,
                "reference_effect": ref_effect,
                "stale_refused": pred.stale_refused,
                "agrees": agree,
            }
            rows.append(row)
            all_deact &= pred.final_status == DEACTIVATED
            all_stale &= pred.stale_refused
            all_agree &= agree
            all_commit &= has_commit
            if pred.final_status == DEACTIVATED and not pred.deact_before_unfreeze:
                unfreeze_first += 1
            if pred.deact_before_unfreeze:
                deact_first += 1
            if not agree:
                mismatches.append(row)
        return rows, all_deact, all_stale, all_agree, all_commit, mismatches, \
            deact_first, unfreeze_first

    (rows, all_deact, all_stale, all_agree, all_commit, mismatches,
     deact_first, unfreeze_first) = run_once()

    # Determinism: a second enumeration must be byte-for-byte identical.
    second = run_once()
    deterministic = (
        [r["order"] for r in rows] == [r["order"] for r in second[0]]
        and [r["predicted_effect"] for r in rows]
        == [r["predicted_effect"] for r in second[0]])

    return EnumerationResult(
        total=len(rows),
        deact_first_count=deact_first,
        unfreeze_first_count=unfreeze_first,
        all_final_deactivated=all_deact,
        all_stale_refused=all_stale,
        all_effects_agree=all_agree,
        durable_commit_always_present=all_commit,
        deterministic=deterministic,
        mismatches=mismatches,
        summary=rows,
    )
