"""Reproduce the incident with two *real* worker threads and barriers.

Two genuine ``threading.Thread`` objects -- a deactivation operator and an
unfreeze operator -- race over a lock-protected durable decision log.  Two
``threading.Barrier`` objects make the reproduction deterministic:

* ``start`` -- both workers must be alive before either acts (real overlap);
* ``gate``  -- the deactivation commits *before* it reaches the gate and the
  unfreeze waits at the gate before its valid commit, so the deactivation is
  provably committed first.

The single race run demonstrates all three hazards together:

1. **deactivation wins** -- the committed deactivation precedes the committed
   unfreeze, and replay shows the account ends ``DEACTIVATED``;
2. **committed, no receipt** -- the unfreeze is durably committed
   (``committed=True``) but the caller's receipt channel is severed
   (``receipt_delivered=False``), so the caller "saw nothing";
3. **old generation, same number, different digest** -- the thaw operator
   first presents ticket ``T-1023`` bound to generation 1 with the *old* body
   digest, while the catalog now holds the reissued body under the *same
   number*.  The store refuses it with ``STALE_GENERATION`` and
   ``TICKET_DIGEST_MISMATCH``.

The captured durable events are then replayed with the ordinary ledger engine,
proving the tool can reconstruct the winner from local files alone.  The small
model (``smallmodel.py``) exhaustively enumerates *every* short interleaving of
the same two programs, so the barrier run is one sample of a fully checked
space, not a lucky execution.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from .ledger import DEACTIVATED, Ledger, NO_EFFECT_DEACTIVATED, EFFECTIVE
from .synthetic import ticket_digests, _ts


class ReceiptDropped(Exception):
    """Raised when the caller's response channel is lost after the commit."""


@dataclass
class StepRecord:
    order: int
    actor: str
    action: str
    thread_ident: int
    thread_name: str


class DecisionStore:
    """A minimal, real, lock-protected append-only decision store."""

    def __init__(self, live_generation: int, catalog_digest: str):
        self.lock = threading.Lock()
        self.live_generation = live_generation
        self.catalog_digest = catalog_digest
        self.events: list[dict[str, Any]] = []
        self.refusals: list[dict[str, Any]] = []
        self.trace: list[StepRecord] = []

    def _step(self, actor: str, action: str) -> None:
        # Caller holds the lock.
        self.trace.append(StepRecord(
            order=len(self.trace) + 1, actor=actor, action=action,
            thread_ident=threading.get_ident(),
            thread_name=threading.current_thread().name))

    def commit_deactivate(self, decision: str, account: str, generation: int,
                          reason: str) -> None:
        with self.lock:
            self._step("deact", "commit")
            self.events.append({
                "kind": "deactivate_decided", "decision": decision,
                "account": account, "generation": generation,
                "reason": reason, "committed": True,
            })

    def refuse_stale(self, actor: str, ticket: str, attempt_generation: int,
                     attempt_digest: str) -> list[str]:
        reasons: list[str] = []
        with self.lock:
            self._step(actor, "stale_attempt")
            if attempt_generation != self.live_generation:
                reasons.append("STALE_GENERATION")
            if attempt_digest != self.catalog_digest:
                reasons.append("TICKET_DIGEST_MISMATCH")
            self.refusals.append({
                "actor": actor, "ticket": ticket,
                "attempt_generation": attempt_generation,
                "attempt_digest": attempt_digest,
                "live_generation": self.live_generation,
                "catalog_digest": self.catalog_digest,
                "reasons": reasons,
            })
        return reasons

    def commit_unfreeze(self, decision: str, account: str, generation: int,
                        ticket: str, ticket_digest: str,
                        approvals: list[dict],
                        receipt_delivered: bool) -> dict[str, Any]:
        with self.lock:
            self._step("thaw", "valid_commit")
            event = {
                "kind": "unfreeze_decided", "decision": decision,
                "account": account, "generation": generation,
                "ticket": ticket, "ticket_digest": ticket_digest,
                "approvals": approvals, "committed": True,
                "receipt_delivered": receipt_delivered,
            }
            self.events.append(event)
            return event


@dataclass
class WorkerOutcome:
    actor: str
    thread_ident: int
    thread_name: str
    stale_refusal: list[str] = field(default_factory=list)
    receipt_dropped: bool = False
    error: str | None = None


def _deactivate_worker(store: DecisionStore, start: threading.Barrier,
                       gate: threading.Barrier, out: dict[str, WorkerOutcome],
                       account: str, generation: int) -> None:
    try:
        start.wait(timeout=10)
        with store.lock:
            store._step("deact", "validate")
        store.commit_deactivate(
            decision="dec-deact", account=account, generation=generation,
            reason="security hold from concurrent response")
        # Committed *before* reaching the gate: it is provably first.
        gate.wait(timeout=10)
        out["deact"] = WorkerOutcome(
            actor="deact", thread_ident=threading.get_ident(),
            thread_name=threading.current_thread().name)
    except threading.BrokenBarrierError as exc:
        out["deact"] = WorkerOutcome(
            actor="deact", thread_ident=threading.get_ident(),
            thread_name=threading.current_thread().name,
            error=f"barrier broken: {exc}")
        _abort(start, gate)


def _thaw_worker(store: DecisionStore, start: threading.Barrier,
                 gate: threading.Barrier, out: dict[str, WorkerOutcome],
                 account: str, generation: int, ticket: str,
                 old_digest: str, new_digest: str,
                 approvals: list[dict]) -> None:
    res = WorkerOutcome(actor="thaw", thread_ident=threading.get_ident(),
                        thread_name=threading.current_thread().name)
    out["thaw"] = res
    try:
        start.wait(timeout=10)
        with store.lock:
            store._step("thaw", "bind_stale")
        # Hazard 3: same ticket number, old generation, old digest.
        res.stale_refusal = store.refuse_stale(
            actor="thaw", ticket=ticket, attempt_generation=1,
            attempt_digest=old_digest)
        # Wait at the gate *before* the valid commit, so the deactivation is
        # already durable when we proceed.
        gate.wait(timeout=10)
        with store.lock:
            store._step("thaw", "bind_valid")
        store.commit_unfreeze(
            decision="dec-valid", account=account, generation=generation,
            ticket=ticket, ticket_digest=new_digest, approvals=approvals,
            receipt_delivered=False)  # the decision is durable ...
        # ... but the caller's response channel is already severed.
        res.receipt_dropped = True
        raise ReceiptDropped("response channel lost after durable commit")
    except ReceiptDropped:
        pass  # the *caller* sees an error; the durable log keeps the commit
    except threading.BrokenBarrierError as exc:
        res.error = f"barrier broken: {exc}"
        _abort(start, gate)


def _abort(*barriers: threading.Barrier) -> None:
    """Break any barrier still waiting so a failed peer cannot deadlock the run."""
    for b in barriers:
        try:
            b.abort()
        except Exception:
            pass


def _setup_events(account: str, org: str) -> list[dict]:
    """Deterministic pre-race history: prove -> freeze(gen1) -> rotate(gen2)."""
    return [
        {"seq": 1, "ts": _ts(7, 0, 0), "kind": "provision",
         "account": account, "org": org, "generation": 1},
        {"seq": 2, "ts": _ts(8, 0, 0), "kind": "freeze_applied",
         "account": account, "generation": 1},
        {"seq": 3, "ts": _ts(9, 30, 0), "kind": "rotate",
         "account": account, "generation": 2},
    ]


def run_reproduction(account: str = "acct-7", org: str = "ops-east") -> dict[str, Any]:
    """Run the barrier-synchronised two-thread reproduction; return evidence."""
    digests = ticket_digests()
    old_digest, new_digest = digests["old"], digests["new"]
    live_generation = 2

    store = DecisionStore(live_generation=live_generation,
                          catalog_digest=new_digest)
    start = threading.Barrier(2)
    gate = threading.Barrier(2)
    outcomes: dict[str, WorkerOutcome] = {}
    errors: list[BaseException] = []

    approvals = [
        {"approver": "p-alice", "account": account,
         "generation": live_generation, "ticket_digest": new_digest},
        {"approver": "p-carol", "account": account,
         "generation": live_generation, "ticket_digest": new_digest},
    ]

    d = threading.Thread(name="worker-deactivate", target=_wrap(
        _deactivate_worker, errors), args=(
            store, start, gate, outcomes, account, live_generation), daemon=True)
    t = threading.Thread(name="worker-unfreeze", target=_wrap(
        _thaw_worker, errors), args=(
            store, start, gate, outcomes, account, live_generation,
            "T-1023", old_digest, new_digest, approvals), daemon=True)

    d.start()
    t.start()
    d.join(timeout=15)
    t.join(timeout=15)
    alive = [w.name for w in (d, t) if w.is_alive()]
    if alive:
        raise RuntimeError(f"reproduction workers did not finish: {alive}")

    # Assemble the durable ledger: setup + race commits (in real commit order) +
    # the two caller reports.
    pre = _setup_events(account, org)
    race = list(store.events)
    posts = [
        {"kind": "report", "ticket": "T-1023", "reported_by": "p-amber",
         "claimed": "success"},
        {"kind": "report", "ticket": "T-1023", "reported_by": "p-bob",
         "claimed": "success"},
    ]
    raw = pre + race + posts
    # Deterministic presentation timestamps by seat; seq is the real order.
    timestamps = ["10:05", "10:10", "10:11", "10:12"]
    ledger_events: list[dict] = []
    for i, ev in enumerate(raw, start=1):
        ev = dict(ev)
        ev["seq"] = i
        if i <= 3:
            ev["ts"] = _setup_events(account, org)[i - 1]["ts"]
        else:
            minute = timestamps[min(i - 4, len(timestamps) - 1)]
            ev["ts"] = f"2026-11-25T{minute}:00Z"
        ledger_events.append(ev)

    ledger = Ledger(ledger_events)
    view, refusals = ledger.replay()
    state = view.states.get(account)
    outcome_deact = view.decision_outcomes.get("dec-deact")
    outcome_valid = view.decision_outcomes.get("dec-valid")

    deact_seq = next(e["seq"] for e in ledger_events
                     if e["kind"] == "deactivate_decided")
    valid_seq = next(e["seq"] for e in ledger_events
                     if e["kind"] == "unfreeze_decided")
    valid_event = next(e for e in ledger_events
                       if e["kind"] == "unfreeze_decided")

    stale = store.refusals[0] if store.refusals else None
    checks = {
        "two_distinct_real_threads":
            len({o.thread_ident for o in outcomes.values()}) == 2
            and all(o.thread_ident != threading.main_thread().ident
                    for o in outcomes.values()),
        "deactivation_committed_first": deact_seq < valid_seq,
        "final_status_deactivated": state.status == DEACTIVATED,
        "deactivation_effective":
            outcome_deact is not None and outcome_deact.effect == EFFECTIVE,
        "unfreeze_committed": valid_event["committed"] is True,
        "receipt_not_delivered": valid_event["receipt_delivered"] is False,
        "unfreeze_had_no_effect": outcome_valid is not None
            and outcome_valid.effect == NO_EFFECT_DEACTIVATED,
        "stale_attempt_refused": stale is not None,
        "stale_refused_generation":
            stale is not None and "STALE_GENERATION" in stale["reasons"],
        "stale_refused_digest":
            stale is not None and "TICKET_DIGEST_MISMATCH" in stale["reasons"],
        "same_ticket_number_two_digests":
            stale is not None
            and stale["ticket"] == valid_event["ticket"]
            and stale["attempt_digest"] != valid_event["ticket_digest"],
    }

    return {
        "account": account,
        "ledger_events": ledger_events,
        "worker_outcomes": {
            k: {"actor": o.actor, "thread_ident": o.thread_ident,
                "thread_name": o.thread_name,
                "stale_refusal": o.stale_refusal,
                "receipt_dropped": o.receipt_dropped, "error": o.error}
            for k, o in outcomes.items()},
        "worker_errors": [repr(e) for e in errors],
        "step_trace": [
            {"order": s.order, "actor": s.actor, "action": s.action,
             "thread_ident": s.thread_ident, "thread_name": s.thread_name}
            for s in store.trace],
        "stale_attempt": stale,
        "replay": {
            "watermark": view.watermark,
            "final_status": state.status,
            "final_generation": state.generation,
            "refusals": refusals,
            "anomalies": view.anomalies,
            "decisions": {d: o.to_dict()
                          for d, o in sorted(view.decision_outcomes.items())},
        },
        "checks": checks,
        "all_checks_pass": all(checks.values()),
    }


def _wrap(fn, errors):
    def inner(*a, **kw):
        try:
            fn(*a, **kw)
        except BaseException as exc:  # surface, never swallow the harness
            errors.append(exc)
            raise
    return inner


def thread_ids_are_real(repro: dict[str, Any]) -> bool:
    """True when both workers ran on distinct, non-main OS threads."""
    outcomes = repro.get("worker_outcomes", {})
    idents = {o["thread_ident"] for o in outcomes.values()}
    names = {o["thread_name"] for o in outcomes.values()}
    return (len(outcomes) == 2 and len(idents) == 2
            and all(i != threading.main_thread().ident for i in idents)
            and len(names) == 2)
