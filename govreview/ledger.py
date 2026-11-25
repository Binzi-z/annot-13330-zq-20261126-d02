"""Append-only decision ledger and per-watermark replay.

The physical log is append-only: every event carries ``seq`` (strictly
increasing), ``ts`` and ``kind``.  Replay folds events up to any ``seq``
watermark into an authorization/operational state, so the successor on-call can
reconstruct exactly what was authorized -- and what actually took effect -- at
*each* historical watermark, instead of trusting whichever ticket reported
success.

Accounts move through::

    ACTIVE --freeze_applied--> FROZEN --unfreeze_decided(valid)--> ACTIVE
    any --deactivate_decided--> DEACTIVATED          (terminal)

Rules enforced during replay:

* ``unfreeze_decided`` / ``deactivate_decided`` may only target the *current*
  generation; a stale-epoch write is refused and recorded as an anomaly (never
  silently retargeted).
* An **unfreeze committed after a deactivation** is *authorized in form* (the
  approvals may be impeccable) but has **no effect**: the deactivation is
  terminal.  The decision is still recorded, with ``effective = false``; this
  is precisely how "reported success" and "actually in effect" diverge.
* A rotation only moves forward and leaves any freeze bound to the stale epoch.

``report`` events are caller-facing claims only; they never mutate state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canon import digest_of

ACTIVE = "ACTIVE"
FROZEN = "FROZEN"
DEACTIVATED = "DEACTIVATED"

# Why an authorized unfreeze may still not have taken effect.
EFFECTIVE = "EFFECTIVE"
NO_EFFECT_ALREADY_ACTIVE = "NO_EFFECT_ALREADY_ACTIVE"
NO_EFFECT_DEACTIVATED = "NO_EFFECT_DEACTIVATED"
NOT_APPLIED_STALE = "NOT_APPLIED_STALE"
NOT_COMMITTED = "NOT_COMMITTED"


class LedgerError(RuntimeError):
    """Structural ledger problem (e.g. non-monotone seq)."""


@dataclass
class DeactivateRecord:
    seq: int
    decision: str
    reason: str
    committed: bool


@dataclass
class UnfreezeRecord:
    seq: int
    decision: str
    ticket: str
    ticket_digest: str
    approvals: list[dict]
    committed: bool
    receipt_delivered: bool


@dataclass
class DecisionOutcome:
    """Per-decision effect record reconstructed during replay."""
    decision: str
    account: str
    generation: int
    seq: int
    committed: bool
    status_before: str
    status_after: str
    effect: str            # EFFECTIVE / NO_EFFECT_* / NOT_APPLIED_STALE / NOT_COMMITTED
    receipt_delivered: bool | None = None

    @property
    def effective(self) -> bool:
        return self.effect == EFFECTIVE

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision, "account": self.account,
            "generation": self.generation, "seq": self.seq,
            "committed": self.committed, "status_before": self.status_before,
            "status_after": self.status_after, "effect": self.effect,
            "effective": self.effective,
            "receipt_delivered": self.receipt_delivered,
        }


@dataclass
class AcctState:
    account: str
    org: str | None = None
    status: str = ACTIVE
    generation: int = 0
    generations: set[int] = field(default_factory=set)
    last_rotation_seq: int | None = None
    status_seq: int | None = None
    freeze_current_seq: int | None = None
    last_unfreeze: UnfreezeRecord | None = None
    deactivation: DeactivateRecord | None = None
    anomalies: list[str] = field(default_factory=list)

    def clone(self) -> "AcctState":
        return AcctState(
            account=self.account, org=self.org, status=self.status,
            generation=self.generation, generations=set(self.generations),
            last_rotation_seq=self.last_rotation_seq,
            status_seq=self.status_seq, freeze_current_seq=self.freeze_current_seq,
            last_unfreeze=self.last_unfreeze, deactivation=self.deactivation,
            anomalies=list(self.anomalies),
        )


@dataclass
class LedgerView:
    watermark: int
    states: dict[str, AcctState]
    events: list[dict[str, Any]]
    anomalies: list[str]
    decision_outcomes: dict[str, DecisionOutcome] = field(default_factory=dict)

    def state(self, account: str) -> AcctState | None:
        return self.states.get(account)


def _event_key(event: dict) -> str:
    return digest_of({k: v for k, v in event.items() if k != "hash"})


def chain_hashes(events: list[dict]) -> list[dict]:
    """Return copies with a verifiable forward hash chain.

    ``hash = sha256(prev_hash || canonical(event-without-hash))``.  Persisted so
    a successor can re-verify the local log was not rewritten between runs.
    """
    out: list[dict] = []
    prev = "sha256:" + "0" * 64
    for ev in events:
        rec = dict(ev)
        rec["hash"] = digest_of({"prev": prev, "event": _event_key(ev)})
        out.append(rec)
        prev = rec["hash"]
    return out


def verify_chain(events: list[dict]) -> list[str]:
    """Re-verify a hash-chained log; return a list of problems (empty = good)."""
    problems: list[str] = []
    prev = "sha256:" + "0" * 64
    for i, ev in enumerate(events):
        expected = digest_of({"prev": prev, "event": _event_key(ev)})
        if ev.get("hash") != expected:
            problems.append(f"event {i} (seq {ev.get('seq')}): hash chain break")
        prev = ev.get("hash")
    return problems


class Ledger:
    """Wraps the validated event list and provides watermark replay."""

    def __init__(self, events: list[dict[str, Any]]):
        self.events = events
        self._seqs = [e["seq"] for e in events]
        if any(b <= a for a, b in zip(self._seqs, self._seqs[1:])):
            raise LedgerError("ledger seq must be strictly increasing")

    def watermarks(self) -> list[int]:
        return list(self._seqs)

    def replay(self, watermark: int | None = None,
               strict: bool = True) -> tuple[LedgerView, list[str]]:
        if watermark is None:
            watermark = self._seqs[-1]
        states: dict[str, AcctState] = {}
        anomalies: list[str] = []
        refusals: list[str] = []
        events: list[dict] = []
        outcomes: dict[str, DecisionOutcome] = {}

        for ev in self.events:
            if ev["seq"] > watermark:
                break
            events.append(ev)
            kind = ev["kind"]

            if kind == "provision":
                st = states.get(ev["account"])
                if st is None:
                    st = AcctState(account=ev["account"])
                    states[ev["account"]] = st
                st.org = ev["org"]
                gen = ev["generation"]
                st.generations.add(gen)
                st.generation = max(st.generation, gen)
                if st.status == DEACTIVATED:
                    anomalies.append(
                        f"seq {ev['seq']}: provision of deactivated account "
                        f"{st.account} did not revive it")
                else:
                    st.status = ACTIVE
                    st.status_seq = ev["seq"]
                continue

            if kind == "report":
                # Caller-facing claims only; they touch no state and carry no
                # account field, so handle them before the account lookup.
                continue

            st = states.get(ev["account"])
            if st is None:
                refusals.append(f"seq {ev['seq']}: {kind} for unprovisioned "
                                f"account {ev['account']}")
                if strict:
                    continue
                st = AcctState(account=ev["account"])
                states[ev["account"]] = st

            if kind == "freeze_applied":
                gen = ev["generation"]
                if gen != st.generation:
                    msg = (f"seq {ev['seq']}: freeze_applied bound to stale "
                           f"generation {gen} (current {st.generation}) on "
                           f"{st.account}")
                    anomalies.append(msg)
                    refusals.append(msg)
                    continue
                if st.status == DEACTIVATED:
                    anomalies.append(
                        f"seq {ev['seq']}: freeze_applied on deactivated "
                        f"{st.account} ignored")
                    continue
                st.status = FROZEN
                st.status_seq = ev["seq"]
                st.freeze_current_seq = ev["seq"]
                continue

            if kind == "rotate":
                gen = ev["generation"]
                if gen <= st.generation:
                    msg = (f"seq {ev['seq']}: rotation to generation {gen} "
                           f"not after current {st.generation} on {st.account}")
                    anomalies.append(msg)
                    refusals.append(msg)
                    continue
                st.generations.add(gen)
                st.generation = gen
                st.last_rotation_seq = ev["seq"]
                if st.status == FROZEN:
                    anomalies.append(
                        f"seq {ev['seq']}: rotation while frozen moved "
                        f"{st.account} to generation {gen}; freeze is now stale")
                continue

            if kind == "unfreeze_decided":
                decision = ev["decision"]
                gen = ev["generation"]
                before = st.status
                if not ev["committed"]:
                    outcomes[decision] = DecisionOutcome(
                        decision, st.account, gen, ev["seq"], False, before,
                        before, NOT_COMMITTED, ev.get("receipt_delivered"))
                    continue
                if gen != st.generation:
                    msg = (f"seq {ev['seq']}: unfreeze '{decision}' bound to "
                           f"stale generation {gen} (current {st.generation}) "
                           f"on {st.account}; refused")
                    anomalies.append(msg)
                    refusals.append(msg)
                    outcomes[decision] = DecisionOutcome(
                        decision, st.account, gen, ev["seq"], True, before,
                        before, NOT_APPLIED_STALE, ev.get("receipt_delivered"))
                    continue
                if st.status == DEACTIVATED:
                    msg = (f"seq {ev['seq']}: unfreeze '{decision}' committed "
                           f"but {st.account} already deactivated at seq "
                           f"{st.deactivation.seq if st.deactivation else '?'}; "
                           f"no effect (deactivation is terminal)")
                    anomalies.append(msg)
                    outcomes[decision] = DecisionOutcome(
                        decision, st.account, gen, ev["seq"], True, before,
                        before, NO_EFFECT_DEACTIVATED, ev.get("receipt_delivered"))
                    st.last_unfreeze = UnfreezeRecord(
                        ev["seq"], decision, ev["ticket"], ev["ticket_digest"],
                        ev.get("approvals") or [], True,
                        ev.get("receipt_delivered", False))
                    continue
                if st.status == ACTIVE:
                    outcomes[decision] = DecisionOutcome(
                        decision, st.account, gen, ev["seq"], True, before,
                        before, NO_EFFECT_ALREADY_ACTIVE, ev.get("receipt_delivered"))
                    continue
                # FROZEN at the live generation: the thaw applies.
                st.status = ACTIVE
                st.status_seq = ev["seq"]
                st.last_unfreeze = UnfreezeRecord(
                    ev["seq"], decision, ev["ticket"], ev["ticket_digest"],
                    ev.get("approvals") or [], True,
                    ev.get("receipt_delivered", False))
                outcomes[decision] = DecisionOutcome(
                    decision, st.account, gen, ev["seq"], True, before,
                    st.status, EFFECTIVE, ev.get("receipt_delivered"))
                continue

            if kind == "deactivate_decided":
                decision = ev["decision"]
                gen = ev["generation"]
                before = st.status
                if not ev["committed"]:
                    outcomes[decision] = DecisionOutcome(
                        decision, st.account, gen, ev["seq"], False, before,
                        before, NOT_COMMITTED)
                    continue
                if gen != st.generation:
                    msg = (f"seq {ev['seq']}: deactivation '{decision}' bound "
                           f"to stale generation {gen} (current {st.generation}) "
                           f"on {st.account}; refused")
                    anomalies.append(msg)
                    refusals.append(msg)
                    outcomes[decision] = DecisionOutcome(
                        decision, st.account, gen, ev["seq"], True, before,
                        before, NOT_APPLIED_STALE)
                    continue
                if st.status == DEACTIVATED:
                    anomalies.append(
                        f"seq {ev['seq']}: redundant deactivation '{decision}' "
                        f"on {st.account}")
                st.status = DEACTIVATED
                st.status_seq = ev["seq"]
                st.deactivation = DeactivateRecord(
                    seq=ev["seq"], decision=decision, reason=ev["reason"],
                    committed=True)
                outcomes[decision] = DecisionOutcome(
                    decision, st.account, gen, ev["seq"], True, before,
                    st.status, EFFECTIVE)
                continue

        view = LedgerView(watermark=watermark, states=states, events=events,
                          anomalies=anomalies, decision_outcomes=outcomes)
        return view, refusals

    def view_before_seq(self, seq: int) -> LedgerView:
        prior = [s for s in self._seqs if s < seq]
        return self.replay(prior[-1] if prior else 0)[0]

    def replay_all(self, strict: bool = True) -> dict[int, tuple[LedgerView, list[str]]]:
        return {wm: self.replay(wm, strict=strict) for wm in self._seqs}


def account_snapshot(state: AcctState | None) -> dict[str, Any]:
    if state is None:
        return {"status": "UNKNOWN", "generation": None}
    return {
        "status": state.status,
        "generation": state.generation,
        "org": state.org,
        "freeze_current_seq": state.freeze_current_seq,
        "deactivated_at": state.deactivation.seq if state.deactivation else None,
        "anomalies": state.anomalies,
    }


def view_summary(view: LedgerView) -> dict[str, Any]:
    return {
        "watermark": view.watermark,
        "accounts": {acc: account_snapshot(st)
                     for acc, st in sorted(view.states.items())},
        "decisions": {d: o.to_dict()
                      for d, o in sorted(view.decision_outcomes.items())},
        "anomalies": view.anomalies,
    }
