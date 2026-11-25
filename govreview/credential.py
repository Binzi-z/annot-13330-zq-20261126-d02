"""Shortest independently-verifiable approval / rejection credentials.

A credential is deliberately *not* a copy of the reasoning.  It is the minimal
pointer-plus-seal that lets a different implementation re-derive the same
verdict from the persisted local files:

``{kind, account, generation, ticket, ticket_digest, decision[, reason][, independence_mode], seal}``

* ``account``/``generation``/``ticket``/``ticket_digest`` locate exactly one
  ``unfreeze_decided`` event and pin its binding triple;
* ``decision`` is what must be re-derived;
* ``reason`` (rejection only) is the primary reason code that must match;
* ``independence_mode`` (approval only) names the rule claimed, because a
  strict-mode approval is genuinely narrower;
* ``seal`` hashes the rest so any byte change is detected.

:func:`verify_credential` is a *second, independent* implementation of the
rule: it re-hashes the ticket body, re-reads approvals from the ledger, and
re-checks independence from the delegation forest.  It never calls the
evaluator.

Minimality is asserted mechanically (:func:`assert_minimal`): dropping any one
field must make verification fail.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canon import digest_of
from .delegation import assess_independence, DEFAULT_MODE
from .ledger import Ledger
from .schema import Bundle

APPROVAL = "approval"
REJECTION = "rejection"

_VALID_DECISION = ("APPROVE", "REJECT")


def _seal(core: dict[str, Any]) -> str:
    return digest_of({"seal_version": 1, "core": core})


def _core(cred: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in cred.items() if k != "seal"}


def build_credential(verdict: Any) -> dict[str, Any]:
    """Build the shortest credential for an ``authorization.Verdict``."""
    kind = APPROVAL if verdict.decision == "APPROVE" else REJECTION
    core: dict[str, Any] = {
        "kind": kind,
        "account": verdict.account,
        "generation": verdict.generation,
        "ticket": verdict.ticket,
        "ticket_digest": verdict.ticket_digest,
        "decision": verdict.decision,
    }
    if kind == REJECTION:
        core["reason"] = verdict.primary_reason()
    else:
        core["independence_mode"] = verdict.independence_mode
    cred = dict(core)
    cred["seal"] = _seal(core)
    return cred


# --------------------------------------------------------------------------
# Independent verifier -- deliberately separate from evaluate_unfreeze()
# --------------------------------------------------------------------------
@dataclass
class VerifyResult:
    ok: bool
    decision: str | None
    reason: str | None
    detail: list[str]
    seal_ok: bool

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "decision": self.decision,
                "reason": self.reason, "seal_ok": self.seal_ok,
                "detail": self.detail}


def _find_event(ledger: Ledger, account: str, ticket: str,
                digest: str) -> dict | None:
    matches = [
        ev for ev in ledger.events
        if ev.get("kind") == "unfreeze_decided"
        and ev.get("account") == account
        and ev.get("ticket") == ticket
        and ev.get("ticket_digest") == digest
    ]
    return matches[0] if len(matches) == 1 else None


def _rederive(cred: dict[str, Any], bundle: Bundle,
              ledger: Ledger) -> VerifyResult:
    problems: list[str] = []
    required = {"kind", "account", "generation", "ticket", "ticket_digest",
                "decision"}
    for key in required:
        if key not in cred:
            problems.append(f"missing field {key!r}")
    if problems:
        return VerifyResult(False, None, None, problems, False)

    seal_ok = cred.get("seal") == _seal(_core(cred))
    if not seal_ok:
        problems.append("seal mismatch: credential was altered")

    kind = cred["kind"]
    if kind not in (APPROVAL, REJECTION):
        problems.append(f"unknown credential kind {kind!r}")
    if cred["decision"] not in _VALID_DECISION:
        problems.append(f"unknown decision {cred['decision']!r}")

    account = cred["account"]
    ticket_id = cred["ticket"]
    digest = cred["ticket_digest"]
    generation = cred["generation"]

    # The credential must point at a real catalog ticket and a unique decision
    # event with exactly this binding triple.  These are *structural* checks:
    # failing them means the credential is not about anything real, so it is
    # rejected outright (not merely judged a form-failure).
    ticket = bundle.tickets.get(ticket_id)
    if ticket is None:
        problems.append(f"ticket {ticket_id!r} absent from tickets.json")
        return VerifyResult(False, None, None, problems, seal_ok)

    event = _find_event(ledger, account, ticket_id, digest)
    if event is None:
        problems.append("no unique unfreeze decision matches the credential")
        return VerifyResult(False, None, None, problems, seal_ok)
    if event["generation"] != generation:
        problems.append("credential generation disagrees with the matched decision")
        return VerifyResult(False, None, None, problems, seal_ok)

    recomputed = digest_of(ticket.body())
    view, _ = ledger.replay(event["seq"])
    state = view.states.get(account)
    live_generation = state.generation if state else None

    # Form re-derivation: this is what the credential attests.  A cited digest
    # that no longer re-hashes is a *reason* (TICKET_DIGEST_MISMATCH), not a
    # verifier error -- especially for a rejection credential built precisely
    # to attest "same number, different digest".
    approvals = event.get("approvals") or []
    redg: list[str] = []
    if account not in bundle.accounts:
        redg.append("ACCOUNT_UNKNOWN")
    if ticket.account != account:
        redg.append("TICKET_ACCOUNT_MISMATCH")
    if recomputed != digest:
        redg.append("TICKET_DIGEST_MISMATCH")
    if not event.get("committed", False):
        redg.append("NOT_COMMITTED")
    if live_generation is not None and generation != live_generation:
        redg.append("STALE_GENERATION")
    if len(approvals) != 2:
        redg.append("NOT_TWO_APPROVALS")
    else:
        a, b = approvals[0].get("approver"), approvals[1].get("approver")
        if a == b:
            redg.append("DUPLICATE_APPROVER")
        for ap in approvals:
            who = ap.get("approver")
            if who not in bundle.people:
                redg.append("UNKNOWN_APPROVER")
                continue
            if ap.get("account") != account:
                redg.append("APPROVAL_ACCOUNT_MISMATCH")
            if ap.get("generation") != generation:
                redg.append("APPROVAL_GENERATION_MISMATCH")
            if ap.get("ticket_digest") != digest:
                redg.append("APPROVAL_DIGEST_MISMATCH")
        if a in bundle.people and b in bundle.people and a != b:
            ind = assess_independence(
                bundle.people, a, b,
                mode=cred.get("independence_mode", DEFAULT_MODE))
            if not ind.independent:
                redg.append("APPROVALS_NOT_INDEPENDENT")

    redg_decision = "REJECT" if redg else "APPROVE"
    from .authorization import _REASON_ORDER
    primary = next((r for r in _REASON_ORDER if r in redg), "OK") if redg else "OK"

    if cred["decision"] != redg_decision:
        problems.append(f"credential claims {cred['decision']} but "
                        f"re-derivation gives {redg_decision}")
    if kind == APPROVAL and cred["decision"] != "APPROVE":
        problems.append("approval credential must claim APPROVE")
    if kind == APPROVAL:
        # An approval must *declare* the independence policy it satisfies; a
        # verifier cannot assume the laxer default on the approver's behalf.
        from .delegation import INDEPENDENCE_MODES
        if "independence_mode" not in cred:
            problems.append("approval credential must declare independence_mode")
        elif cred["independence_mode"] not in INDEPENDENCE_MODES:
            problems.append(
                f"unknown independence_mode {cred['independence_mode']!r}")
    if kind == REJECTION:
        if cred["decision"] != "REJECT":
            problems.append("rejection credential must claim REJECT")
        claimed = cred.get("reason")
        if claimed is None:
            problems.append("rejection credential missing reason")
        elif claimed != primary:
            problems.append(f"claimed reason {claimed!r} != re-derived "
                            f"{primary!r}")

    return VerifyResult(not problems, redg_decision, primary,
                        list(problems), seal_ok)


def verify_credential(cred: dict[str, Any], bundle: Bundle,
                      ledger: Ledger) -> VerifyResult:
    try:
        return _rederive(cred, bundle, ledger)
    except Exception as exc:  # a malformed credential must not crash the review
        return VerifyResult(False, None, None, [f"verifier error: {exc}"], False)


def assert_minimal(cred: dict[str, Any], bundle: Bundle,
                   ledger: Ledger) -> dict[str, Any]:
    """Prove each field is necessary: baseline verifies, each one-field drop fails."""
    base = verify_credential(cred, bundle, ledger)
    if not base.ok:
        raise AssertionError("baseline credential does not verify")
    field_results = []
    for key in sorted(_core(cred)) + ["seal"]:
        reduced = {k: v for k, v in cred.items() if k != key}
        res = verify_credential(reduced, bundle, ledger)
        field_results.append({"dropped": key,
                              "still_verifies": res.ok,
                              "load_bearing": not res.ok})
    return {
        "minimal": all(f["load_bearing"] for f in field_results),
        "field_count": len(cred),
        "fields": field_results,
        "baseline_ok": base.ok,
    }


def tamper_report(cred: dict[str, Any], bundle: Bundle,
                  ledger: Ledger) -> list[dict[str, Any]]:
    """Show that meaningful single-field edits are rejected."""
    cases = []
    for key in _core(cred):
        alt = dict(cred)
        alt[key] = _mutate(cred[key])
        cases.append((f"tamper {key}", alt))
    alt = dict(cred)
    alt["seal"] = "sha256:" + "0" * 64
    cases.append(("tamper seal", alt))
    out = []
    for label, alt in cases:
        res = verify_credential(alt, bundle, ledger)
        out.append({"case": label, "rejected": not res.ok})
    return out


def _mutate(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        if value.startswith("sha256:"):
            return "sha256:" + "f" * 64
        if value:
            return value[:-1] + ("X" if value[-1] != "X" else "Y")
    return "MUTATED"
