"""Authorization evaluator: does an unfreeze decision actually authorize?

The rule (from the incident write-up):

* an unfreeze needs **two** approvals from people on **mutually independent
  control chains**;
* each approval is **bound** to the account, the *target generation about to be
  unfrozen*, and the **ticket digest**.

Authorization has two layers, and separating them is the whole point of the
review:

* **Form** -- the decision is well-formed: ticket exists and re-hashes, the
  generation is the live one, two distinct independent approvers each bind the
  full triple, and it was committed.  A form-valid decision is what an
  *approval credential* attests.
* **Effect** -- whether the thaw actually changed the account's status.  A
  form-valid unfreeze committed after a terminal deactivation has **no
  effect**, which is exactly the gap between "the ticket reported success" and
  "the account is really thawed".

Everything is derived from local files; no live account is consulted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canon import digest_of
from .delegation import assess_independence, DEFAULT_MODE
from .ledger import AcctState, DEACTIVATED
from .schema import Bundle

# --- reason codes -----------------------------------------------------------
OK = "OK"
NO_TICKET = "NO_TICKET"
TICKET_DIGEST_MISMATCH = "TICKET_DIGEST_MISMATCH"
TICKET_ACCOUNT_MISMATCH = "TICKET_ACCOUNT_MISMATCH"
NOT_TWO_APPROVALS = "NOT_TWO_APPROVALS"
DUPLICATE_APPROVER = "DUPLICATE_APPROVER"
UNKNOWN_APPROVER = "UNKNOWN_APPROVER"
APPROVALS_NOT_INDEPENDENT = "APPROVALS_NOT_INDEPENDENT"
APPROVAL_ACCOUNT_MISMATCH = "APPROVAL_ACCOUNT_MISMATCH"
APPROVAL_GENERATION_MISMATCH = "APPROVAL_GENERATION_MISMATCH"
APPROVAL_DIGEST_MISMATCH = "APPROVAL_DIGEST_MISMATCH"
ACCOUNT_UNKNOWN = "ACCOUNT_UNKNOWN"
STALE_GENERATION = "STALE_GENERATION"
NOT_COMMITTED = "NOT_COMMITTED"

APPROVE = "APPROVE"
REJECT = "REJECT"

# Deterministic severity order for the *primary* reason.
_REASON_ORDER = [
    NO_TICKET, ACCOUNT_UNKNOWN, TICKET_ACCOUNT_MISMATCH,
    TICKET_DIGEST_MISMATCH, STALE_GENERATION, NOT_COMMITTED,
    NOT_TWO_APPROVALS, DUPLICATE_APPROVER, UNKNOWN_APPROVER,
    APPROVALS_NOT_INDEPENDENT, APPROVAL_ACCOUNT_MISMATCH,
    APPROVAL_GENERATION_MISMATCH, APPROVAL_DIGEST_MISMATCH,
]


@dataclass
class Verdict:
    decision: str
    account: str
    generation: int
    ticket: str | None
    ticket_digest: str | None
    reason_codes: list[str]
    detail: list[str] = field(default_factory=list)
    approvers: list[str] = field(default_factory=list)
    independence_mode: str = DEFAULT_MODE
    approvals_used: list[dict] = field(default_factory=list)
    chains: dict[str, str] = field(default_factory=dict)
    # Layer 2: actual effect at the end of replay.
    effect: str | None = None

    def primary_reason(self) -> str:
        for code in _REASON_ORDER:
            if code in self.reason_codes:
                return code
        return OK if self.decision == APPROVE else (
            self.reason_codes[0] if self.reason_codes else OK)

    def form_authorized(self) -> bool:
        return self.decision == APPROVE

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "account": self.account,
            "generation": self.generation,
            "ticket": self.ticket,
            "ticket_digest": self.ticket_digest,
            "reason_codes": self.reason_codes,
            "detail": self.detail,
            "approvers": self.approvers,
            "independence_mode": self.independence_mode,
            "effect": self.effect,
        }


def ticket_body_digest(bundle: Bundle, ticket_id: str) -> str | None:
    t = bundle.tickets.get(ticket_id)
    return digest_of(t.body()) if t is not None else None


def evaluate_unfreeze(event: dict, state: AcctState | None, bundle: Bundle,
                      independence_mode: str = DEFAULT_MODE) -> Verdict:
    """Evaluate an ``unfreeze_decided`` event against the state at its watermark.

    ``state`` is the account state reconstructed at the watermark that *includes*
    this event's replay (so its effect is already folded in).  Form checks use
    the event payload; effect is read from the corresponding DecisionOutcome.
    """
    account = event["account"]
    gen = event["generation"]
    tkt_id = event.get("ticket")
    tkt_digest = event.get("ticket_digest")
    approvals = event.get("approvals") or []
    reasons: list[str] = []
    detail: list[str] = []
    approvers: list[str] = []
    used: list[dict] = []
    chains: dict[str, str] = {}

    if account not in bundle.accounts:
        reasons.append(ACCOUNT_UNKNOWN)
        detail.append(f"account {account!r} not in accounts.json")

    # Ticket must exist, its stored digest must re-hash, and it must target
    # this account -- otherwise the approval binds nothing real.
    if tkt_id is None or tkt_id not in bundle.tickets:
        reasons.append(NO_TICKET)
        detail.append(f"ticket {tkt_id!r} not found in catalog")
    else:
        recomputed = ticket_body_digest(bundle, tkt_id)
        ticket = bundle.tickets[tkt_id]
        if ticket.account != account:
            reasons.append(TICKET_ACCOUNT_MISMATCH)
            detail.append(f"ticket {tkt_id} belongs to {ticket.account!r}, "
                          f"not {account!r}")
        if tkt_digest != recomputed:
            reasons.append(TICKET_DIGEST_MISMATCH)
            detail.append(
                f"decision cites digest {tkt_digest!r} but ticket {tkt_id} "
                f"body re-hashes to {recomputed!r} "
                f"(same number, different body)")

    # Generation must be the live one now; a stale epoch never authorizes.
    current_gen = state.generation if state is not None else None
    if current_gen is not None and gen != current_gen:
        reasons.append(STALE_GENERATION)
        detail.append(f"decision targets generation {gen} but live generation "
                      f"is {current_gen}")

    if not event.get("committed", False):
        reasons.append(NOT_COMMITTED)
        detail.append("decision recorded but never committed")

    # Exactly two, distinct, independent, fully bound approvals.
    if len(approvals) != 2:
        reasons.append(NOT_TWO_APPROVALS)
        detail.append(f"expected 2 approvals, found {len(approvals)}")

    seen: set[str] = set()
    for ap in approvals:
        who = ap.get("approver")
        approvers.append(who)
        if who in seen:
            reasons.append(DUPLICATE_APPROVER)
            detail.append(f"approver {who!r} appears more than once")
        seen.add(who)
        if who not in bundle.people:
            reasons.append(UNKNOWN_APPROVER)
            detail.append(f"approver {who!r} not in delegation.json")
            continue
        chains[who] = bundle.people[who].control_chain
        if ap.get("account") != account:
            reasons.append(APPROVAL_ACCOUNT_MISMATCH)
            detail.append(f"approval by {who} bound to account "
                          f"{ap.get('account')!r}, not {account!r}")
        if ap.get("generation") != gen:
            reasons.append(APPROVAL_GENERATION_MISMATCH)
            detail.append(f"approval by {who} bound to generation "
                          f"{ap.get('generation')!r}, not {gen}")
        if ap.get("ticket_digest") != tkt_digest:
            reasons.append(APPROVAL_DIGEST_MISMATCH)
            detail.append(f"approval by {who} bound to digest "
                          f"{ap.get('ticket_digest')!r}, not {tkt_digest!r}")

    if len(approvals) == 2 and len(seen) == 2 \
            and all(w in bundle.people for w in approvers):
        ind = assess_independence(bundle.people, approvers[0], approvers[1],
                                  mode=independence_mode)
        if not ind.independent:
            reasons.append(APPROVALS_NOT_INDEPENDENT)
            detail.append(ind.reason)
        else:
            for ap in approvals:
                used.append({
                    "approver": ap["approver"],
                    "control_chain": bundle.people[ap["approver"]].control_chain,
                    "account": ap["account"],
                    "generation": ap["generation"],
                    "ticket_digest": ap["ticket_digest"],
                })
    elif len(approvals) == 2:
        reasons.append(APPROVALS_NOT_INDEPENDENT)
        detail.append("cannot establish independence with unresolved approvers")

    if state is not None and state.status == DEACTIVATED:
        # Not a form defect: the form may be perfect.  Recorded so the report
        # can explain why a "successful" unfreeze had no effect.
        detail.append(
            "account is deactivated at this watermark; form-valid unfreeze "
            "has no effect (deactivation is terminal)")

    ordered = [r for r in _REASON_ORDER if r in reasons]
    return Verdict(
        decision=APPROVE if not ordered else REJECT,
        account=account, generation=gen, ticket=tkt_id,
        ticket_digest=tkt_digest, reason_codes=ordered, detail=detail,
        approvers=approvers, independence_mode=independence_mode,
        approvals_used=used, chains=chains)
