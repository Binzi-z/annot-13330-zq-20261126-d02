"""Delegation-aware independence checks for the two-approver rule.

Two approvers are *independent* when they sit on different control chains.
An optional stricter mode additionally forbids any shared delegator in the
delegation forest (two chains that branch from one manager are not treated as
independent under ``strict_no_common_delegator``).

Delegation edges never cross organization boundaries (enforced upstream by the
schema validator), so an approver can only descend from peers in its own org.
"""

from __future__ import annotations

from dataclasses import dataclass

from .schema import Person

INDEPENDENCE_MODES = ("control_chain", "strict_no_common_delegator")
DEFAULT_MODE = "control_chain"


@dataclass(frozen=True)
class Independence:
    independent: bool
    mode: str
    reason: str
    chain_a: str
    chain_b: str
    common_delegator: str | None


def chain_of(people: dict[str, Person], person_id: str) -> str:
    p = people.get(person_id)
    if p is None:
        raise KeyError(f"unknown person {person_id!r}")
    return p.control_chain


def ancestors(people: dict[str, Person], person_id: str) -> list[str]:
    """Walk *up* the ``delegated_from`` chain, including *person_id* first."""
    out: list[str] = []
    cur: str | None = person_id
    seen: set[str] = set()
    while cur is not None:
        if cur in seen:  # defensive: schema rejects cycles
            break
        seen.add(cur)
        out.append(cur)
        cur = people[cur].delegated_from if cur in people else None
    return out


def nearest_common_delegator(people: dict[str, Person],
                             a: str, b: str) -> str | None:
    """Lowest common ancestor of two people in the delegation forest.

    Returns the shared delegator strictest closest to both, or ``None`` when
    their lineages are disjoint.  The walk includes the people themselves, so
    an (impossible under schema dedupe) self-relation still resolves.
    """
    anc_a = ancestors(people, a)
    anc_b = ancestors(people, b)
    pos_b = {pid: i for i, pid in enumerate(anc_b)}
    best: str | None = None
    best_idx = -1
    for i, pid in enumerate(anc_a):
        if pid in pos_b:
            # Closest to *a* (smallest i) wins; ties impossible in a tree.
            if best is None or i < best_idx:
                best, best_idx = pid, i
    return best


def assess_independence(people: dict[str, Person], approver_a: str,
                        approver_b: str,
                        mode: str = DEFAULT_MODE) -> Independence:
    """Decide whether two approvers satisfy the independence rule."""
    if mode not in INDEPENDENCE_MODES:
        raise ValueError(f"unknown independence mode {mode!r}")
    if approver_a not in people:
        return Independence(False, mode, f"unknown approver {approver_a!r}",
                            "", "", None)
    if approver_b not in people:
        return Independence(False, mode, f"unknown approver {approver_b!r}",
                            "", "", None)
    if approver_a == approver_b:
        return Independence(
            False, mode, "the same person cannot supply both approvals",
            chain_of(people, approver_a), chain_of(people, approver_b), approver_a)

    chain_a = chain_of(people, approver_a)
    chain_b = chain_of(people, approver_b)
    if chain_a == chain_b:
        return Independence(
            False, mode,
            f"both approvers share control chain {chain_a!r}",
            chain_a, chain_b, nearest_common_delegator(people, approver_a, approver_b))

    lca = nearest_common_delegator(people, approver_a, approver_b)
    if mode == "strict_no_common_delegator" and lca is not None:
        return Independence(
            False, mode,
            f"approvers share delegator {lca!r}; strict mode needs disjoint lineage",
            chain_a, chain_b, lca)

    return Independence(True, mode, "different control chains; no shared authority",
                        chain_a, chain_b, lca)


def org_members(people: dict[str, Person], org: str) -> list[str]:
    return sorted(pid for pid, p in people.items() if p.org == org)
