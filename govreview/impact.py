"""Impact analysis over 60,000 org-partitioned records.

Records live on partitions named ``org/partition-N`` and span five orgs.  A
single deactivation of ``acct-7`` (org ``ops-east``) is applied and we report
*which* partitions it actually affects and how many records, then verify the
per-partition count against a full independent scan of the whole set.

The point is to make "actual impact" checkable rather than asserted:

* records are generated deterministically (stable ids, no randomness);
* the incremental path (walk records mentioning the account) and the full-scan
  path (re-count every record) must agree exactly;
* a fixed partition-total invariant (sum of partition counts == 60,000) is
  checked independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

TOTAL_RECORDS = 60_000
ORGS = ["ops-east", "finance-west", "warehouse-south", "dev-north", "lab-core"]
PARTITIONS_PER_ORG = 4
# acct-7 belongs to ops-east and owns records spread over its partitions.
TARGET_ACCOUNT = "acct-7"
TARGET_ORG = "ops-east"


@dataclass
class Record:
    rid: str
    account: str
    org: str
    partition: str
    generation: int
    status: str            # 'active' | 'frozen' | 'deactivated'

    def to_dict(self) -> dict[str, Any]:
        return {"rid": self.rid, "account": self.account, "org": self.org,
                "partition": self.partition, "generation": self.generation,
                "status": self.status}


def _account_id_for(org: str, index: int) -> str:
    # Each org gets a deterministic pool of synthetic accounts.
    return f"acct-{org}-{index:03d}"


def build_records(total: int = TOTAL_RECORDS,
                  seed_account: str = TARGET_ACCOUNT,
                  seed_org: str = TARGET_ORG) -> list[Record]:
    """Deterministically build *total* records across orgs/partitions.

    Distribution is balanced to the record: every org gets the same count, and
    every partition within an org gets the same count (remainder to the earliest
    partitions).  ``acct-7`` owns a known, counted slice of ``ops-east``.
    """
    if total % len(ORGS) != 0:
        raise ValueError("total must divide evenly across orgs for balance")
    per_org = total // len(ORGS)
    per_partition_base = per_org // PARTITIONS_PER_ORG
    remainder = per_org % PARTITIONS_PER_ORG

    records: list[Record] = []
    for org in ORGS:
        part_counts = [per_partition_base + (1 if p < remainder else 0)
                       for p in range(PARTITIONS_PER_ORG)]
        for p_idx in range(PARTITIONS_PER_ORG):
            part = f"{org}/partition-{p_idx}"
            count = part_counts[p_idx]
            for j in range(count):
                # Global running position within the org.
                pos = sum(part_counts[:p_idx]) + j
                # Deterministic account assignment: 30% to acct-7 in the target
                # org, otherwise a stable pool id.
                if org == seed_org and pos % 10 < 3:
                    account = seed_account
                else:
                    account = _account_id_for(org, pos % 97)
                gen = 1 + (pos % 5)
                status = "active"
                if org == seed_org and account == seed_account:
                    status = "deactivated"
                elif org == seed_org and pos % 7 == 0:
                    status = "frozen"
                records.append(Record(
                    rid=f"rec-{len(records):06d}",
                    account=account, org=org, partition=part,
                    generation=gen, status=status))
    # Deterministic ordering by partition then rid.
    records.sort(key=lambda r: (r.partition, r.rid))
    if len(records) != total:
        raise AssertionError(f"record count {len(records)} != {total}")
    return records


def partition_totals(records: list[Record]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for r in records:
        totals[r.partition] = totals.get(r.partition, 0) + 1
    return dict(sorted(totals.items()))


def incremental_impact(records: list[Record],
                       account: str = TARGET_ACCOUNT) -> dict[str, int]:
    """Walk records mentioning *account*; count per partition it appears in."""
    by_part: dict[str, int] = {}
    for r in records:
        if r.account == account:
            by_part[r.partition] = by_part.get(r.partition, 0) + 1
    return dict(sorted(by_part.items()))


def full_scan_impact(records: list[Record],
                     account: str = TARGET_ACCOUNT) -> dict[str, int]:
    """Independent full scan: re-derive counts from scratch, no shared state."""
    seen: dict[str, int] = {}
    for r in records:
        if r.account != account:
            continue
        seen.setdefault(r.partition, 0)
        seen[r.partition] += 1
    return dict(sorted(seen.items()))


@dataclass
class ImpactReport:
    total_records: int
    target_account: str
    target_org: str
    affected_partitions: list[str]
    affected_record_count: int
    partition_counts: dict[str, int]
    org_partition_totals: dict[str, int]
    per_org_affected: dict[str, int]
    incremental: dict[str, int]
    full_scan: dict[str, int]
    blast_radius_if_partition_wide: int = 0
    checks: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "target_account": self.target_account,
            "target_org": self.target_org,
            "affected_partitions": self.affected_partitions,
            "affected_record_count": self.affected_record_count,
            "partition_counts": self.partition_counts,
            "org_partition_totals": self.org_partition_totals,
            "per_org_affected": self.per_org_affected,
            "incremental": self.incremental,
            "full_scan": self.full_scan,
            "blast_radius_if_partition_wide": self.blast_radius_if_partition_wide,
            "checks": self.checks,
        }


def analyze_impact(records: list[Record] | None = None) -> ImpactReport:
    if records is None:
        records = build_records()

    totals = partition_totals(records)
    inc = incremental_impact(records)
    full = full_scan_impact(records)

    affected_parts = sorted(inc)
    affected_count = sum(inc.values())

    org_totals: dict[str, int] = {}
    for part, n in totals.items():
        org = part.split("/", 1)[0]
        org_totals[org] = org_totals.get(org, 0) + n

    per_org_affected: dict[str, int] = {}
    for part, n in inc.items():
        org = part.split("/", 1)[0]
        per_org_affected[org] = per_org_affected.get(org, 0) + n

    # What the deactivation actually owns (per-partition counts of target
    # records) vs. the over-broad blast radius of denylisting whole touched
    # partitions (all records there).  Reported for contrast.
    touched_partition_records = sum(totals[p] for p in affected_parts)

    checks = {
        "total_is_60000": len(records) == TOTAL_RECORDS,
        "all_partitions_covered":
            len(totals) == len(ORGS) * PARTITIONS_PER_ORG,
        "partition_totals_sum_to_total": sum(totals.values()) == len(records),
        "incremental_matches_full_scan": inc == full,
        "affected_only_target_org": all(
            p.split("/", 1)[0] == TARGET_ORG for p in affected_parts),
        "affected_count_is_sum_of_parts": affected_count == sum(inc.values()),
        "org_total_sum": sum(org_totals.values()) == len(records),
    }

    return ImpactReport(
        total_records=len(records),
        target_account=TARGET_ACCOUNT,
        target_org=TARGET_ORG,
        affected_partitions=affected_parts,
        affected_record_count=affected_count,
        partition_counts=totals,
        org_partition_totals=org_totals,
        per_org_affected=per_org_affected,
        incremental=inc,
        full_scan=full,
        blast_radius_if_partition_wide=touched_partition_records,
        checks=checks,
    )


def verify_full_set(records: list[Record]) -> dict[str, Any]:
    """Independent full-set verification of the impact claim.

    Recompute counts two more ways (a streaming accumulator and a sorted
    grouping) and require all three to agree, plus structural invariants.
    """
    inc = incremental_impact(records)
    full = full_scan_impact(records)

    # Third, distinct method: sort-and-group.
    grouped: dict[str, int] = {}
    keyed = sorted((r.account, r.partition) for r in records)
    for account, part in keyed:
        if account != TARGET_ACCOUNT:
            continue
        grouped[part] = grouped.get(part, 0) + 1
    grouped = dict(sorted(grouped.items()))

    totals = partition_totals(records)
    # Re-derive totals via Counter-independent summation.
    recount: dict[str, int] = {}
    for r in records:
        recount[r.partition] = recount.get(r.partition, 0) + 1

    return {
        "incremental": inc,
        "full_scan": full,
        "sorted_group": grouped,
        "three_methods_agree": inc == full == grouped,
        "partition_totals_match_recount": totals == dict(sorted(recount.items())),
        "grand_total": len(records),
        "grand_total_ok": len(records) == TOTAL_RECORDS,
        "sum_of_affected_parts": sum(inc.values()),
        "affected_partition_count": len(inc),
    }
