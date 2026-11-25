"""Deterministic generator for the synthetic incident input.

Everything is derived from fixed seeds and fixed timestamps, so regenerating
the bundle yields byte-identical files (checked via the manifest).

Story (*one* account, two racing tickets):

* ``acct-7`` (org ``ops-east``) starts ACTIVE at generation 1, then is frozen.
* Ticket ``T-1023`` is **reissued** after a rotation: the same ticket number
  now carries a different body and a different digest (``D_new``).  A stale
  approval still cites the pre-rotation body ``D_old`` -- the *old generation,
  same number, different digest* hazard.
* A rotation moves the live epoch to 2 while frozen.
* ``dec-stale`` is an unfreeze citing generation 1 + ``D_old`` whose two
  approvers are on the **same** control chain -- rejected (stale + not
  independent + digest mismatch).
* ``dec-deact`` deactivates generation 2 -- the deactivation wins the race.
* ``dec-valid`` is a **form-perfect** unfreeze (generation 2, ``D_new``,
  independent approvers, committed) but the caller never got the receipt.  It
  has **no effect** because the account is already deactivated.  Both tickets
  still *report success*.

Secondary accounts in other orgs populate the impact analysis.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .canon import digest_of, dump_json, dump_jsonl, load_jsonl
from .ledger import chain_hashes

T1023_REASON_NEW = "restore operator console access (reissued after rotation)"
T1023_REASON_OLD = "restore operator console access"


def _ts(h: int, m: int, s: int) -> str:
    return f"2026-11-25T{h:02d}:{m:02d}:{s:02d}Z"


def _ticket_body(tid: str, account: str, gen: int, requester: str,
                 when: str, reason: str) -> dict:
    return {"id": tid, "account": account, "target_generation": gen,
            "requested_by": requester, "requested_at": when, "reason": reason}


def ticket_digests() -> dict[str, str]:
    """Both historical bodies of ticket T-1023 (same number, different digest)."""
    old = _ticket_body("T-1023", "acct-7", 1, "p-amber", _ts(8, 40, 0),
                       T1023_REASON_OLD)
    new = _ticket_body("T-1023", "acct-7", 2, "p-amber", _ts(9, 0, 0),
                       T1023_REASON_NEW)
    return {"old": digest_of(old), "new": digest_of(new)}


def build_people() -> list[dict]:
    return [
        # ops-east: three disjoint control chains
        {"id": "p-alice", "org": "ops-east", "control_chain": "chain-A",
         "delegated_from": None},
        {"id": "p-amber", "org": "ops-east", "control_chain": "chain-A",
         "delegated_from": "p-alice"},
        {"id": "p-bob", "org": "ops-east", "control_chain": "chain-B",
         "delegated_from": None},
        {"id": "p-bella", "org": "ops-east", "control_chain": "chain-B",
         "delegated_from": "p-bob"},
        {"id": "p-carol", "org": "ops-east", "control_chain": "chain-C",
         "delegated_from": None},
        # finance-west
        {"id": "p-dana", "org": "finance-west", "control_chain": "chain-A",
         "delegated_from": None},
        {"id": "p-dmitri", "org": "finance-west", "control_chain": "chain-B",
         "delegated_from": "p-dana"},
        # warehouse-south
        {"id": "p-eve", "org": "warehouse-south", "control_chain": "chain-A",
         "delegated_from": None},
        {"id": "p-erik", "org": "warehouse-south", "control_chain": "chain-B",
         "delegated_from": "p-eve"},
        # dev-north
        {"id": "p-frank", "org": "dev-north", "control_chain": "chain-A",
         "delegated_from": None},
        {"id": "p-fiona", "org": "dev-north", "control_chain": "chain-B",
         "delegated_from": "p-frank"},
        # lab-core
        {"id": "p-gina", "org": "lab-core", "control_chain": "chain-A",
         "delegated_from": None},
        {"id": "p-gil", "org": "lab-core", "control_chain": "chain-B",
         "delegated_from": "p-gina"},
        # edge-north
        {"id": "p-hana", "org": "edge-north", "control_chain": "chain-A",
         "delegated_from": None},
        {"id": "p-hugo", "org": "edge-north", "control_chain": "chain-B",
         "delegated_from": "p-hana"},
    ]


def build_accounts() -> list[dict]:
    return [{"id": "acct-7", "org": "ops-east",
             "display": "Synthetic Ops East 7"}]


def build_tickets() -> list[dict]:
    new = _ticket_body("T-1023", "acct-7", 2, "p-amber", _ts(9, 0, 0),
                       T1023_REASON_NEW)
    new["digest"] = digest_of(new)
    return [new]


def build_ledger() -> list[dict]:
    d_old = ticket_digests()["old"]
    d_new = ticket_digests()["new"]
    return [
        {"seq": 1, "ts": _ts(7, 0, 0), "kind": "provision",
         "account": "acct-7", "org": "ops-east", "generation": 1},
        # Operator freezes acct-7 (normal ops), then someone asks to thaw it.
        {"seq": 2, "ts": _ts(8, 0, 0), "kind": "freeze_applied",
         "account": "acct-7", "generation": 1},
        # Rotation to generation 2; T-1023 is reissued with a new body.
        {"seq": 3, "ts": _ts(9, 30, 0), "kind": "rotate",
         "account": "acct-7", "generation": 2},
        # Hazard 3: stale generation + same number + different (old) digest,
        # and two approvals on the SAME chain.  Rejected.
        {"seq": 4, "ts": _ts(10, 0, 0), "kind": "unfreeze_decided",
         "decision": "dec-stale", "account": "acct-7", "generation": 1,
         "ticket": "T-1023", "ticket_digest": d_old,
         "approvals": [
             {"approver": "p-alice", "account": "acct-7", "generation": 1,
              "ticket_digest": d_old},
             {"approver": "p-amber", "account": "acct-7", "generation": 1,
              "ticket_digest": d_old},
         ],
         "committed": True, "receipt_delivered": True},
        # Hazard 1: deactivation lands first, on the live generation.
        {"seq": 5, "ts": _ts(10, 5, 0), "kind": "deactivate_decided",
         "decision": "dec-deact", "account": "acct-7", "generation": 2,
         "reason": "security hold from concurrent response", "committed": True},
        # Hazard 2: form-perfect, committed unfreeze; caller gets no receipt,
        # and it has no effect because deactivation is terminal.
        {"seq": 6, "ts": _ts(10, 10, 0), "kind": "unfreeze_decided",
         "decision": "dec-valid", "account": "acct-7", "generation": 2,
         "ticket": "T-1023", "ticket_digest": d_new,
         "approvals": [
             {"approver": "p-alice", "account": "acct-7", "generation": 2,
              "ticket_digest": d_new},
             {"approver": "p-carol", "account": "acct-7", "generation": 2,
              "ticket_digest": d_new},
         ],
         "committed": True, "receipt_delivered": False},
        # Both tickets report success -- the ambiguity the successor faced.
        {"seq": 7, "ts": _ts(10, 11, 0), "kind": "report",
         "ticket": "T-1023", "reported_by": "p-amber", "claimed": "success"},
        {"seq": 8, "ts": _ts(10, 12, 0), "kind": "report",
         "ticket": "T-1023", "reported_by": "p-bob", "claimed": "success"},
    ]


def generate_inputs(out_dir: str | Path) -> dict[str, str]:
    """Write the synthetic input files; return per-file (physical) SHA-256."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    accounts = build_accounts()
    people = build_people()
    tickets = build_tickets()
    ledger = build_ledger()

    dump_json({"accounts": accounts}, out / "accounts.json")
    dump_json({"people": people}, out / "delegation.json")
    dump_json({"tickets": tickets}, out / "tickets.json")
    dump_jsonl(ledger, out / "ledger.jsonl")
    dump_jsonl(chain_hashes(ledger), out / "decision_log.jsonl")

    return physical_digests(out)


def physical_digests(out_dir: str | Path) -> dict[str, str]:
    out = Path(out_dir)
    result = {}
    for name in ("accounts.json", "delegation.json", "tickets.json",
                 "ledger.jsonl", "decision_log.jsonl"):
        fp = out / name
        result[name] = hashlib.sha256(fp.read_bytes()).hexdigest()
    return result


def logical_digests(out_dir: str | Path) -> dict[str, str]:
    """Digest of the canonical *content* (stable regardless of formatting)."""
    out = Path(out_dir)
    return {
        "accounts": digest_of({"accounts": json_load(out / "accounts.json")}),
        "delegation": digest_of({"people": json_load(out / "delegation.json")}),
        "tickets": digest_of({"tickets": json_load(out / "tickets.json")}),
        "ledger": digest_of(load_jsonl(out / "ledger.jsonl")),
    }


def json_load(path: str | Path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
