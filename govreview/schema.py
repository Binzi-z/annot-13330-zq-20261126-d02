"""Input schema validation and offline/local-file guards.

Inputs (all synthetic JSON, never network):

* ``accounts.json``   -- ``{"accounts": [{id, org, display}]}``
* ``delegation.json`` -- ``{"people": [{id, org, control_chain, delegated_from}]}``
* ``tickets.json``    -- ``{"tickets": [{id, account, target_generation,
                          requested_by, requested_at, reason, digest}]}``
* ``ledger.jsonl``    -- append-only decision log, one event per line

The guard refuses anything that is not a plain local file inside the input
tree, so the review cannot be pointed at a network location or a symlink that
escapes the sandbox.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canon import digest_of

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_CHAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

MAX_ITEMS = 200_000
MAX_STR = 400


class InputError(ValueError):
    """Raised when synthetic input fails validation."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems[:12]) + (
            f" … (+{len(problems) - 12} more)" if len(problems) > 12 else ""))


# --------------------------------------------------------------------------
# Offline / local-file guard
# --------------------------------------------------------------------------
def assert_local_tree(root: str | Path, paths: list[str | Path]) -> list[Path]:
    """Resolve *paths*, requiring each to be a regular file inside *root*.

    Rejects URL-looking paths, missing files, directories, and symlinks whose
    real location escapes the input root.  Returns the resolved paths.
    """
    root_p = Path(root).resolve()
    if not root_p.is_dir():
        raise InputError([f"input root is not a directory: {root_p}"])
    resolved: list[Path] = []
    for raw in paths:
        s = str(raw)
        if "://" in s or s.startswith(("http:", "https:", "ftp:")):
            raise InputError([f"network-looking path rejected: {s}"])
        p = Path(raw)
        if p.is_symlink():
            # Allow only symlinks that still resolve inside the root.
            real = p.resolve()
            if not _is_within(real, root_p):
                raise InputError([f"symlink escapes input root: {p} -> {real}"])
        p = p.resolve()
        if not _is_within(p, root_p):
            raise InputError([f"path escapes input root: {p}"])
        if not p.is_file():
            raise InputError([f"input is not a regular file: {p}"])
        resolved.append(p)
    return resolved


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Bundle
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Account:
    id: str
    org: str
    display: str


@dataclass(frozen=True)
class Person:
    id: str
    org: str
    control_chain: str
    delegated_from: str | None


@dataclass(frozen=True)
class Ticket:
    id: str
    account: str
    target_generation: int
    requested_by: str
    requested_at: str
    reason: str
    digest: str

    def body(self) -> dict[str, Any]:
        """The immutable request body whose digest approvals bind to."""
        return {
            "id": self.id,
            "account": self.account,
            "target_generation": self.target_generation,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
            "reason": self.reason,
        }


@dataclass
class Bundle:
    accounts: dict[str, Account]
    people: dict[str, Person]
    tickets: dict[str, Ticket]
    ledger: list[dict[str, Any]]


def _check_str(problems: list[str], where: str, value: Any, *,
               pattern: re.Pattern[str] | None = None,
               maximum: int = MAX_STR) -> None:
    if not isinstance(value, str):
        problems.append(f"{where}: expected string, got {type(value).__name__}")
        return
    if not value or len(value) > maximum:
        problems.append(f"{where}: empty or longer than {maximum} chars")
    if pattern is not None and not pattern.match(value):
        problems.append(f"{where}: malformed value {value!r}")


def _check_int(problems: list[str], where: str, value: Any, *,
               minimum: int = 0, maximum: int = 1_000_000) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        problems.append(f"{where}: expected integer")
    elif not (minimum <= value <= maximum):
        problems.append(f"{where}: out of range [{minimum},{maximum}]")


def _require_keys(problems: list[str], where: str, obj: Any,
                  keys: dict[str, bool]) -> bool:
    """Validate an object's keys ({name: required}); return True only when the
    object is a dict and every required key is present."""
    if not isinstance(obj, dict):
        problems.append(f"{where}: expected object")
        return False
    ok = True
    for key, required in keys.items():
        if required and key not in obj:
            problems.append(f"{where}: missing key {key!r}")
            ok = False
    for key in obj:
        if key not in keys:
            problems.append(f"{where}: unexpected key {key!r}")
    return ok


# --------------------------------------------------------------------------
# Sub-validators
# --------------------------------------------------------------------------
def validate_accounts(doc: Any) -> dict[str, Account]:
    problems: list[str] = []
    if not _require_keys(problems, "accounts.json", doc, {"accounts": True}):
        raise InputError(problems)
    items = doc["accounts"]
    if not isinstance(items, list) or not items:
        raise InputError(["accounts.json: 'accounts' must be a non-empty list"])
    if len(items) > MAX_ITEMS:
        raise InputError([f"accounts.json: too many accounts ({len(items)})"])
    out: dict[str, Account] = {}
    for i, item in enumerate(items):
        where = f"accounts[{i}]"
        if not _require_keys(problems, where, item,
                             {"id": True, "org": True, "display": True}):
            continue
        _check_str(problems, f"{where}.id", item.get("id"), pattern=_ID_RE)
        _check_str(problems, f"{where}.org", item.get("org"), pattern=_ID_RE)
        _check_str(problems, f"{where}.display", item.get("display"))
        acc = Account(item.get("id"), item.get("org"), item.get("display"))
        if acc.id in out:
            problems.append(f"{where}: duplicate account id {acc.id!r}")
        else:
            out[acc.id] = acc
    if problems:
        raise InputError(problems)
    return out


def validate_delegation(doc: Any, accounts: dict[str, Account]) -> dict[str, Person]:
    problems: list[str] = []
    if not _require_keys(problems, "delegation.json", doc, {"people": True}):
        raise InputError(problems)
    items = doc["people"]
    if not isinstance(items, list) or not items:
        raise InputError(["delegation.json: 'people' must be a non-empty list"])
    if len(items) > MAX_ITEMS:
        raise InputError([f"delegation.json: too many people ({len(items)})"])
    out: dict[str, Person] = {}
    for i, item in enumerate(items):
        where = f"people[{i}]"
        if not _require_keys(problems, where, item, {
                "id": True, "org": True, "control_chain": True,
                "delegated_from": False}):
            continue
        _check_str(problems, f"{where}.id", item.get("id"), pattern=_ID_RE)
        _check_str(problems, f"{where}.org", item.get("org"), pattern=_ID_RE)
        _check_str(problems, f"{where}.control_chain",
                   item.get("control_chain"), pattern=_CHAIN_RE)
        dfrom = item.get("delegated_from")
        if dfrom is not None:
            _check_str(problems, f"{where}.delegated_from", dfrom,
                       pattern=_ID_RE)
        p = Person(item.get("id"), item.get("org"),
                   item.get("control_chain"), dfrom)
        if p.id in out:
            problems.append(f"{where}: duplicate person id {p.id!r}")
        else:
            out[p.id] = p
    # Referential integrity & cycles.
    for pid, person in out.items():
        if person.delegated_from is not None:
            if person.delegated_from not in out:
                problems.append(
                    f"delegation[{pid}]: delegated_from {person.delegated_from!r} unknown")
            elif out[person.delegated_from].org != person.org:
                problems.append(
                    f"delegation[{pid}]: crosses org boundary "
                    f"({person.org!r} -> {out[person.delegated_from].org!r})")
    for pid in out:
        walk, cur = set(), pid
        while cur is not None and cur in out:
            if cur in walk:
                problems.append(f"delegation[{pid}]: delegation cycle detected")
                break
            walk.add(cur)
            cur = out[cur].delegated_from
    if problems:
        raise InputError(problems)
    return out


def validate_tickets(doc: Any, accounts: dict[str, Account],
                     people: dict[str, Person]) -> dict[str, Ticket]:
    problems: list[str] = []
    if _require_keys(problems, "tickets.json", doc, {"tickets": True}) is False:
        raise InputError(problems)
    items = doc["tickets"]
    if not isinstance(items, list):
        raise InputError(["tickets.json: 'tickets' must be a list"])
    if len(items) > MAX_ITEMS:
        raise InputError([f"tickets.json: too many tickets ({len(items)})"])
    out: dict[str, Ticket] = {}
    for i, item in enumerate(items):
        where = f"tickets[{i}]"
        if not _require_keys(problems, where, item, {
                "id": True, "account": True, "target_generation": True,
                "requested_by": True, "requested_at": True,
                "reason": True, "digest": True}):
            continue
        _check_str(problems, f"{where}.id", item.get("id"), pattern=_ID_RE)
        _check_str(problems, f"{where}.account", item.get("account"),
                   pattern=_ID_RE)
        _check_int(problems, f"{where}.target_generation",
                   item.get("target_generation"))
        _check_str(problems, f"{where}.requested_by", item.get("requested_by"),
                   pattern=_ID_RE)
        _check_str(problems, f"{where}.requested_at", item.get("requested_at"),
                   pattern=_TS_RE)
        _check_str(problems, f"{where}.reason", item.get("reason"), maximum=200)
        _check_str(problems, f"{where}.digest", item.get("digest"),
                   pattern=_DIGEST_RE)
        if not all(isinstance(item.get(k), str) for k in
                   ("id", "account", "requested_by", "requested_at",
                    "reason", "digest")) \
                or not isinstance(item.get("target_generation"), int):
            continue  # this ticket's fields are structurally unusable
        acc_id = item["account"]
        if acc_id not in accounts:
            problems.append(f"{where}: unknown account {acc_id!r}")
        if item["requested_by"] not in people:
            problems.append(f"{where}: unknown requester {item['requested_by']!r}")
        t = Ticket(
            id=item["id"], account=acc_id,
            target_generation=item["target_generation"],
            requested_by=item["requested_by"],
            requested_at=item["requested_at"], reason=item["reason"],
            digest=item["digest"],
        )
        if digest_of(t.body()) != t.digest:
            problems.append(
                f"{where}: stored digest does not match canonical ticket body")
        if t.id in out:
            problems.append(
                f"{where}: duplicate ticket id {t.id!r} -- the same number "
                f"with two bodies is exactly the stale-alias hazard")
        else:
            out[t.id] = t
    if problems:
        raise InputError(problems)
    return out


# Ledger event kinds and the keys each kind must carry.
_EVENT_KEYS: dict[str, dict[str, bool]] = {
    "provision": {"account": True, "org": True, "generation": True},
    "rotate": {"account": True, "generation": True},
    "freeze_applied": {"account": True, "generation": True},
    "unfreeze_decided": {
        "decision": True, "account": True, "generation": True,
        "ticket": True, "ticket_digest": True, "approvals": True,
        "committed": True, "receipt_delivered": True,
    },
    "deactivate_decided": {
        "decision": True, "account": True, "generation": True,
        "committed": True, "reason": True,
    },
    "report": {"ticket": True, "reported_by": True, "claimed": True},
}
_COMMON_KEYS = {"seq": True, "ts": True, "kind": True}


def validate_ledger(rows: list[dict], accounts: dict[str, Account],
                    people: dict[str, Person],
                    tickets: dict[str, Ticket]) -> list[dict]:
    problems: list[str] = []
    if not rows:
        raise InputError(["ledger.jsonl: no events"])
    if len(rows) > MAX_ITEMS * 2:
        raise InputError([f"ledger.jsonl: too many events ({len(rows)})"])
    last_seq = 0
    for i, row in enumerate(rows):
        where = f"ledger[{i}]"
        if not isinstance(row, dict):
            problems.append(f"{where}: expected object")
            continue
        kind = row.get("kind")
        if kind not in _EVENT_KEYS:
            problems.append(f"{where}: unknown kind {kind!r}")
            continue
        allowed = dict(_COMMON_KEYS)
        allowed.update(_EVENT_KEYS[kind])
        _require_keys(problems, where, row, allowed)
        _check_int(problems, f"{where}.seq", row.get("seq"), minimum=1)
        _check_str(problems, f"{where}.ts", row.get("ts"), pattern=_TS_RE)
        if isinstance(row.get("seq"), int) and row["seq"] <= last_seq:
            problems.append(f"{where}: seq {row['seq']} not strictly increasing")
        if isinstance(row.get("seq"), int):
            last_seq = max(last_seq, row["seq"])

        acc = row.get("account")
        if acc is not None:
            _check_str(problems, f"{where}.account", acc, pattern=_ID_RE)
            if isinstance(acc, str) and acc not in accounts:
                problems.append(f"{where}: unknown account {acc!r}")

        if kind in ("provision", "rotate", "freeze_applied",
                    "unfreeze_decided", "deactivate_decided"):
            _check_int(problems, f"{where}.generation", row.get("generation"))

        if kind == "provision":
            org = row.get("org")
            _check_str(problems, f"{where}.org", org, pattern=_ID_RE)
            if isinstance(acc, str) and isinstance(org, str) \
                    and acc in accounts and accounts[acc].org != org:
                problems.append(
                    f"{where}: provision org {org!r} disagrees with "
                    f"accounts.json {accounts[acc].org!r}")

        if kind == "rotate":
            if row.get("generation") == 0:
                problems.append(f"{where}: rotation must increase generation")

        if kind == "unfreeze_decided":
            _check_str(problems, f"{where}.decision", row.get("decision"),
                       pattern=_ID_RE)
            _check_str(problems, f"{where}.ticket", row.get("ticket"),
                       pattern=_ID_RE)
            _check_str(problems, f"{where}.ticket_digest",
                       row.get("ticket_digest"), pattern=_DIGEST_RE)
            if not isinstance(row.get("committed"), bool):
                problems.append(f"{where}.committed: expected boolean")
            if not isinstance(row.get("receipt_delivered"), bool):
                problems.append(f"{where}.receipt_delivered: expected boolean")
            tkt = row.get("ticket")
            if isinstance(tkt, str) and tkt not in tickets:
                problems.append(f"{where}: unknown ticket {tkt!r}")
            _validate_approvals(problems, where, row.get("approvals"),
                                people, acc)

        if kind == "deactivate_decided":
            _check_str(problems, f"{where}.decision", row.get("decision"),
                       pattern=_ID_RE)
            _check_str(problems, f"{where}.reason", row.get("reason"),
                       maximum=200)
            if not isinstance(row.get("committed"), bool):
                problems.append(f"{where}.committed: expected boolean")

        if kind == "report":
            _check_str(problems, f"{where}.ticket", row.get("ticket"),
                       pattern=_ID_RE)
            _check_str(problems, f"{where}.reported_by",
                       row.get("reported_by"), pattern=_ID_RE)
            if row.get("claimed") not in ("success", "failure"):
                problems.append(
                    f"{where}.claimed: expected 'success' or 'failure'")
    if problems:
        raise InputError(problems)
    return rows


def _validate_approvals(problems: list[str], where: str, approvals: Any,
                        people: dict[str, Person], account: Any) -> None:
    if not isinstance(approvals, list):
        problems.append(f"{where}.approvals: expected list")
        return
    if len(approvals) > 8:
        problems.append(f"{where}.approvals: too many ({len(approvals)})")
    for j, ap in enumerate(approvals):
        apw = f"{where}.approvals[{j}]"
        if not _require_keys(problems, apw, ap, {
                "approver": True, "account": True, "generation": True,
                "ticket_digest": True}):
            continue
        _check_str(problems, f"{apw}.approver", ap.get("approver"),
                   pattern=_ID_RE)
        _check_str(problems, f"{apw}.account", ap.get("account"),
                   pattern=_ID_RE)
        _check_int(problems, f"{apw}.generation", ap.get("generation"))
        _check_str(problems, f"{apw}.ticket_digest", ap.get("ticket_digest"),
                   pattern=_DIGEST_RE)
        if ap.get("approver") not in people:
            problems.append(f"{apw}: unknown approver {ap.get('approver')!r}")
        if account is not None and ap.get("account") != account:
            problems.append(
                f"{apw}: approval bound to a different account "
                f"({ap.get('account')!r} != {account!r})")


def load_bundle(input_dir: str | Path) -> Bundle:
    """Guard + load + validate all four synthetic input files."""
    from .canon import load_json, load_jsonl

    root = Path(input_dir).resolve()
    paths = [root / n for n in
             ("accounts.json", "delegation.json", "tickets.json", "ledger.jsonl")]
    assert_local_tree(root, paths)

    accounts = validate_accounts(load_json(paths[0]))
    people = validate_delegation(load_json(paths[1]), accounts)
    tickets = validate_tickets(load_json(paths[2]), accounts, people)
    ledger = validate_ledger(load_jsonl(paths[3]), accounts, people, tickets)
    return Bundle(accounts=accounts, people=people, tickets=tickets,
                  ledger=ledger)
