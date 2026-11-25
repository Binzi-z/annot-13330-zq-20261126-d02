"""Canonical JSON, digests and crash-safe (atomic) file IO.

Every digest in this toolkit is computed over *canonical* JSON: UTF-8, sorted
keys, no insignificant whitespace, ``ensure_ascii=False``.  Reconstructing the
same bytes on any machine makes digests independently checkable.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def canonical_json(obj: Any) -> str:
    """Serialize *obj* to canonical JSON text (stable across runs/machines)."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    return canonical_json(obj).encode("utf-8")


def digest_of(obj: Any) -> str:
    """SHA-256 over canonical JSON, prefixed ``sha256:``."""
    return "sha256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()


def digest_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes) -> None:
    """Write *data* to *path* atomically (temp file + fsync + replace)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", suffix=p.suffix, dir=p.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def dump_json(obj: Any, path: str | os.PathLike[str]) -> None:
    """Persist *obj* as pretty JSON atomically (trailing newline)."""
    text = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    atomic_write_bytes(path, text.encode("utf-8"))


def dump_jsonl(rows: list[dict], path: str | os.PathLike[str]) -> None:
    """Persist one canonical JSON object per line atomically (``\\n`` only)."""
    body = "".join(canonical_json(r) + "\n" for r in rows)
    atomic_write_bytes(path, body.encode("utf-8"))


def load_json(path: str | os.PathLike[str]) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_jsonl(path: str | os.PathLike[str]) -> list[dict]:
    rows: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
    return rows


def write_manifest(root: str | os.PathLike[str], names: list[str],
                   path: str | os.PathLike[str]) -> dict:
    """Hash every artifact by relative name; persist and return the manifest."""
    root_p = Path(root)
    entries = []
    for name in names:
        fp = root_p / name
        if not fp.is_file():
            raise FileNotFoundError(f"manifest target missing: {fp}")
        entries.append({
            "path": name,
            "size": fp.stat().st_size,
            "sha256": hashlib.sha256(fp.read_bytes()).hexdigest(),
        })
    manifest = {"algorithm": "sha256", "entries": entries}
    dump_json(manifest, path)
    return manifest


def verify_manifest(root: str | os.PathLike[str],
                    path: str | os.PathLike[str]) -> tuple[bool, list[str]]:
    """Re-hash artifacts against a stored manifest; report mismatches."""
    root_p = Path(root)
    manifest = load_json(path)
    problems: list[str] = []
    for entry in manifest.get("entries", []):
        fp = root_p / entry["path"]
        if not fp.is_file():
            problems.append(f"missing: {entry['path']}")
            continue
        actual = hashlib.sha256(fp.read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            problems.append(f"digest mismatch: {entry['path']}")
        if fp.stat().st_size != entry["size"]:
            problems.append(f"size mismatch: {entry['path']}")
    return (not problems), problems
