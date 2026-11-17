"""Canonical JSON, SHA-256 and explicit-time helpers shared by all modules."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)

ZERO_HASH = "0" * 64


def canonical_json(obj: Any) -> str:
    """Deterministic JSON text: sorted keys, no whitespace, no NaN/Infinity."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical_json(obj).encode("utf-8"))


def safe_hash_obj(obj: Any) -> str:
    """Like :func:`hash_obj` but never raises (non-JSON input hashes its repr, tagged)."""
    try:
        return hash_obj(obj)
    except (TypeError, ValueError):
        return sha256_hex(("non-json:" + repr(obj)).encode("utf-8"))


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def freeze(obj: Any) -> Any:
    """Recursively read-only view of JSON data (dict -> MappingProxyType, list -> tuple)."""
    if isinstance(obj, dict):
        return MappingProxyType({k: freeze(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return tuple(freeze(v) for v in obj)
    return obj


def parse_time(value: Any) -> datetime:
    """Parse an RFC 3339 timestamp that carries an explicit offset; return aware UTC."""
    if not isinstance(value, str) or not _RFC3339.match(value):
        raise ValueError(f"not an RFC 3339 timestamp with timezone: {value!r}")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def format_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
