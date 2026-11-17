"""Apply workspace JSON Schemas without implicit external retrieval.

The default ``jsonschema`` registry fetches ``http(s)://`` and ``file://``
``$ref`` targets over the network or the local filesystem. Here every schema is validated through a
``referencing.Registry`` whose only retrieval path is a workspace-relative
file read:

* ``#...`` fragment references inside a loaded document resolve normally;
* relative references (``other.schema.json#/$defs/x``) resolve to files inside
  the workspace (no ``..`` escape, no symlink escape);
* the JSON Schema meta-schemas bundled with ``jsonschema-specifications``
  resolve locally;
* everything else (``http``, ``https``, ``file``, ``urn``, absolute paths,
  a foreign ``$id`` base) is unresolvable and validation fails closed.

Every document actually loaded (root and referenced) is reported with its
SHA-256 so callers can compare the closure against hashes frozen in a
contract or acceptance baseline. Resolution is lazy: only references the
validated document actually reaches are loaded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import referencing
import referencing.jsonschema
from jsonschema import Draft202012Validator
from referencing.exceptions import NoSuchResource, Unresolvable

from .canonical import resolve_in_workspace, sha256_hex

WORKSPACE_BASE = "https://phi-core.invalid/workspace/"
_URI_SAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/")


@dataclass(frozen=True)
class SchemaCheck:
    """``code`` is None when validation ran; ``valid`` is then True/False."""

    code: str | None
    valid: bool | None = None
    errors: tuple[str, ...] = ()
    closure: Mapping[str, str] = field(default_factory=dict)


def _uri_for(rel: str) -> str:
    return WORKSPACE_BASE + "".join(
        ch if ch in _URI_SAFE else "".join(f"%{b:02X}" for b in ch.encode("utf-8")) for ch in rel)


def _rel_from_uri(uri: str) -> str | None:
    """Inverse of :func:`_uri_for`; anything not under the workspace base is None."""
    if not uri.startswith(WORKSPACE_BASE) or any(c in uri for c in "?#\\"):
        return None
    tail = uri[len(WORKSPACE_BASE):].encode("utf-8")
    out, i = bytearray(), 0
    while i < len(tail):
        if tail[i:i + 1] == b"%":
            try:
                out.append(int(tail[i + 1:i + 3].decode("ascii"), 16))
            except ValueError:
                return None
            if len(tail[i + 1:i + 3]) != 2:
                return None
            i += 3
        else:
            out.append(tail[i])
            i += 1
    try:
        rel = out.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return rel or None


def _load_json_bytes(path: Path) -> tuple[Any, str]:
    data = path.read_bytes()
    return json.loads(data.decode("utf-8")), sha256_hex(data)


def check_document(workspace: str | Path, schema_rel: str, document: Any) -> SchemaCheck:
    """Validate ``document`` against the workspace schema at ``schema_rel``."""
    ws = Path(workspace)
    closure: dict[str, str] = {}
    root_path = resolve_in_workspace(ws, schema_rel)
    if root_path is None:
        return SchemaCheck("SCHEMA_PATH_OUTSIDE_WORKSPACE")
    if not root_path.is_file():
        return SchemaCheck("SCHEMA_FILE_MISSING")
    try:
        schema, digest = _load_json_bytes(root_path)
    except (OSError, ValueError):
        return SchemaCheck("SCHEMA_FILE_INVALID")
    closure[schema_rel] = digest
    try:
        Draft202012Validator.check_schema(schema)
    except Exception:  # noqa: BLE001 - any meta-schema problem means no usable criterion
        return SchemaCheck("SCHEMA_FILE_INVALID", closure=dict(closure))
    if isinstance(schema, dict) and "$id" not in schema:
        schema = {"$id": _uri_for(schema_rel), **schema}

    def retrieve(uri: str):
        rel = _rel_from_uri(uri)
        target = resolve_in_workspace(ws, rel) if rel is not None else None
        if target is None or not target.is_file():
            raise NoSuchResource(ref=uri)
        try:
            contents, ref_digest = _load_json_bytes(target)
        except (OSError, ValueError) as exc:
            raise NoSuchResource(ref=uri) from exc
        closure[rel] = ref_digest
        return referencing.Resource.from_contents(
            contents, default_specification=referencing.jsonschema.DRAFT202012)

    registry = referencing.Registry(retrieve=retrieve)
    try:
        validator = Draft202012Validator(schema, registry=registry)
        errors = sorted(e.message for e in validator.iter_errors(document))
    except Unresolvable:
        return SchemaCheck("SCHEMA_REF_UNRESOLVABLE", closure=dict(closure))
    except Exception:  # noqa: BLE001 - fail closed on any validator failure
        return SchemaCheck("SCHEMA_VALIDATION_ERROR", closure=dict(closure))
    return SchemaCheck(None, valid=not errors, errors=tuple(errors[:20]), closure=dict(closure))


def pin_issue(closure: Mapping[str, str], schema_rel: str, schema_sha256: Any,
              ref_pins: Mapping[str, Any] | None) -> tuple[str, str] | None:
    """Compare a loaded closure with frozen hashes.

    Returns ``None`` when every loaded document is pinned and matches, else
    ``("unresolved" | "violated", code)``: an unpinned criterion cannot be
    decided; a pinned criterion whose bytes differ is a verified violation."""
    if not isinstance(schema_sha256, str):
        return "unresolved", "SCHEMA_CRITERION_NOT_PINNED"
    if closure.get(schema_rel) != schema_sha256:
        return "violated", "SCHEMA_CRITERION_MODIFIED"
    pins = ref_pins if isinstance(ref_pins, Mapping) else {}
    for rel, digest in sorted(closure.items()):
        if rel == schema_rel:
            continue
        if rel not in pins:
            return "unresolved", "SCHEMA_REF_NOT_PINNED"
        if pins[rel] != digest:
            return "violated", "SCHEMA_CRITERION_MODIFIED"
    return None
