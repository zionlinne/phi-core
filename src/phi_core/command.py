"""Frozen-criterion protocol for Acceptance ``command`` requirements.

Roles are explicit and never inferred from ``artifacts``:

* **Criterion** files are listed in ``pinned_files`` with their SHA-256. They
  are read once, hashed in memory, and only those verified bytes are written
  into the execution snapshot.
* The **program** is the code the command executes from the workspace: the
  ``{python}`` script, every file that ``-m module`` can load from the
  workspace (module file, package ``__init__``/``__main__``), or a workspace
  ``argv[0]``. A workspace program must be a criterion file. ``artifacts``
  cannot waive this.
* **Data** arguments of a ``{python}`` program that name workspace files must
  be pinned or lie inside a declared ``artifacts`` path. For any program
  other than ``{python}`` the library cannot tell data from code, so every
  workspace file named in argv must be pinned.

Paths fail closed: a token that names an existing path through a symlink,
junction or alias resolving outside the workspace, a dangling or looping
link, a relative ``..`` escape, or an absolute path into the workspace makes
the result INCONCLUSIVE before anything runs. External link targets are never
read.

The command runs with its working directory set to a private snapshot
directory outside the workspace: a copy of the workspace (``__pycache__``
and links that leave the workspace omitted) with every criterion file
overwritten by its verified bytes. Writes to the workspace during the run
therefore cannot change the bytes the command reads. The snapshot is
re-hashed after the run; files the command created or changed (other than
criterion files and ``__pycache__``) are then copied back into the workspace
without following links, so checker reports still appear there.
It is private to the acceptance process by file mode only: a malicious
process running under the same OS account is out of scope.
"""

from __future__ import annotations

import importlib.machinery
import os
import pkgutil
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .canonical import sha256_hex

_PY_OPTS_WITH_VALUE = set("cmWX")
_PY_LONG_OPTS_WITH_VALUE = {"--check-hash-based-pycs"}
_HAS_FD_WALK = hasattr(os, "fwalk") and os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")


class Refusal(Exception):
    def __init__(self, status: str, code: str, detail: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.status, self.code, self.detail = status, code, dict(detail or {})


def _inc(code: str, **detail: Any) -> Refusal:
    return Refusal("INCONCLUSIVE", code, detail)


def _inside(root: Path, p: Path) -> bool:
    try:
        p.relative_to(root)
    except ValueError:
        return False
    return True


def _visited(path: str, limit: int = 64) -> list[Path]:
    """Every path visited while resolving ``path`` component by component,
    including each symlink location and each directory traversed."""
    p = Path(path)
    cur = Path(p.anchor or os.sep)
    pending = list(p.parts[1:]) if p.anchor else list(p.parts)
    seen, hops = [cur], 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            cur = cur.parent
            seen.append(cur)
            continue
        nxt = cur / part
        seen.append(nxt)
        if os.path.islink(nxt):
            hops += 1
            if hops > limit:
                break
            target = Path(os.readlink(nxt))
            if target.is_absolute():
                cur = Path(target.anchor)
                pending = list(target.parts[1:]) + pending
            else:
                pending = list(target.parts) + pending
        else:
            cur = nxt
    return seen


@dataclass
class _Paths:
    ws: Path      # absolute, as given
    root: Path    # fully resolved

    def lexical_inside(self, p: Path) -> bool:
        p = Path(os.path.normpath(p))
        return _inside(self.ws, p) or _inside(self.root, p)

    def host_path_touches_workspace(self, path: str) -> bool:
        """True when resolving a host path passes through the workspace at any
        hop, so the producer could redirect it."""
        if self.lexical_inside(Path(path)):
            return True
        try:
            if _inside(self.root, Path(path).resolve()):
                return True
        except (OSError, RuntimeError):
            pass
        return any(self.lexical_inside(v) for v in _visited(path))

    def resolve(self, cand: Path, token: str) -> Path:
        try:
            real = cand.resolve(strict=True)
        except (OSError, RuntimeError):
            raise _inc("COMMAND_PATH_ESCAPES_WORKSPACE", token=token, reason="unresolvable") from None
        if not _inside(self.root, real):
            raise _inc("COMMAND_PATH_ESCAPES_WORKSPACE", token=token, reason="resolves-outside-workspace")
        return real

    def token(self, tok: str) -> Path | None:
        """Resolved workspace path named by ``tok``; None when it names no
        existing workspace path (plain text, or a host path outside it)."""
        if not tok or "\x00" in tok:
            return None
        p = Path(tok)
        if p.is_absolute():
            if self.host_path_touches_workspace(tok):
                raise _inc("COMMAND_ABSOLUTE_WORKSPACE_PATH", token=tok)
            return None
        norm = os.path.normpath(tok)
        if norm == ".." or norm.startswith(".." + os.sep) or norm.startswith("../"):
            raise _inc("COMMAND_PATH_ESCAPES_WORKSPACE", token=tok, reason="relative-escape")
        cand = self.ws / norm
        if not os.path.lexists(cand):
            return None
        return self.resolve(cand, tok)

    def rel(self, real: Path) -> str:
        return real.relative_to(self.root).as_posix() if real != self.root else "."


@dataclass
class _Plan:
    argv: list[str]
    program: list[str] = field(default_factory=list)
    data: list[str] = field(default_factory=list)
    strict: bool = False
    path0: str | None = None  # workspace dir Python puts first on sys.path


def _files_under(real: Path) -> list[Path]:
    if real.is_file():
        return [real]
    return sorted(f for f in real.rglob("*") if f.is_file() and "__pycache__" not in f.parts)


def _module_candidates(paths: _Paths, module: str) -> list[str]:
    parts = [x for x in module.split(".") if x]
    found: list[str] = []
    for k, part in enumerate(parts):
        parent = paths.token(os.path.join(*parts[:k])) if k else paths.root
        if parent is None or not parent.is_dir():
            break
        last = k == len(parts) - 1
        for entry in sorted(os.listdir(parent)):
            if entry != part and not entry.startswith(part + "."):
                continue
            real = paths.token(os.path.join(*parts[:k], entry))
            if real is None:
                continue
            if real.is_file():
                found.append(paths.rel(real))
            elif real.is_dir() and entry == part:
                for inner in sorted(os.listdir(real)):
                    stem = inner.split(".", 1)[0]
                    if stem == "__init__" or (last and stem == "__main__"):
                        sub = paths.token(os.path.join(*parts[:k], entry, inner))
                        if sub is not None and sub.is_file():
                            found.append(paths.rel(sub))
    return found


def _opt_value(tok: str) -> str | None:
    if tok.startswith("-") and "=" in tok:
        return tok.split("=", 1)[1]
    return None


def _plan_python(argv: list[str], paths: _Paths) -> _Plan:
    plan = _Plan(argv=argv)
    i, n = 1, len(argv)
    script = module = None
    inline = safe_path = False
    while i < n:
        t = argv[i]
        if t == "--":
            i += 1
            if i < n:
                script, i = argv[i], i + 1
            break
        if t == "-":
            raise _inc("COMMAND_PROGRAM_UNSUPPORTED", reason="python program read from stdin")
        if t.startswith("--"):
            i += 2 if t in _PY_LONG_OPTS_WITH_VALUE else 1
            continue
        if t.startswith("-") and len(t) > 1:
            j, consumed_next = 1, False
            while j < len(t):
                ch = t[j]
                if ch in "IP":
                    safe_path = True
                if ch in _PY_OPTS_WITH_VALUE:
                    val = t[j + 1:]
                    if not val:
                        val = argv[i + 1] if i + 1 < n else ""
                        consumed_next = True
                    if ch == "c":
                        inline = True
                    elif ch == "m":
                        module = val
                    break
                j += 1
            i += 2 if consumed_next else 1
            if inline or module is not None:
                break
            continue
        script, i = t, i + 1
        break
    if script is None and module is None and not inline:
        raise _inc("COMMAND_PROGRAM_UNSUPPORTED", reason="interactive python has no program")
    if script is not None:
        real = paths.token(script)
        if real is not None:
            plan.program += [paths.rel(f) for f in _files_under(real)]
            if not safe_path:
                plan.path0 = paths.rel(real if real.is_dir() else real.parent)
    else:
        if not safe_path:
            plan.path0 = "."
    if module is not None:
        plan.program += _module_candidates(paths, module)
    for tok in argv[i:]:
        for cand in (tok, _opt_value(tok)):
            if cand is None:
                continue
            real = paths.token(cand)
            if real is not None:
                plan.data += [paths.rel(f) for f in _files_under(real)]
    return plan


def _trusted_module_names(exclude: list[Path]) -> set[str]:
    """Top-level modules the checker would otherwise import from the standard
    library or the interpreter's installed packages."""
    names = set(sys.builtin_module_names) | set(getattr(sys, "stdlib_module_names", ()))
    for entry in sys.path:
        if not entry:
            continue
        try:
            real = Path(entry).resolve()
        except (OSError, RuntimeError):
            continue
        if any(_inside(x, real) or _inside(real, x) for x in exclude) or not real.is_dir():
            continue
        names.update(m.name for m in pkgutil.iter_modules([str(real)]))
    return names


def _shadowing(snap: Path, path0: str, trusted: set[str]) -> list[str]:
    """Workspace files in the first ``sys.path`` directory that would be imported
    in place of a trusted module (module files, compiled modules, packages)."""
    base = snap / path0
    suffixes = sorted(importlib.machinery.all_suffixes(), key=len, reverse=True)
    found = []
    for entry in sorted(os.listdir(base)):
        full = base / entry
        if full.is_file():
            name = next((entry[:-len(x)] for x in suffixes if entry.endswith(x)), None)
            if name in trusted:
                found.append(full.relative_to(snap).as_posix())
        elif full.is_dir() and entry in trusted:
            for inner in sorted(os.listdir(full)):
                if inner.split(".", 1)[0] == "__init__" and (full / inner).is_file():
                    found += [f.relative_to(snap).as_posix() for f in _files_under(full)]
                    break
    return found


def _clean_path(path_value: str, paths: _Paths) -> str:
    keep = []
    for entry in path_value.split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        if paths.host_path_touches_workspace(entry):
            continue
        keep.append(entry)
    return os.pathsep.join(keep)


def _plan_external(argv: list[str], paths: _Paths, path_value: str) -> _Plan:
    plan = _Plan(argv=list(argv), strict=True)
    prog = argv[0]
    if "/" in prog or os.sep in prog:
        real = paths.token(prog)
        if real is not None:
            plan.program.append(paths.rel(real))
    else:
        found = shutil.which(prog, path=path_value)
        if found is None:
            raise _inc("COMMAND_NOT_RUNNABLE", reason="program not found on PATH", program=prog)
        if paths.host_path_touches_workspace(found):
            raise _inc("COMMAND_PROGRAM_IN_WORKSPACE", program=prog)
        plan.argv[0] = found
    for tok in argv[1:]:
        for cand in (tok, _opt_value(tok)):
            if cand is None:
                continue
            real = paths.token(cand)
            if real is not None:
                plan.data += [paths.rel(f) for f in _files_under(real)]
    return plan


def _read_nofollow(root: Path, rel: str) -> bytes:
    """Read a resolved workspace file without following any link on the way, so a
    path component swapped for a symlink after resolution fails instead of
    reading outside the workspace."""
    parts = Path(rel).parts
    if not _HAS_FD_WALK:
        return (root / rel).read_bytes()
    fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0), dir_fd=fd)
            os.close(fd)
            fd = nxt
        ffd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    finally:
        os.close(fd)
    with os.fdopen(ffd, "rb") as fh:
        return fh.read()


def _verify_pins(spec, paths: _Paths, modified_code: str) -> dict[str, tuple[bytes, int]]:
    """Verified criterion bytes and file mode keyed by resolved relative path."""
    out: dict[str, tuple[bytes, int]] = {}
    for pin in spec.get("pinned_files", []):
        rel = pin["path"]
        try:
            real = paths.token(rel)
        except Refusal:
            real = None
        if real is None or Path(rel).is_absolute() or not real.is_file():
            raise Refusal("FAIL", "COMMAND_PINNED_FILE_MISSING", {"path": rel})
        key = paths.rel(real)
        try:
            data = _read_nofollow(paths.root, key)
            mode = real.stat().st_mode
        except OSError:
            raise Refusal("FAIL", "COMMAND_PINNED_FILE_MISSING", {"path": rel}) from None
        if sha256_hex(data) != pin["sha256"]:
            raise Refusal("FAIL", modified_code, {"path": rel})
        out[key] = (data, mode)
    return out


def _artifact_roots(spec, paths: _Paths) -> list[str]:
    roots = []
    for a in spec.get("artifacts", []):
        real = paths.token(a)
        if real is not None:
            roots.append(paths.rel(real))
    return roots


def _covered(rel: str, roots: list[str]) -> bool:
    return any(r == "." or rel == r or rel.startswith(r + "/") for r in roots)


def _write_file(dest: Path, data: bytes, mode: int) -> None:
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, (mode & 0o755) | 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _link_into_snapshot(paths: _Paths, snap: Path, rel: str, omitted: list[str]) -> None:
    try:
        real = paths.resolve(paths.root / rel, rel)
    except Refusal:
        omitted.append(rel)
        return
    link = snap / rel
    os.symlink(os.path.relpath(snap / paths.rel(real), link.parent), link)


def _copy_workspace(paths: _Paths, snap: Path, copied: dict[str, str]) -> dict[str, Any]:
    omitted: list[str] = []
    skipped: list[str] = []
    count = 0
    root = str(paths.root)
    if _HAS_FD_WALK:
        walker = os.fwalk(root, follow_symlinks=False)
    else:
        walker = ((d, ds, fs, None) for d, ds, fs in os.walk(root, followlinks=False))
    for dirpath, dirnames, filenames, dirfd in walker:
        reldir = os.path.relpath(dirpath, root)
        reldir = "" if reldir == "." else reldir
        for name in list(dirnames) + list(filenames):
            rel = os.path.join(reldir, name) if reldir else name
            st = os.stat(name, dir_fd=dirfd, follow_symlinks=False) if dirfd is not None else \
                os.lstat(os.path.join(dirpath, name))
            if stat.S_ISLNK(st.st_mode):
                if name in dirnames:
                    dirnames.remove(name)
                _link_into_snapshot(paths, snap, rel, omitted)
            elif stat.S_ISDIR(st.st_mode):
                if name == "__pycache__":
                    dirnames.remove(name)
                    skipped.append(rel)
                else:
                    (snap / rel).mkdir(mode=0o700)
            elif stat.S_ISREG(st.st_mode):
                if dirfd is not None:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dirfd)
                    with os.fdopen(fd, "rb") as fh:
                        data = fh.read()
                else:
                    data = Path(dirpath, name).read_bytes()
                _write_file(snap / rel, data, st.st_mode)
                copied[Path(rel).as_posix()] = sha256_hex(data)
                count += 1
            else:
                skipped.append(rel)
    return {"files_copied": count, "omitted_links_leaving_workspace": sorted(omitted)[:50],
            "skipped": sorted(skipped)[:50]}


def _write_back_nofollow(root: Path, rel: str, data: bytes) -> None:
    parts = Path(rel).parts
    if not _HAS_FD_WALK:
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if any(p.is_symlink() for p in [dest, *dest.parents] if _inside(root, p)):
            raise OSError("symlink on write-back path")
        dest.write_bytes(data)
        return
    dflag = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for part in parts[:-1]:
            try:
                nxt = os.open(part, dflag, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o755, dir_fd=fd)
                nxt = os.open(part, dflag, dir_fd=fd)
            os.close(fd)
            fd = nxt
        ffd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644, dir_fd=fd)
    finally:
        os.close(fd)
    with os.fdopen(ffd, "wb") as fh:
        fh.write(data)


def _write_back(paths: _Paths, snap: Path, copied: dict[str, str], pinned) -> dict[str, list[str]]:
    """Copy files the command created or changed back into the workspace, never
    criterion files, never ``__pycache__``, never through a link."""
    written, refused = [], []
    for dirpath, dirnames, filenames in os.walk(snap, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != "__pycache__" and not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            full = Path(dirpath, name)
            if full.is_symlink() or not full.is_file():
                continue
            rel = full.relative_to(snap).as_posix()
            if rel in pinned:
                continue
            data = full.read_bytes()
            if copied.get(rel) == sha256_hex(data):
                continue
            try:
                _write_back_nofollow(paths.root, rel, data)
                written.append(rel)
            except OSError:
                refused.append(rel)
    return {"outputs_written_back": sorted(written)[:50], "outputs_not_written_back": sorted(refused)[:50]}


def _make_snapshot_dir(paths: _Paths) -> Path:
    snap = Path(tempfile.mkdtemp(prefix="phi-accept-")).resolve()
    if _inside(paths.root, snap) or _inside(snap, paths.root):
        shutil.rmtree(snap, ignore_errors=True)
        raise _inc("COMMAND_SNAPSHOT_INSIDE_WORKSPACE")
    return snap


def _tail(text: str, n: int = 2000) -> str:
    return text[-n:] if text else ""


def _role_problem(plan: _Plan, pinned, artifacts: list[str]):
    program_unpinned = sorted({p for p in plan.program if p not in pinned})
    data_unpinned = sorted({d for d in plan.data if d not in pinned
                            and (plan.strict or not _covered(d, artifacts))})
    if not program_unpinned and not data_unpinned:
        return None
    return "INCONCLUSIVE", ["COMMAND_WORKSPACE_FILE_NOT_PINNED"], {
        "unpinned": sorted(set(program_unpinned) | set(data_unpinned))[:50],
        "program_not_pinned": program_unpinned[:50],
        "data_not_pinned_or_declared": data_unpinned[:50],
        "artifacts_waive_data_only": True,
        "argv_roles": "unparsed-program-all-pinned" if plan.strict else "python",
    }


def run_command(spec: Mapping[str, Any], workspace: Path, command_env: Mapping[str, str] | None):
    """Return ``(status, reason_codes, detail)`` for one command requirement."""
    try:
        return _run(spec, workspace, command_env)
    except Refusal as r:
        return r.status, [r.code], r.detail


def _run(spec, workspace: Path, command_env):
    paths = _Paths(Path(os.path.abspath(workspace)), Path(workspace).resolve())
    env = dict(command_env) if command_env is not None else {"PATH": os.environ.get("PATH", "")}
    env["PATH"] = _clean_path(env.get("PATH", ""), paths)
    pinned = _verify_pins(spec, paths, "COMMAND_PINNED_FILE_MODIFIED")

    argv = list(spec["argv"])
    if argv[0] == "{python}":
        if paths.host_path_touches_workspace(sys.executable):
            raise _inc("COMMAND_INTERPRETER_IN_WORKSPACE")
        argv = [sys.executable if a == "{python}" else a for a in argv]
        plan = _plan_python(argv, paths)
    else:
        argv = [sys.executable if a == "{python}" else a for a in argv]
        plan = _plan_external(argv, paths, env["PATH"])

    refused = _role_problem(plan, pinned, _artifact_roots(spec, paths))
    if refused is not None:
        return refused

    snap = _make_snapshot_dir(paths)
    try:
        copied_hashes: dict[str, str] = {}
        copied = _copy_workspace(paths, snap, copied_hashes)
        for rel, (data, mode) in pinned.items():
            dest = snap / rel
            if dest.is_symlink() or dest.exists():
                dest.unlink()
            dest.parent.mkdir(parents=True, exist_ok=True)
            _write_file(dest, data, mode)
        # Roles are checked again on the private snapshot: the bytes that run.
        spaths = _Paths(snap, snap)
        splan = _plan_python(plan.argv, spaths) if not plan.strict else _plan_external(plan.argv, spaths, env["PATH"])
        refused = _role_problem(splan, pinned, _artifact_roots(spec, spaths))
        if refused is not None:
            refused[2]["changed_while_snapshotting"] = True
            return refused
        if splan.path0 is not None:
            shadows = [x for x in _shadowing(snap, splan.path0, _trusted_module_names([paths.root, snap]))
                       if x not in pinned]
            if shadows:
                return "INCONCLUSIVE", ["COMMAND_WORKSPACE_SHADOWS_MODULE"], {"shadowing_not_pinned": shadows[:50]}
        try:
            proc = subprocess.run(plan.argv, cwd=snap, capture_output=True, text=True, shell=False,
                                  stdin=subprocess.DEVNULL, timeout=spec.get("timeout_seconds", 120), env=env)
        except subprocess.TimeoutExpired:
            return "INCONCLUSIVE", ["COMMAND_TIMEOUT"], {}
        except OSError as exc:
            return "INCONCLUSIVE", ["COMMAND_NOT_RUNNABLE"], {"error": type(exc).__name__}
        detail = {
            "exit_code": proc.returncode, "stdout_tail": _tail(proc.stdout), "stderr_tail": _tail(proc.stderr),
            "pinned_files_verified": [p["path"] for p in spec.get("pinned_files", [])],
            "execution": {"cwd": "frozen-snapshot", "program": plan.program,
                          "argv_roles": "unparsed-program-all-pinned" if plan.strict else "python", **copied},
        }
        for rel, (data, _mode) in pinned.items():
            dest = snap / rel
            if dest.is_symlink() or not dest.is_file() or sha256_hex(dest.read_bytes()) != sha256_hex(data):
                return "FAIL", ["COMMAND_PINNED_FILE_MODIFIED_DURING_RUN"], {**detail, "path": rel,
                                                                             "where": "snapshot"}
        detail["execution"].update(_write_back(paths, snap, copied_hashes, pinned))
    finally:
        shutil.rmtree(snap, ignore_errors=True)
    try:
        _verify_pins(spec, paths, "COMMAND_PINNED_FILE_MODIFIED_DURING_RUN")
    except Refusal as r:
        return "FAIL", [r.code], {**detail, **r.detail, "where": "workspace"}
    if proc.returncode == spec.get("expected_exit_code", 0):
        return "PASS", ["COMMAND_EXIT_CODE_AS_EXPECTED"], detail
    return "FAIL", ["COMMAND_EXIT_CODE_UNEXPECTED"], detail
