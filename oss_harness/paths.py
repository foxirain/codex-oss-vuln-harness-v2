from __future__ import annotations

import os
import re
import uuid
from pathlib import Path


_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_SYMBOL = re.compile(r"^[A-Za-z_~][A-Za-z0-9_.$:<>~\-]*(?:\([^\r\n]*\))?$")


def is_within(path: Path, root: Path) -> bool:
    """Return True only when *path* resolves beneath *root*."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def safe_repo_file(repo_root: Path, path: Path) -> Path | None:
    """Resolve a regular repository file without following repository symlinks."""
    root = repo_root.expanduser().resolve()
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return None
    current = root
    for part in relative.parts:
        if part in {'', '.', '..'}:
            return None
        current = current / part
        if current.is_symlink():
            return None
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not is_within(resolved, root) or not resolved.is_file():
        return None
    return resolved


def safe_repo_dir(repo_root: Path, path: Path) -> Path | None:
    root = repo_root.expanduser().resolve()
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return None
    current = root
    for part in relative.parts:
        if part in {'', '.', '..'}:
            return None
        current = current / part
        if current.is_symlink():
            return None
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not is_within(resolved, root) or not resolved.is_dir():
        return None
    return resolved


def iter_repo_files(repo_root: Path):
    """Yield only regular, non-symlink files contained by *repo_root*."""
    root = repo_root.expanduser().resolve()
    for path in root.rglob('*'):
        resolved = safe_repo_file(root, path)
        if resolved is not None:
            yield resolved


def validate_repo_target(repo_root: Path, raw_target: str) -> str:
    """Validate ``relative/file::optional_symbol`` and return canonical text."""
    value = raw_target.strip().strip('`').strip()
    if not value or '\x00' in value or '\n' in value or '\r' in value:
        raise ValueError('next target is empty or contains control characters')
    if value.startswith(('/', '\\', '//')) or _WINDOWS_DRIVE.match(value):
        raise ValueError('next target must be a repository-relative path')
    if '\\' in value:
        raise ValueError('next target must use repository-relative POSIX separators')

    path_text, separator, symbol = value.partition('::')
    path_text = path_text.strip()
    path = Path(path_text)
    if not path_text or path.is_absolute() or any(part in {'', '.', '..'} for part in path.parts):
        raise ValueError('next target contains an unsafe path')
    resolved = safe_repo_file(repo_root, path)
    if resolved is None:
        raise ValueError('next target is not a regular file inside the repository')
    root = repo_root.expanduser().resolve()
    canonical = resolved.relative_to(root).as_posix()
    if separator:
        symbol = symbol.strip().strip('`').strip()
        if not symbol or not _SYMBOL.fullmatch(symbol):
            raise ValueError('next target symbol has an invalid format')
        canonical = f'{canonical}::{symbol}'
    return canonical


def atomic_write_text(path: Path, text: str, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp')
    try:
        temporary.write_text(text, encoding='utf-8')
        if mode is not None:
            temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
