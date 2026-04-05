from __future__ import annotations

import hashlib
import re
from pathlib import Path

AUTOPILOT_FINDINGS_DIRNAME = 'autopilot/findings'


def finding_dir(session_dir: Path) -> Path:
    return session_dir / AUTOPILOT_FINDINGS_DIRNAME


def list_finding_files(session_dir: Path) -> list[Path]:
    base = finding_dir(session_dir)
    if not base.exists():
        return []
    return sorted(path for path in base.glob('finding-*.txt') if path.is_file())


def select_finding_files(session_dir: Path, selectors: list[str] | None = None) -> list[Path]:
    files = list_finding_files(session_dir)
    if not selectors:
        return files
    selected: list[Path] = []
    for selector in selectors:
        selector_path = Path(selector)
        if selector_path.exists():
            selected.append(selector_path.expanduser().resolve())
            continue
        for candidate in files:
            if selector == candidate.name or selector == candidate.stem or selector in candidate.name:
                selected.append(candidate)
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in selected:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def finding_slug(path: Path) -> str:
    stem = re.sub(r'[^a-zA-Z0-9._-]+', '-', path.stem).strip('-').lower() or 'finding'
    suffix = hashlib.sha1(str(path).encode('utf-8')).hexdigest()[:8]
    return f'{stem}-{suffix}'
