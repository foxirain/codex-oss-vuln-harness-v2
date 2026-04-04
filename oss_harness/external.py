from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from oss_harness.models import ExternalSignal

CRASH_CLASS_PATTERNS = {
    'asan': re.compile(r'addresssanitizer|asan', re.IGNORECASE),
    'ubsan': re.compile(r'ubsan|undefinedbehavior', re.IGNORECASE),
    'uaf': re.compile(r'use-after-free|heap-use-after-free', re.IGNORECASE),
    'oob': re.compile(r'out[- ]of[- ]bounds|buffer overflow|stack overflow', re.IGNORECASE),
    'null-deref': re.compile(r'null pointer|null dereference|segmentation fault|sigsegv', re.IGNORECASE),
    'panic': re.compile(r'panic:|fatal error:|thread .* panicked', re.IGNORECASE),
}

PATH_LINE_PATTERNS = [
    re.compile(r'(?P<path>[A-Za-z0-9_./\\-]+\.(?:c|cc|cpp|cxx|h|hpp|hh|go|rs|py|js|jsx|mjs|cjs|ts|tsx|java|kt|php|rb))(?:[:#](?P<line>\d+))?'),
]


def load_external_signal_index(path: Path | None) -> dict[str, list[ExternalSignal]]:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding='utf-8'))
    index: dict[str, list[ExternalSignal]] = {}
    for item in data.get('signals', []):
        rel_path = str(item.get('path', '')).strip().replace('\\', '/')
        if not rel_path:
            continue
        index.setdefault(rel_path, []).append(
            ExternalSignal(
                source=str(item.get('source', 'external')),
                weight=int(item.get('weight', 5)),
                summary=str(item.get('summary', 'external signal')),
                url=str(item.get('url', '')),
                metadata=dict(item.get('metadata', {})),
            )
        )
    return index


def load_crash_signal_index(repo_root: Path, crash_dir: Path | None, max_files: int = 200) -> dict[str, list[ExternalSignal]]:
    if crash_dir is None or not crash_dir.exists():
        return {}
    repo_files = [path for path in repo_root.rglob('*') if path.is_file()]
    path_index = _build_path_index(repo_root, repo_files)
    signals: dict[str, list[ExternalSignal]] = defaultdict(list)
    for crash_file in sorted(path for path in crash_dir.rglob('*') if path.is_file())[:max_files]:
        try:
            text = crash_file.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        severity, labels = _classify_crash(text)
        seen_paths: set[str] = set()
        for rel_path, line_no in _extract_paths(text, path_index):
            if rel_path in seen_paths:
                continue
            seen_paths.add(rel_path)
            summary = f"crash feed:{','.join(labels) or 'crash'} from {crash_file.name}"
            metadata = {'crash_file': crash_file.name, 'labels': labels}
            if line_no:
                metadata['line_no'] = line_no
            signals[rel_path].append(ExternalSignal(source='crash', weight=severity, summary=summary, metadata=metadata))
    return dict(signals)


def _build_path_index(repo_root: Path, repo_files: list[Path]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = defaultdict(list)
    for file_path in repo_files:
        rel = str(file_path.relative_to(repo_root)).replace('\\', '/')
        index[rel].append(rel)
        index[file_path.name].append(rel)
        tail = '/'.join(rel.split('/')[-2:])
        index[tail].append(rel)
    return index


def _classify_crash(text: str) -> tuple[int, list[str]]:
    labels = [label for label, pattern in CRASH_CLASS_PATTERNS.items() if pattern.search(text)]
    if not labels:
        return 6, []
    if any(label in {'asan', 'uaf', 'oob'} for label in labels):
        return 12, labels
    if any(label in {'ubsan', 'null-deref'} for label in labels):
        return 9, labels
    return 7, labels


def _extract_paths(text: str, path_index: dict[str, list[str]]) -> list[tuple[str, int | None]]:
    matches: list[tuple[str, int | None]] = []
    for pattern in PATH_LINE_PATTERNS:
        for match in pattern.finditer(text):
            raw_path = match.group('path').replace('\\', '/').lstrip('./')
            line_no = int(match.group('line')) if match.groupdict().get('line') else None
            candidates = path_index.get(raw_path) or path_index.get(Path(raw_path).name) or path_index.get('/'.join(raw_path.split('/')[-2:])) or []
            for candidate in candidates[:3]:
                matches.append((candidate, line_no))
    return matches
