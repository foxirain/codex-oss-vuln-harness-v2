from __future__ import annotations

import fnmatch
from pathlib import PurePosixPath


def normalize_paths(paths: list[str]) -> list[str]:
    return list(dict.fromkeys(_normalize(path) for path in paths if path))


def label_matches(path: str, label: str) -> bool:
    normalized_path = _normalize(path)
    normalized_label = _normalize(label)
    if any(token in normalized_label for token in ('*', '?', '[')):
        return fnmatch.fnmatchcase(normalized_path, normalized_label)
    if normalized_label.endswith('/'):
        return normalized_path.startswith(normalized_label)
    return normalized_path == normalized_label


def matching_paths(paths: list[str], labels: list[str]) -> list[str]:
    return sorted({path for path in normalize_paths(paths) if any(label_matches(path, label) for label in labels)})


def matched_labels(paths: list[str], labels: list[str]) -> list[str]:
    normalized_paths = normalize_paths(paths)
    return sorted({label for label in labels if any(label_matches(path, label) for path in normalized_paths)})


def _normalize(value: str) -> str:
    normalized = value.replace('\\', '/')
    while normalized.startswith('./'):
        normalized = normalized[2:]
    parts = PurePosixPath(normalized.rstrip('/')).parts
    if not normalized or normalized.startswith('/') or '..' in parts:
        raise ValueError(f'labels and ranked paths must be repository-relative: {value!r}')
    return normalized
