from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

IMPORT_PATTERNS = {
    "python": [
        re.compile(r"^\s*import\s+([a-zA-Z0-9_\.]+)", re.MULTILINE),
        re.compile(r"^\s*from\s+([a-zA-Z0-9_\.]+)\s+import\s+", re.MULTILINE),
    ],
    "javascript": [
        re.compile(r"import\s+.*?from\s+['\"]([^'\"]+)['\"]"),
        re.compile(r"require\(['\"]([^'\"]+)['\"]\)"),
    ],
    "go": [
        re.compile(r"^\s*import\s+\(?\s*['\"]([^'\"]+)['\"]", re.MULTILINE),
        re.compile(r"^\s*['\"]([^'\"]+)['\"]", re.MULTILINE),
    ],
    "rust": [
        re.compile(r"\buse\s+([a-zA-Z0-9_:]+)"),
        re.compile(r"\bmod\s+([a-zA-Z0-9_]+)\s*;"),
    ],
    "java": [
        re.compile(r"^\s*import\s+([a-zA-Z0-9_\.]+);", re.MULTILINE),
    ],
    "php": [
        re.compile(r"\b(use|include|require)(_once)?\s*\(?\s*['\"]([^'\"]+)['\"]"),
    ],
    "ruby": [
        re.compile(r"\b(require|require_relative)\s+['\"]([^'\"]+)['\"]"),
    ],
}


def build_import_graph(repo_root: Path, language_map: dict[str, str], max_files: int = 5000) -> dict[str, dict[str, object]]:
    files = sorted(language_map)
    files = files[:max_files]
    module_index = _module_index(files)
    outgoing: dict[str, set[str]] = defaultdict(set)
    incoming: Counter[str] = Counter()

    for rel_path in files:
        language = language_map[rel_path]
        file_path = repo_root / rel_path
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        targets = _extract_targets(rel_path, language, text, module_index)
        for target in targets:
            if target == rel_path:
                continue
            outgoing[rel_path].add(target)
            incoming[target] += 1

    return {
        rel_path: {
            "imports": sorted(outgoing.get(rel_path, set())),
            "out_degree": len(outgoing.get(rel_path, set())),
            "in_degree": int(incoming.get(rel_path, 0)),
        }
        for rel_path in files
    }


def _module_index(files: list[str]) -> dict[str, str]:
    index: dict[str, str] = {}
    for rel_path in files:
        no_suffix = str(Path(rel_path).with_suffix(""))
        dotted = no_suffix.replace("/", ".")
        index[dotted] = rel_path
        index[no_suffix] = rel_path
        index[Path(no_suffix).name] = rel_path
    return index


def _extract_targets(rel_path: str, language: str, text: str, module_index: dict[str, str]) -> set[str]:
    targets: set[str] = set()
    patterns = IMPORT_PATTERNS.get(language, [])
    for pattern in patterns:
        for match in pattern.findall(text):
            raw = match[-1] if isinstance(match, tuple) else match
            normalized = _normalize_import(rel_path, language, raw)
            if not normalized:
                continue
            target = module_index.get(normalized) or module_index.get(normalized.replace("/", "."))
            if target:
                targets.add(target)
    return targets


def _normalize_import(rel_path: str, language: str, raw: str) -> str:
    value = raw.strip()
    if not value or value.startswith(("http://", "https://", "@types/")):
        return ""
    if language == "javascript":
        if value.startswith("."):
            base = (Path(rel_path).parent / value).resolve().as_posix()
            return Path(base).name
        return value.strip("/").replace("/", ".")
    if language == "python":
        return value.strip(".")
    if language == "rust":
        return value.replace("::", ".")
    if language == "go":
        return Path(value).name
    if language in {"java", "php", "ruby"}:
        return value.strip("/").replace("/", ".")
    return value
