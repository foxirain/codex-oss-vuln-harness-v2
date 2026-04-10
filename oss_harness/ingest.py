from __future__ import annotations

import re
from pathlib import Path

STRICT_VERDICTS = {
    'cve_candidate',
    'plausible_security_bug',
    'latent_bug',
    'not_cve_candidate',
    'needs_more_context',
}

VERDICT_PATTERNS = [
    re.compile(r'strict verdict\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
    re.compile(r'final verdict\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
]

NEXT_PATTERNS = [
    re.compile(r'single best next (?:target|file|function)\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
    re.compile(r'single next (?:target|file|function)\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
]

BULLET_VALUE_PATTERNS = [re.compile(r'^\s*[-*]\s*(?P<value>.+?)\s*$')]

STRUCTURED_FIELDS = {
    'entrypoint': [
        re.compile(r'entrypoint\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
        re.compile(r'exact entrypoint\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
    ],
    'attacker_control': [
        re.compile(r'attacker[_\s-]*control\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
    ],
    'sink': [
        re.compile(r'sink\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
        re.compile(r'sensitive sink\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
        re.compile(r'invariant break\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
    ],
    'impact': [
        re.compile(r'impact\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
        re.compile(r'concrete impact\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
    ],
    'not_blocked_by': [
        re.compile(r'not blocked by\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
        re.compile(r'why checks fail\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
    ],
}


def load_response(path: Path | None, stdin_text: str) -> str:
    if path is not None:
        return path.read_text(encoding='utf-8')
    return stdin_text


def parse_response(text: str) -> dict:
    verdict = _extract_verdict(text)
    next_target = _extract_next_target(text)
    notes = _extract_notes(text)
    structured = _extract_structured_fields(text)
    should_continue = bool(next_target) and verdict not in {'cve_candidate', 'plausible_security_bug'}
    return {
        'verdict': verdict,
        'next_target': next_target,
        'notes': notes,
        'structured': structured,
        'promotion_ready': _promotion_ready(verdict, structured),
        'should_continue': should_continue,
    }


def _extract_verdict(text: str) -> str:
    lines = text.splitlines()
    for pattern in VERDICT_PATTERNS:
        for index, line in enumerate(lines):
            match = pattern.search(line)
            if not match:
                continue
            value = _normalize_inline_value(match.group('value'))
            if not value and index + 1 < len(lines):
                value = _extract_bullet_value(lines[index + 1])
            mapped = _map_verdict(value)
            if mapped:
                return mapped
    raise ValueError('could not extract verdict from Codex response')


def _extract_next_target(text: str) -> str:
    lines = text.splitlines()
    for pattern in NEXT_PATTERNS:
        for index, line in enumerate(lines):
            match = pattern.search(line)
            if not match:
                continue
            value = _normalize_inline_value(match.group('value'))
            if not value and index + 1 < len(lines):
                value = _extract_bullet_value(lines[index + 1])
            if value and value.lower() not in {'none', 'n/a', 'na', '없음'}:
                return value
    return ''


def _extract_notes(text: str, limit: int = 320) -> str:
    compact = ' '.join(line.strip() for line in text.splitlines() if line.strip())
    compact = re.sub(r'\s+', ' ', compact)
    return compact[:limit]


def _extract_structured_fields(text: str) -> dict[str, str]:
    extracted: dict[str, str] = {}
    lines = text.splitlines()
    for field_name, patterns in STRUCTURED_FIELDS.items():
        extracted[field_name] = _extract_labeled_field(lines, patterns)
    return extracted


def _extract_labeled_field(lines: list[str], patterns: list[re.Pattern[str]]) -> str:
    for pattern in patterns:
        for index, line in enumerate(lines):
            match = pattern.search(line)
            if not match:
                continue
            value = _normalize_inline_value(match.group('value'))
            if not value and index + 1 < len(lines):
                value = _extract_bullet_value(lines[index + 1])
            if value:
                return value
    return ''


def _normalize_inline_value(value: str) -> str:
    value = value.strip()
    if value in {'', '-', '*'}:
        return ''
    return value.strip('` ')


def _extract_bullet_value(line: str) -> str:
    for pattern in BULLET_VALUE_PATTERNS:
        match = pattern.match(line)
        if match:
            return match.group('value').strip().strip('`')
    return ''


def _map_verdict(value: str) -> str:
    if not value:
        return ''
    lowered = value.lower().strip()
    normalized = lowered.replace(' ', '_').replace('-', '_')
    if normalized in STRICT_VERDICTS:
        return normalized
    return ''


def _promotion_ready(verdict: str, structured: dict[str, str]) -> bool:
    if verdict not in {'cve_candidate', 'plausible_security_bug'}:
        return False
    return all(structured.get(field, '').strip() for field in ('entrypoint', 'attacker_control', 'sink', 'impact'))
