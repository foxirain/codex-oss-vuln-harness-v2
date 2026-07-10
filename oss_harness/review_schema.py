from __future__ import annotations


TIERS = {'S', 'A', 'B', 'C', 'D'}
CONFIDENCES = {'high', 'medium', 'low'}
TIER_DISPOSITION = {
    'S': 'confirmed',
    'A': 'strong',
    'B': 'plausible',
    'C': 'weak',
    'D': 'reject',
}
STRING_FIELDS = (
    'finding_file', 'title', 'tier', 'confidence', 'disposition', 'summary',
    'entrypoint', 'reachability', 'attacker_control', 'sink', 'impact',
)
LIST_FIELDS = ('key_evidence', 'blocking_gaps', 'next_actions')
PLACEHOLDERS = {'', 'none', 'n/a', 'na', 'unknown', 'tbd', 'todo', 'not provided', 'insufficient evidence'}


def validate_review(data: dict, *, expected_finding: str | None = None) -> dict:
    if not isinstance(data, dict):
        raise ValueError('review must be a JSON object')
    normalized: dict = {}
    for field in STRING_FIELDS:
        value = data.get(field)
        if not isinstance(value, str):
            raise ValueError(f'review field {field!r} must be a string')
        normalized[field] = value.strip()
    for field in LIST_FIELDS:
        value = data.get(field)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f'review field {field!r} must be a list of strings')
        normalized[field] = [item.strip() for item in value if item.strip()]

    tier = normalized['tier'].upper()
    confidence = normalized['confidence'].lower()
    disposition = normalized['disposition'].lower()
    if tier not in TIERS:
        raise ValueError('review tier must be one of S, A, B, C, or D')
    if confidence not in CONFIDENCES:
        raise ValueError('review confidence must be high, medium, or low')
    if disposition != TIER_DISPOSITION[tier]:
        raise ValueError(f'disposition {disposition!r} is inconsistent with tier {tier}')
    if expected_finding is not None and normalized['finding_file'] != expected_finding:
        raise ValueError('review finding_file does not match the requested finding')
    if not _meaningful(normalized['title']) or not _meaningful(normalized['summary']):
        raise ValueError('review title and summary must be meaningful')
    if tier in {'S', 'A'}:
        for field in ('entrypoint', 'reachability', 'attacker_control', 'sink', 'impact'):
            if not _meaningful(normalized[field]):
                raise ValueError(f'{tier}-tier review requires meaningful {field}')
        if not any(_meaningful(value) for value in normalized['key_evidence']):
            raise ValueError(f'{tier}-tier review requires meaningful key evidence')

    normalized['tier'] = tier
    normalized['confidence'] = confidence
    normalized['disposition'] = disposition
    return normalized


def _meaningful(value: str) -> bool:
    normalized = ' '.join(value.lower().strip().strip('`').rstrip('.').split())
    if len(normalized) < 3 or normalized in PLACEHOLDERS:
        return False
    return not normalized.startswith(('unknown ', 'none ', 'n/a ', 'not applicable', 'not provided', 'insufficient evidence'))
