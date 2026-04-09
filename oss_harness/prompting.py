from __future__ import annotations

from pathlib import Path

from oss_harness.models import Candidate

BASE_PLAYBOOK = """Audit one target for a plausible CVE-grade vulnerability.

Keep a high bar:
- confirm a real attacker-controlled entrypoint
- identify the exact sink, lifetime break, parser failure, or trust-boundary mistake
- explain concrete impact
- if evidence is weak, return a strict negative verdict and one best next target
"""


def _candidate_value(candidate: Candidate | dict, key: str, default):
    if isinstance(candidate, dict):
        return candidate.get(key, default)
    return getattr(candidate, key, default)


def prompt_profile_for_candidate(candidate: Candidate | dict) -> str:
    language = str(_candidate_value(candidate, 'language', '') or '')
    exposure = str(_candidate_value(candidate, 'exposure', '') or '')
    score = int(_candidate_value(candidate, 'score', 0) or 0)
    sinks = {str(item) for item in (_candidate_value(candidate, 'sink_kinds', []) or [])}
    external = _candidate_value(candidate, 'external_signals', []) or []
    sources = {
        str(item.get('source', '')) if isinstance(item, dict) else str(getattr(item, 'source', ''))
        for item in external
    }
    strong_external = any(
        (int(item.get('weight', 0)) if isinstance(item, dict) else int(getattr(item, 'weight', 0))) >= 8
        for item in external
    )
    native_deep_exposures = {
        'transport or protocol state machine',
        'trust-material or handshake path',
        'control-plane or resolver path',
        'allocator or buffer-management path',
        'memory-corruption-prone native path',
    }
    if (
        score >= 120
        or strong_external
        or exposure in native_deep_exposures
        or {'crash', 'sanitizer', 'advisory', 'cve'} & sources
        or (language == 'c_cpp' and 'memory-sensitive native path' in sinks and score >= 55)
    ):
        return 'deep'
    if (
        score >= 45
        or len(sinks) >= 2
        or exposure in {'remote API', 'auth boundary', 'language binding or FFI path'}
        or language == 'c_cpp'
    ):
        return 'balanced'
    return 'lean'


def should_attach_snippet(candidate: Candidate | dict, *, requested: bool, attempt: int = 0) -> bool:
    if not requested or attempt > 0:
        return False
    profile = prompt_profile_for_candidate(candidate)
    if profile == 'deep':
        return True
    if profile == 'balanced':
        score = int(_candidate_value(candidate, 'score', 0) or 0)
        exposure = str(_candidate_value(candidate, 'exposure', '') or '')
        return score >= 70 or exposure in {
            'transport or protocol state machine',
            'trust-material or handshake path',
            'control-plane or resolver path',
            'language binding or FFI path',
        }
    return False


def render_bundle_prompt(repo_root: Path, candidate: Candidate, policy: dict, *, profile: str | None = None) -> str:
    profile = profile or prompt_profile_for_candidate(candidate)
    rel_path = candidate.path.relative_to(repo_root)
    surfaces = ', '.join(candidate.attack_surfaces[:3]) or 'unclassified'
    sinks = ', '.join(candidate.sink_kinds[:3]) or 'unclassified'
    frameworks = ', '.join(candidate.framework_hints[:3]) or 'none'
    entrypoints = ', '.join(candidate.entrypoint_markers[:3]) or 'none'
    return f"""{BASE_PLAYBOOK}

Target:
- file: `{rel_path}`
- language: `{candidate.language}`
- subsystem: `{candidate.subsystem}`
- exposure: `{candidate.exposure}`
- score: `{candidate.score}`
- prompt profile: `{profile}`
- attack surfaces: `{surfaces}`
- sink kinds: `{sinks}`
- framework hints: `{frameworks}`
- entrypoint markers: `{entrypoints}`

Policy focus:
{render_policy_focus(policy, candidate, profile=profile)}

Why this target is high-value:
{_render_reasons(candidate, profile)}

Observed signals:
{_render_signals(candidate, profile)}

External context:
{_render_external(candidate, profile)}

Primary symbols:
{_render_symbols(candidate, profile)}

Semantic summary:
{_render_semantic(candidate, profile)}

Required output:
- strict verdict: one of `cve_candidate`, `plausible_security_bug`, `latent_bug`, `not_cve_candidate`, `needs_more_context`
- short analysis: exact entrypoint, attacker control, sink or invariant break, impact, and why checks fail or hold
- one best next target only, or `none`
"""


def render_policy_focus(policy: dict, candidate: Candidate | dict, *, profile: str | None = None) -> str:
    profile = profile or prompt_profile_for_candidate(candidate)
    rel_path = str(_candidate_value(candidate, 'path', ''))
    lowered_path = rel_path.replace('\\', '/').lower()
    sinks = {str(item).lower() for item in (_candidate_value(candidate, 'sink_kinds', []) or [])}
    sections: list[str] = []

    def add_section(title: str, items: list[str], limit: int) -> None:
        selected = [str(item).strip() for item in items if str(item).strip()][:limit]
        if selected:
            sections.append(f"{title}: " + '; '.join(selected))

    add_section('In scope', policy.get('in_scope', []), 3 if profile == 'lean' else 4)
    add_section('Out of scope', policy.get('out_of_scope', []), 2)
    add_section('Forbidden', policy.get('forbidden_findings', []), 2)

    entry_points = [item for item in policy.get('entry_points', []) if _policy_item_matches_path(item, lowered_path)]
    if not entry_points:
        entry_points = list(policy.get('entry_points', [])[: (2 if profile == 'lean' else 3)])
    add_section('Relevant entrypoints', entry_points, 2 if profile == 'lean' else 3)

    hot_paths = [item for item in policy.get('hot_paths', []) if _policy_item_matches_path(item, lowered_path)]
    add_section('Matching hot paths', hot_paths, 2)

    preferred_sinks = [item for item in policy.get('preferred_sinks', []) if any(token in str(item).lower() for token in sinks)]
    if not preferred_sinks and profile != 'lean':
        preferred_sinks = list(policy.get('preferred_sinks', [])[:2])
    add_section('Preferred sinks', preferred_sinks, 2)

    add_section('Preferred bug classes', policy.get('preferred_bug_classes', []), 2 if profile == 'lean' else 3)
    add_section('Notes', policy.get('notes', []), 1 if profile == 'lean' else 2)
    return '\n'.join(f'- {item}' for item in sections) or '- no explicit policy focus available'


def _policy_item_matches_path(item: str, lowered_path: str) -> bool:
    token = str(item).strip().strip('`').replace('\\', '/').strip('/').lower()
    if not token:
        return False
    return token in lowered_path


def _render_reasons(candidate: Candidate, profile: str) -> str:
    limit = {'lean': 5, 'balanced': 7, 'deep': 9}[profile]
    items = candidate.reasons[:limit]
    return '\n'.join(f'- {reason}' for reason in items) or '- no ranking reasons captured'


def _render_signals(candidate: Candidate, profile: str) -> str:
    limit = {'lean': 3, 'balanced': 4, 'deep': 5}[profile]
    lines = [
        f"- line {signal.line_no}: `{signal.name}` (+{signal.weight}) :: {signal.rationale}"
        for signal in candidate.signals[:limit]
    ]
    return '\n'.join(lines) or '- no line-level signals captured'


def _render_external(candidate: Candidate, profile: str) -> str:
    limit = {'lean': 3, 'balanced': 4, 'deep': 5}[profile]
    lines = [
        f"- {signal.summary} (+{signal.weight}) [{signal.source}]"
        for signal in candidate.external_signals[:limit]
    ]
    return '\n'.join(lines) or '- no external context attached'


def _render_symbols(candidate: Candidate, profile: str) -> str:
    limit = {'lean': 2, 'balanced': 3, 'deep': 4}[profile]
    lines = [
        f"- {symbol.kind} `{symbol.name}` lines {symbol.line_start}-{symbol.line_end} tags={','.join(symbol.tags[:4]) or 'none'}"
        for symbol in candidate.primary_symbols[:limit]
    ]
    return '\n'.join(lines) or '- no symbol-level hints captured'


def _render_semantic(candidate: Candidate, profile: str) -> str:
    limit = {'lean': 2, 'balanced': 3, 'deep': 4}[profile]
    lines = [f'- {item}' for item in candidate.semantic_summary[:limit]]
    return '\n'.join(lines) or '- no semantic summary captured'
