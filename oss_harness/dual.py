from __future__ import annotations

import json
from pathlib import Path

from oss_harness.bundle import write_session_bundle
from oss_harness.models import Candidate, ExternalSignal, LanguageStat, Signal, SymbolHint

HEADER_SUFFIXES = {'.h', '.hh', '.hpp', '.hxx'}


def write_dual_session_bundle(
    *,
    repo_root: Path,
    out_dir: Path,
    blind_candidates: list[Candidate],
    signal_candidates: list[Candidate],
    per_side_top: int,
    policy: dict,
    language_stats: list[LanguageStat],
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    blind_dir = out_dir / 'blind'
    signal_dir = out_dir / 'signal'
    merged_dir = out_dir / 'merged'

    write_session_bundle(
        repo_root=repo_root,
        out_dir=blind_dir,
        candidates=blind_candidates,
        top_n=per_side_top,
        policy=policy,
        language_stats=language_stats,
    )
    write_session_bundle(
        repo_root=repo_root,
        out_dir=signal_dir,
        candidates=signal_candidates,
        top_n=per_side_top,
        policy=policy,
        language_stats=language_stats,
    )

    merged_candidates, provenance = merge_dual_candidates(
        blind_candidates,
        signal_candidates,
        per_side_top=per_side_top,
        repo_root=repo_root,
    )
    write_session_bundle(
        repo_root=repo_root,
        out_dir=merged_dir,
        candidates=merged_candidates,
        top_n=min(per_side_top * 2, len(merged_candidates)),
        policy=policy,
        language_stats=language_stats,
    )

    _augment_session(blind_dir, session_mode='blind', per_side_top=per_side_top)
    _augment_session(signal_dir, session_mode='signal', per_side_top=per_side_top)
    _augment_session(
        merged_dir,
        session_mode='merged',
        per_side_top=per_side_top,
        provenance=provenance,
        blind_session=blind_dir,
        signal_session=signal_dir,
    )

    return {
        'session_root': out_dir,
        'blind_session': blind_dir,
        'signal_session': signal_dir,
        'merged_session': merged_dir,
    }


def merge_dual_candidates(
    blind_candidates: list[Candidate],
    signal_candidates: list[Candidate],
    *,
    per_side_top: int,
    repo_root: Path,
) -> tuple[list[Candidate], dict[str, dict[str, object]]]:
    budget = max(1, per_side_top * 2)
    merged: list[Candidate] = []
    merged_by_path: dict[str, Candidate] = {}
    provenance: dict[str, dict[str, object]] = {}
    counters = {'header_only': 0, 'subsystem': {}, 'path_class': {}}
    limits = {
        'header_only': max(1, budget // 5),
        'subsystem': max(2, budget // 3),
        'path_class': max(2, budget // 2),
    }

    blind_state = _SelectionState('blind', blind_candidates, per_side_top)
    signal_state = _SelectionState('signal', signal_candidates, per_side_top)

    while len(merged) < budget and (blind_state.needs_more() or signal_state.needs_more()):
        progress = False
        for state in (blind_state, signal_state):
            if len(merged) >= budget or not state.needs_more():
                continue
            if _consume_next_candidate(state, repo_root, merged, merged_by_path, provenance, counters, limits, relaxed=False):
                progress = True
        if not progress:
            break

    while len(merged) < budget:
        progress = False
        for state in (blind_state, signal_state):
            if len(merged) >= budget:
                break
            if _consume_next_candidate(state, repo_root, merged, merged_by_path, provenance, counters, limits, relaxed=True):
                progress = True
        if not progress:
            break

    for merged_rank, candidate in enumerate(merged, start=1):
        rel_path = str(candidate.path.relative_to(repo_root))
        provenance.setdefault(rel_path, {'sources': [], 'blind_rank': None, 'signal_rank': None})['merged_rank'] = merged_rank
    return merged, provenance


class _SelectionState:
    def __init__(self, source_name: str, candidates: list[Candidate], unique_budget: int) -> None:
        self.source_name = source_name
        self.candidates = candidates
        self.unique_budget = unique_budget
        self.cursor = 0
        self.unique_added = 0
        self.deferred: list[tuple[int, Candidate]] = []

    def needs_more(self) -> bool:
        return self.unique_added < self.unique_budget and self.cursor < len(self.candidates)


def _consume_next_candidate(
    state: _SelectionState,
    repo_root: Path,
    merged: list[Candidate],
    merged_by_path: dict[str, Candidate],
    provenance: dict[str, dict[str, object]],
    counters: dict[str, object],
    limits: dict[str, int],
    *,
    relaxed: bool,
) -> bool:
    if relaxed and state.deferred:
        rank, candidate = state.deferred.pop(0)
        return _accept_candidate(candidate, rank=rank, state=state, repo_root=repo_root, merged=merged, merged_by_path=merged_by_path, provenance=provenance, counters=counters, limits=limits, relaxed=True)

    while state.cursor < len(state.candidates):
        rank = state.cursor + 1
        candidate = state.candidates[state.cursor]
        state.cursor += 1
        rel_path = str(candidate.path.relative_to(repo_root))
        entry = provenance.setdefault(rel_path, {'sources': [], 'blind_rank': None, 'signal_rank': None})
        if state.source_name not in entry['sources']:
            entry['sources'].append(state.source_name)
        entry[f'{state.source_name}_rank'] = rank
        if rel_path in merged_by_path:
            _merge_candidate(merged_by_path[rel_path], candidate, source_name=state.source_name, rank=rank)
            continue
        if not relaxed and _violates_diversity(candidate, counters, limits):
            state.deferred.append((rank, candidate))
            continue
        return _accept_candidate(candidate, rank=rank, state=state, repo_root=repo_root, merged=merged, merged_by_path=merged_by_path, provenance=provenance, counters=counters, limits=limits, relaxed=relaxed)
    return False


def _accept_candidate(
    candidate: Candidate,
    *,
    rank: int,
    state: _SelectionState,
    repo_root: Path,
    merged: list[Candidate],
    merged_by_path: dict[str, Candidate],
    provenance: dict[str, dict[str, object]],
    counters: dict[str, object],
    limits: dict[str, int],
    relaxed: bool,
) -> bool:
    rel_path = str(candidate.path.relative_to(repo_root))
    clone = _clone_candidate(candidate)
    clone.reasons = list(clone.reasons) + [f'dual_mode:{state.source_name}_top_rank={rank}']
    if relaxed:
        clone.reasons.append('dual_mode:relaxed_diversity_fill')
    merged_by_path[rel_path] = clone
    merged.append(clone)
    state.unique_added += 1
    _bump_diversity_counters(candidate, counters)
    provenance.setdefault(rel_path, {'sources': [], 'blind_rank': None, 'signal_rank': None})
    return True


def _violates_diversity(candidate: Candidate, counters: dict[str, object], limits: dict[str, int]) -> bool:
    subsystem = candidate.subsystem or candidate.path.parts[0]
    path_class = candidate.exposure or 'unclassified'
    is_header = candidate.path.suffix.lower() in HEADER_SUFFIXES
    if is_header and int(counters['header_only']) >= limits['header_only']:
        return True
    if int(counters['subsystem'].get(subsystem, 0)) >= limits['subsystem']:
        return True
    if int(counters['path_class'].get(path_class, 0)) >= limits['path_class']:
        return True
    return False


def _bump_diversity_counters(candidate: Candidate, counters: dict[str, object]) -> None:
    subsystem = candidate.subsystem or candidate.path.parts[0]
    path_class = candidate.exposure or 'unclassified'
    counters['subsystem'][subsystem] = int(counters['subsystem'].get(subsystem, 0)) + 1
    counters['path_class'][path_class] = int(counters['path_class'].get(path_class, 0)) + 1
    if candidate.path.suffix.lower() in HEADER_SUFFIXES:
        counters['header_only'] = int(counters['header_only']) + 1


def _clone_candidate(candidate: Candidate) -> Candidate:
    return Candidate(
        path=candidate.path,
        language=candidate.language,
        subsystem=candidate.subsystem,
        exposure=candidate.exposure,
        score=candidate.score,
        attack_surfaces=list(candidate.attack_surfaces),
        sink_kinds=list(candidate.sink_kinds),
        framework_hints=list(candidate.framework_hints),
        entrypoint_markers=list(candidate.entrypoint_markers),
        primary_symbols=[
            SymbolHint(
                name=symbol.name,
                kind=symbol.kind,
                line_start=symbol.line_start,
                line_end=symbol.line_end,
                score=symbol.score,
                tags=list(symbol.tags),
            )
            for symbol in candidate.primary_symbols
        ],
        semantic_summary=list(candidate.semantic_summary),
        reasons=list(candidate.reasons),
        signals=[
            Signal(
                name=signal.name,
                weight=signal.weight,
                line_no=signal.line_no,
                line=signal.line,
                rationale=signal.rationale,
                language=signal.language,
            )
            for signal in candidate.signals
        ],
        path_signals=list(candidate.path_signals),
        external_signals=[
            ExternalSignal(
                source=signal.source,
                weight=signal.weight,
                summary=signal.summary,
                url=signal.url,
                metadata=dict(signal.metadata),
            )
            for signal in candidate.external_signals
        ],
    )


def _merge_candidate(existing: Candidate, incoming: Candidate, *, source_name: str, rank: int) -> None:
    existing.score = max(existing.score, incoming.score)
    existing.attack_surfaces = _merge_unique(existing.attack_surfaces, incoming.attack_surfaces)
    existing.sink_kinds = _merge_unique(existing.sink_kinds, incoming.sink_kinds)
    existing.framework_hints = _merge_unique(existing.framework_hints, incoming.framework_hints)
    existing.entrypoint_markers = _merge_unique(existing.entrypoint_markers, incoming.entrypoint_markers)
    existing.semantic_summary = _merge_unique(existing.semantic_summary, incoming.semantic_summary)[:6]
    existing.path_signals = _merge_unique(existing.path_signals, incoming.path_signals)
    existing.reasons = _merge_unique(existing.reasons, incoming.reasons)
    existing.reasons.append(f'dual_mode:{source_name}_top_rank={rank}')
    existing.signals = _merge_signals(existing.signals, incoming.signals)
    existing.external_signals = _merge_external(existing.external_signals, incoming.external_signals)
    if len(incoming.primary_symbols) > len(existing.primary_symbols):
        existing.primary_symbols = [
            SymbolHint(
                name=symbol.name,
                kind=symbol.kind,
                line_start=symbol.line_start,
                line_end=symbol.line_end,
                score=symbol.score,
                tags=list(symbol.tags),
            )
            for symbol in incoming.primary_symbols
        ]


def _merge_unique(left: list[str], right: list[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for item in [*left, *right]:
        if item not in seen:
            seen.add(item)
            merged.append(item)
    return merged


def _merge_signals(left: list[Signal], right: list[Signal]) -> list[Signal]:
    seen: set[tuple[str, int, str]] = set()
    merged: list[Signal] = []
    for item in [*left, *right]:
        key = (item.name, item.line_no, item.language)
        if key not in seen:
            seen.add(key)
            merged.append(item)
    merged.sort(key=lambda item: (-item.weight, item.line_no))
    return merged


def _merge_external(left: list[ExternalSignal], right: list[ExternalSignal]) -> list[ExternalSignal]:
    seen: set[tuple[str, str, int]] = set()
    merged: list[ExternalSignal] = []
    for item in [*left, *right]:
        key = (item.source, item.summary, item.weight)
        if key not in seen:
            seen.add(key)
            merged.append(item)
    return merged


def _augment_session(
    session_dir: Path,
    *,
    session_mode: str,
    per_side_top: int,
    provenance: dict[str, dict[str, object]] | None = None,
    blind_session: Path | None = None,
    signal_session: Path | None = None,
) -> None:
    targets_path = session_dir / 'targets.json'
    manifest = json.loads(targets_path.read_text(encoding='utf-8'))
    manifest['session_mode'] = session_mode
    manifest['dual_top_per_side'] = per_side_top
    if blind_session is not None:
        manifest['blind_session'] = str(blind_session)
    if signal_session is not None:
        manifest['signal_session'] = str(signal_session)
    if provenance:
        for candidate in manifest.get('candidates', []):
            meta = provenance.get(candidate.get('path', ''), {})
            if meta:
                candidate['dual_sources'] = meta.get('sources', [])
                candidate['blind_rank'] = meta.get('blind_rank')
                candidate['signal_rank'] = meta.get('signal_rank')
                candidate['merged_rank'] = meta.get('merged_rank')
    targets_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')

    session_md = session_dir / 'SESSION.md'
    text = session_md.read_text(encoding='utf-8')
    prefix_lines = [
        f'- Session mode: `{session_mode}`',
        f'- Dual top-per-side: `{per_side_top}`',
    ]
    if blind_session is not None:
        prefix_lines.append(f'- Blind session: `{blind_session}`')
    if signal_session is not None:
        prefix_lines.append(f'- Signal session: `{signal_session}`')
    header = '# OSS Codex Harness Session\n\n'
    text = text.replace(header, header + '\n'.join(prefix_lines) + '\n\n', 1)
    session_md.write_text(text, encoding='utf-8')
