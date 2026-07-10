from __future__ import annotations

import json
from pathlib import Path

from oss_harness.dual import merge_dual_candidates
from oss_harness.labels import matched_labels, matching_paths, normalize_paths
from oss_harness.policy import find_default_policy, load_policy
from oss_harness.prompting import prompt_profile_for_candidate
from oss_harness.provenance import file_sha256, scan_provenance
from oss_harness.targeting import discover_candidates, load_json_config


MODES = ('blind', 'signal', 'dual')


def run_benchmark_modes(corpus_path: Path) -> dict[str, object]:
    corpus = json.loads(corpus_path.read_text(encoding='utf-8'))
    cases = list(corpus.get('cases', []))
    top_k_default = int(corpus.get('top_k', 20) or 20)
    limit_default = int(corpus.get('limit', 120) or 120)
    case_results: list[dict[str, object]] = []

    for case in cases:
        repo_root = Path(case['repo_root']).expanduser().resolve()
        policy_path = Path(case['policy']).expanduser().resolve() if case.get('policy') else find_default_policy(repo_root)
        policy = load_policy(policy_path)
        config = load_json_config(Path(case['config']).expanduser().resolve()) if case.get('config') else {}
        signals_json = Path(case['signals_json']).expanduser().resolve() if case.get('signals_json') else None
        crash_dir = Path(case['crash_dir']).expanduser().resolve() if case.get('crash_dir') else None
        sbom_path = Path(case['sbom']).expanduser().resolve() if case.get('sbom') else None
        limit = int(case.get('limit', limit_default) or limit_default)
        top_k = int(case.get('top_k', top_k_default) or top_k_default)
        known_good = list(case.get('known_good', []))
        known_bad = list(case.get('known_bad', []))

        blind_candidates, _ = discover_candidates(repo_root, policy=policy, limit=limit, config=config, external_signal_path=None, crash_dir=None, sbom_path=None, use_git_history=False)
        signal_candidates, _ = discover_candidates(repo_root, policy=policy, limit=limit, config=config, external_signal_path=signals_json, crash_dir=crash_dir, sbom_path=sbom_path)
        dual_candidates, dual_provenance = merge_dual_candidates(blind_candidates, signal_candidates, per_side_top=top_k, repo_root=repo_root)

        modes = {
            'blind': _mode_metrics(blind_candidates, repo_root=repo_root, top_k=top_k, known_good=known_good, known_bad=known_bad),
            'signal': _mode_metrics(signal_candidates, repo_root=repo_root, top_k=top_k, known_good=known_good, known_bad=known_bad),
            'dual': _mode_metrics(dual_candidates, repo_root=repo_root, top_k=top_k, known_good=known_good, known_bad=known_bad),
        }
        overlaps = {
            'blind_signal_overlap': _top_overlap(modes['blind']['top_ranked_paths'], modes['signal']['top_ranked_paths']),
            'blind_dual_overlap': _top_overlap(modes['blind']['top_ranked_paths'], modes['dual']['top_ranked_paths']),
            'signal_dual_overlap': _top_overlap(modes['signal']['top_ranked_paths'], modes['dual']['top_ranked_paths']),
        }
        dual_novelty = {
            'blind_only': [path for path, meta in dual_provenance.items() if meta.get('sources') == ['blind']],
            'signal_only': [path for path, meta in dual_provenance.items() if meta.get('sources') == ['signal']],
            'both': [path for path, meta in dual_provenance.items() if len(meta.get('sources', [])) == 2],
        }
        case_results.append({
            'name': case.get('name') or repo_root.name,
            'repo_root': str(repo_root),
            'policy': str(policy_path) if policy_path else '',
            'signals_json': str(signals_json) if signals_json else '',
            'crash_dir': str(crash_dir) if crash_dir else '',
            'sbom': str(sbom_path) if sbom_path else '',
            'top_k': top_k,
            'limit': limit,
            'modes': modes,
            'overlaps': overlaps,
            'dual_novelty': dual_novelty,
            'recommendation': _recommend_case(modes, overlaps),
            'provenance': scan_provenance(
                repo_root,
                policy=policy_path,
                config=Path(case['config']).expanduser().resolve() if case.get('config') else None,
                signals=signals_json,
                crash_dir=crash_dir,
                sbom=sbom_path,
            ),
        })

    aggregate = _aggregate_results(case_results)
    return {
        'cases': case_results,
        'aggregate': aggregate,
        'analysis': _analysis_summary(case_results, aggregate),
        'provenance': {'corpus_path': str(corpus_path), 'corpus_sha256': file_sha256(corpus_path)},
    }


def _mode_metrics(candidates, *, repo_root: Path, top_k: int, known_good: list[str], known_bad: list[str]) -> dict[str, object]:
    top_candidates = list(candidates[:top_k])
    top_paths = normalize_paths([candidate.path.relative_to(repo_root).as_posix() for candidate in top_candidates])
    prompt_profiles: dict[str, int] = {}
    exposures: dict[str, int] = {}
    for candidate in top_candidates:
        profile = prompt_profile_for_candidate(candidate)
        if profile:
            prompt_profiles[profile] = prompt_profiles.get(profile, 0) + 1
        exposures[candidate.exposure] = exposures.get(candidate.exposure, 0) + 1
    good_paths = matching_paths(top_paths, known_good)
    bad_paths = matching_paths(top_paths, known_bad)
    good_labels = matched_labels(top_paths, known_good)
    return {
        'candidate_count': len(candidates),
        'top_ranked_paths': top_paths,
        'labeled_hotspot_precision': round(len(good_paths) / max(1, len(top_paths)), 4) if known_good else None,
        'labeled_hotspot_recall': round(len(good_labels) / max(1, len(set(known_good))), 4) if known_good else None,
        'known_good_hits': good_paths,
        'known_bad_hits': bad_paths,
        'matched_known_good_labels': good_labels,
        'bad_hit_count': len(bad_paths),
        'exposure_mix': exposures,
        'prompt_profile_mix': prompt_profiles,
    }


def _top_overlap(left: list[str], right: list[str]) -> dict[str, object]:
    left_set = set(left)
    right_set = set(right)
    shared = sorted(left_set & right_set)
    return {
        'shared_count': len(shared),
        'shared_ratio': round(len(shared) / max(1, min(len(left), len(right))), 4),
        'shared_paths': shared,
    }


def _recommend_case(modes: dict[str, dict[str, object]], overlaps: dict[str, dict[str, object]]) -> str:
    if modes['signal']['labeled_hotspot_precision'] is not None and modes['blind']['labeled_hotspot_precision'] is not None:
        blind_precision = float(modes['blind']['labeled_hotspot_precision'])
        signal_precision = float(modes['signal']['labeled_hotspot_precision'])
        dual_precision = float(modes['dual']['labeled_hotspot_precision'])
        if dual_precision >= max(blind_precision, signal_precision):
            return 'dual is best on labeled hotspot precision; use dual as default and keep single-mode scans for diagnosis'
        if signal_precision > blind_precision and modes['signal']['bad_hit_count'] <= modes['blind']['bad_hit_count']:
            return 'signal is stronger on labeled hotspot precision; improve signal coverage and use dual as backstop'
        if blind_precision > signal_precision:
            return 'blind ranks the labeled hotspots more cleanly; reduce signal bias or refine external signal weighting'
    if overlaps['blind_signal_overlap']['shared_ratio'] < 0.4:
        return 'blind and signal are exploring different surfaces; dual is likely worth the extra scan budget'
    return 'blind and signal overlap heavily; improve labeled-hotspot ranking precision before adding more scan breadth'


def _aggregate_results(case_results: list[dict[str, object]]) -> dict[str, object]:
    aggregate = {
        'cases': len(case_results),
        'modes': {
            mode: {
                'avg_candidate_count': 0.0,
                'avg_labeled_hotspot_precision': 0.0,
                'avg_labeled_hotspot_recall': 0.0,
                'avg_bad_hit_count': 0.0,
                'labeled_cases': 0,
            }
            for mode in MODES
        },
        'avg_blind_signal_overlap': 0.0,
        'avg_blind_dual_overlap': 0.0,
        'avg_signal_dual_overlap': 0.0,
    }
    if not case_results:
        return aggregate
    for case in case_results:
        for mode in MODES:
            data = case['modes'][mode]
            aggregate['modes'][mode]['avg_candidate_count'] += float(data['candidate_count'])
            aggregate['modes'][mode]['avg_bad_hit_count'] += float(data['bad_hit_count'])
            if data['labeled_hotspot_precision'] is not None:
                aggregate['modes'][mode]['avg_labeled_hotspot_precision'] += float(data['labeled_hotspot_precision'])
                aggregate['modes'][mode]['avg_labeled_hotspot_recall'] += float(data['labeled_hotspot_recall'])
                aggregate['modes'][mode]['labeled_cases'] += 1
        aggregate['avg_blind_signal_overlap'] += float(case['overlaps']['blind_signal_overlap']['shared_ratio'])
        aggregate['avg_blind_dual_overlap'] += float(case['overlaps']['blind_dual_overlap']['shared_ratio'])
        aggregate['avg_signal_dual_overlap'] += float(case['overlaps']['signal_dual_overlap']['shared_ratio'])
    for mode in MODES:
        aggregate['modes'][mode]['avg_candidate_count'] = round(aggregate['modes'][mode]['avg_candidate_count'] / len(case_results), 2)
        aggregate['modes'][mode]['avg_bad_hit_count'] = round(aggregate['modes'][mode]['avg_bad_hit_count'] / len(case_results), 2)
        labeled = aggregate['modes'][mode]['labeled_cases']
        if labeled:
            aggregate['modes'][mode]['avg_labeled_hotspot_precision'] = round(aggregate['modes'][mode]['avg_labeled_hotspot_precision'] / labeled, 4)
            aggregate['modes'][mode]['avg_labeled_hotspot_recall'] = round(aggregate['modes'][mode]['avg_labeled_hotspot_recall'] / labeled, 4)
        else:
            aggregate['modes'][mode]['avg_labeled_hotspot_precision'] = None
            aggregate['modes'][mode]['avg_labeled_hotspot_recall'] = None
    aggregate['avg_blind_signal_overlap'] = round(aggregate['avg_blind_signal_overlap'] / len(case_results), 4)
    aggregate['avg_blind_dual_overlap'] = round(aggregate['avg_blind_dual_overlap'] / len(case_results), 4)
    aggregate['avg_signal_dual_overlap'] = round(aggregate['avg_signal_dual_overlap'] / len(case_results), 4)
    return aggregate


def _analysis_summary(case_results: list[dict[str, object]], aggregate: dict[str, object]) -> dict[str, object]:
    summary = {
        'best_mode_by_labeled_hotspot_precision': None,
        'mode_notes': [],
    }
    precision_scores = {
        mode: aggregate['modes'][mode]['avg_labeled_hotspot_precision']
        for mode in MODES
        if aggregate['modes'][mode]['avg_labeled_hotspot_precision'] is not None
    }
    if precision_scores:
        summary['best_mode_by_labeled_hotspot_precision'] = max(precision_scores, key=precision_scores.get)
    if aggregate['avg_blind_signal_overlap'] < 0.5:
        summary['mode_notes'].append('Blind and signal overlap is low on average; dual mode is likely surfacing complementary candidate sets.')
    if precision_scores:
        best = summary['best_mode_by_labeled_hotspot_precision']
        summary['mode_notes'].append(f'Best labeled-hotspot precision currently belongs to: {best}.')
    else:
        summary['mode_notes'].append('No labeled hotspot paths were supplied; overlap and candidate shape are descriptive only, not vulnerability-detection precision.')
    for case in case_results:
        summary['mode_notes'].append(f"{case['name']}: {case['recommendation']}")
    return summary
