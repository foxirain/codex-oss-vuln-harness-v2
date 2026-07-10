from __future__ import annotations

import json
from pathlib import Path

from oss_harness.findings import list_finding_files
from oss_harness.labels import matched_labels, matching_paths, normalize_paths
from oss_harness.provenance import file_sha256
from oss_harness.review_schema import validate_review
from oss_harness.reviewing import TIER_ORDER


def run_eval_corpus(corpus_path: Path) -> dict[str, object]:
    corpus = json.loads(corpus_path.read_text(encoding='utf-8'))
    cases = list(corpus.get('cases', []))
    results: list[dict[str, object]] = []
    aggregate = {
        'cases': len(cases),
        'labeled_hotspot_precision': 0.0,
        'labeled_hotspot_recall': 0.0,
        'review_confirmation_rate': 0.0,
        'review_rejection_rate': 0.0,
        'review_s_rate': 0.0,
        'review_a_rate': 0.0,
        'review_b_rate': 0.0,
    }
    if not cases:
        return {'cases': [], 'aggregate': aggregate, 'provenance': {'corpus_path': str(corpus_path), 'corpus_sha256': file_sha256(corpus_path)}}

    for case in cases:
        session_dir = Path(case['session_dir']).expanduser().resolve()
        manifest = json.loads((session_dir / 'targets.json').read_text(encoding='utf-8'))
        top_k = int(case.get('top_k', 20))
        ranked_paths = normalize_paths([item.get('path', '') for item in manifest.get('candidates', [])[:top_k]])
        known_good = list(case.get('known_good', []))
        known_bad = list(case.get('known_bad', []))
        good_paths = matching_paths(ranked_paths, known_good)
        bad_paths = matching_paths(ranked_paths, known_bad)
        good_labels = matched_labels(ranked_paths, known_good)
        top_precision = len(good_paths) / max(1, len(ranked_paths))
        top_recall = len(good_labels) / max(1, len(set(known_good))) if known_good else 0.0

        findings = list_finding_files(session_dir)
        review_index_path = session_dir / 'review' / 'review_index.json'
        raw_reviews = []
        if review_index_path.exists():
            raw_reviews = json.loads(review_index_path.read_text(encoding='utf-8')).get('reviews', [])
        finding_names = {path.name for path in findings}
        reviews_by_finding: dict[str, dict] = {}
        for item in raw_reviews:
            try:
                review = validate_review(item)
            except (TypeError, ValueError):
                continue
            if review['finding_file'] in finding_names:
                reviews_by_finding[review['finding_file']] = review
        reviews = list(reviews_by_finding.values())
        promoted = len(findings)
        strong_reviews = len([item for item in reviews if TIER_ORDER.get(str(item.get('tier', 'D')).upper(), 0) >= TIER_ORDER['B']])
        weak_reviews = len([item for item in reviews if str(item.get('tier', 'D')).upper() in {'C', 'D'}])
        review_confirmation_rate = strong_reviews / max(1, len(reviews))
        review_rejection_rate = weak_reviews / max(1, len(reviews))
        review_count = max(1, len(reviews))
        review_s_rate = len([item for item in reviews if str(item.get('tier', '')).upper() == 'S']) / review_count
        review_a_rate = len([item for item in reviews if str(item.get('tier', '')).upper() == 'A']) / review_count
        review_b_rate = len([item for item in reviews if str(item.get('tier', '')).upper() == 'B']) / review_count

        result = {
            'name': case.get('name') or session_dir.name,
            'session_dir': str(session_dir),
            'top_k': top_k,
            'labeled_hotspot_precision': round(top_precision, 4),
            'labeled_hotspot_recall': round(top_recall, 4),
            'promoted_findings': promoted,
            'reviewed_findings': len(reviews),
            'review_coverage': round(len(reviews) / max(1, promoted), 4),
            'review_confirmation_rate': round(review_confirmation_rate, 4),
            'review_rejection_rate': round(review_rejection_rate, 4),
            'review_s_rate': round(review_s_rate, 4),
            'review_a_rate': round(review_a_rate, 4),
            'review_b_rate': round(review_b_rate, 4),
            'top_ranked_paths': ranked_paths,
            'known_good_hits': good_paths,
            'known_bad_hits': bad_paths,
            'matched_known_good_labels': good_labels,
            'session_provenance': manifest.get('provenance', {}),
        }
        results.append(result)
        for key in ('labeled_hotspot_precision', 'labeled_hotspot_recall', 'review_confirmation_rate', 'review_rejection_rate', 'review_s_rate', 'review_a_rate', 'review_b_rate'):
            aggregate[key] += float(result[key])

    for key in ('labeled_hotspot_precision', 'labeled_hotspot_recall', 'review_confirmation_rate', 'review_rejection_rate', 'review_s_rate', 'review_a_rate', 'review_b_rate'):
        aggregate[key] = round(aggregate[key] / len(results), 4)
    return {'cases': results, 'aggregate': aggregate, 'provenance': {'corpus_path': str(corpus_path), 'corpus_sha256': file_sha256(corpus_path)}}
