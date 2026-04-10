from __future__ import annotations

import json
from pathlib import Path

from oss_harness.findings import list_finding_files
from oss_harness.reviewing import TIER_ORDER


def run_eval_corpus(corpus_path: Path) -> dict[str, object]:
    corpus = json.loads(corpus_path.read_text(encoding='utf-8'))
    cases = list(corpus.get('cases', []))
    results: list[dict[str, object]] = []
    aggregate = {
        'cases': len(cases),
        'top_k_precision': 0.0,
        'top_k_recall': 0.0,
        'finding_promotion_precision': 0.0,
        'false_promotion_rate': 0.0,
        'review_s_rate': 0.0,
        'review_a_rate': 0.0,
        'review_b_rate': 0.0,
    }
    if not cases:
        return {'cases': [], 'aggregate': aggregate}

    for case in cases:
        session_dir = Path(case['session_dir']).expanduser().resolve()
        manifest = json.loads((session_dir / 'targets.json').read_text(encoding='utf-8'))
        top_k = int(case.get('top_k', 20))
        ranked_paths = [item.get('path', '') for item in manifest.get('candidates', [])[:top_k]]
        known_good = set(case.get('known_good', []))
        known_bad = set(case.get('known_bad', []))
        hits = len([path for path in ranked_paths if path in known_good])
        false_hits = len([path for path in ranked_paths if path in known_bad])
        top_precision = hits / max(1, len(ranked_paths))
        top_recall = hits / max(1, len(known_good)) if known_good else 0.0

        findings = list_finding_files(session_dir)
        review_index_path = session_dir / 'review' / 'review_index.json'
        reviews = []
        if review_index_path.exists():
            reviews = json.loads(review_index_path.read_text(encoding='utf-8')).get('reviews', [])
        promoted = len(findings)
        strong_reviews = len([item for item in reviews if TIER_ORDER.get(str(item.get('tier', 'D')).upper(), 0) >= TIER_ORDER['B']])
        weak_reviews = len([item for item in reviews if str(item.get('tier', 'D')).upper() in {'C', 'D'}])
        finding_promotion_precision = strong_reviews / max(1, promoted)
        false_promotion_rate = weak_reviews / max(1, promoted)
        review_count = max(1, len(reviews))
        review_s_rate = len([item for item in reviews if str(item.get('tier', '')).upper() == 'S']) / review_count
        review_a_rate = len([item for item in reviews if str(item.get('tier', '')).upper() == 'A']) / review_count
        review_b_rate = len([item for item in reviews if str(item.get('tier', '')).upper() == 'B']) / review_count

        result = {
            'name': case.get('name') or session_dir.name,
            'session_dir': str(session_dir),
            'top_k': top_k,
            'top_k_precision': round(top_precision, 4),
            'top_k_recall': round(top_recall, 4),
            'promoted_findings': promoted,
            'reviewed_findings': len(reviews),
            'finding_promotion_precision': round(finding_promotion_precision, 4),
            'false_promotion_rate': round(false_promotion_rate, 4),
            'review_s_rate': round(review_s_rate, 4),
            'review_a_rate': round(review_a_rate, 4),
            'review_b_rate': round(review_b_rate, 4),
            'top_ranked_paths': ranked_paths,
            'known_good_hits': sorted(path for path in ranked_paths if path in known_good),
            'known_bad_hits': sorted(path for path in ranked_paths if path in known_bad),
        }
        results.append(result)
        for key in ('top_k_precision', 'top_k_recall', 'finding_promotion_precision', 'false_promotion_rate', 'review_s_rate', 'review_a_rate', 'review_b_rate'):
            aggregate[key] += float(result[key])

    for key in ('top_k_precision', 'top_k_recall', 'finding_promotion_precision', 'false_promotion_rate', 'review_s_rate', 'review_a_rate', 'review_b_rate'):
        aggregate[key] = round(aggregate[key] / len(results), 4)
    return {'cases': results, 'aggregate': aggregate}
