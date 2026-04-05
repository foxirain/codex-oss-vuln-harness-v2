from __future__ import annotations

import json
from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.findings import finding_slug

TIER_ORDER = {'S': 5, 'A': 4, 'B': 3, 'C': 2, 'D': 1}


def run_review(
    session_dir: Path,
    *,
    repo_root: Path,
    finding_files: list[Path],
    timeout_spec: str,
    model: str,
    sandbox: str,
    full_auto: bool,
    unsafe_bypass: bool,
) -> dict[str, str]:
    session_dir = session_dir.expanduser().resolve()
    review_dir = session_dir / 'review'
    review_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    for finding_file in finding_files:
        slug = finding_slug(finding_file)
        item_dir = review_dir / slug
        item_dir.mkdir(parents=True, exist_ok=True)
        result_json = item_dir / 'review.json'
        result_md = item_dir / 'review.md'
        response_file = item_dir / 'codex-response.txt'
        stdout_file = item_dir / 'codex.stdout.txt'
        stderr_file = item_dir / 'codex.stderr.txt'
        prompt = _review_prompt(session_dir, repo_root, finding_file, result_json, result_md)
        artifacts = run_codex_exec(
            repo_root=repo_root,
            prompt_text=prompt,
            response_file=response_file,
            stdout_file=stdout_file,
            stderr_file=stderr_file,
            timeout_seconds=parse_duration(timeout_spec),
            model=model,
            sandbox=sandbox,
            full_auto=full_auto,
            unsafe_bypass=unsafe_bypass,
            add_dirs=[session_dir, review_dir, item_dir],
        )
        results.append({'finding': str(finding_file), 'returncode': artifacts.returncode, 'json': str(result_json), 'markdown': str(result_md)})

    summary_path = review_dir / 'REVIEW_SUMMARY.md'
    index_path = review_dir / 'review_index.json'
    _write_review_summary(review_dir, summary_path, index_path)
    return {'review_dir': str(review_dir), 'summary': str(summary_path), 'index': str(index_path), 'count': str(len(finding_files))}


def _review_prompt(session_dir: Path, repo_root: Path, finding_file: Path, result_json: Path, result_md: Path) -> str:
    return f'''You are reviewing one vulnerability finding for realism and quality.

Repository root: {repo_root}
Session directory: {session_dir}
Finding file: {finding_file}

Read the finding file, inspect the repository code, and decide how strong the claim is.

Tier definitions:
- S: confirmed or near-confirmed; the finding is well-supported and report-ready
- A: strong; probably valid but missing one or two supporting details
- B: plausible; worth keeping, but major proof gaps remain
- C: weak; likely overstated or too incomplete for reporting
- D: reject; not a credible vulnerability finding

Output requirements:
1. Write JSON to {result_json}
2. Write a concise markdown review to {result_md}

JSON schema:
{{
  "finding_file": "{finding_file.name}",
  "title": "",
  "tier": "S|A|B|C|D",
  "confidence": "high|medium|low",
  "disposition": "confirmed|strong|plausible|weak|reject",
  "summary": "",
  "reachability": "",
  "attacker_control": "",
  "impact": "",
  "key_evidence": ["..."],
  "blocking_gaps": ["..."],
  "next_actions": ["..."]
}}

Markdown review requirements:
- title
- tier
- one-paragraph verdict
- evidence bullets
- gaps bullets
- recommended next action bullets

Be strict. Do not rubber-stamp. Downgrade findings that lack a concrete attacker-controlled entrypoint, a sensitive sink, or a realistic impact path.
After writing both files, print a short confirmation with the chosen tier.
'''


def _write_review_summary(review_dir: Path, summary_path: Path, index_path: Path) -> None:
    items: list[dict] = []
    for review_json in sorted(review_dir.glob('*/review.json')):
        try:
            data = json.loads(review_json.read_text(encoding='utf-8'))
        except Exception:
            continue
        data['_path'] = str(review_json)
        items.append(data)
    items.sort(key=lambda item: (-TIER_ORDER.get(str(item.get('tier', 'D')).upper(), 0), str(item.get('title', ''))))
    index_path.write_text(json.dumps({'reviews': items}, indent=2), encoding='utf-8')

    lines = ['# Review Summary', '']
    for tier in ['S', 'A', 'B', 'C', 'D']:
        tier_items = [item for item in items if str(item.get('tier', '')).upper() == tier]
        if not tier_items:
            continue
        lines.extend([f'## {tier} Tier', ''])
        for item in tier_items:
            lines.append(f"- {item.get('title') or item.get('finding_file')}: {item.get('summary', '')}")
        lines.append('')
    summary_path.write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')
