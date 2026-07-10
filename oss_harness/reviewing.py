from __future__ import annotations

import json
from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.findings import finding_slug
from oss_harness.outputs import parse_json_object_response, require_successful_response, write_json
from oss_harness.paths import atomic_write_text
from oss_harness.review_schema import validate_review

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
    if review_dir.is_symlink():
        raise RuntimeError(f'review output directory must not be a symlink: {review_dir}')
    review_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    for finding_file in finding_files:
        slug = finding_slug(finding_file)
        item_dir = review_dir / slug
        if item_dir.is_symlink():
            raise RuntimeError(f'review item directory must not be a symlink: {item_dir}')
        item_dir.mkdir(parents=True, exist_ok=True)
        result_json = item_dir / 'review.json'
        result_md = item_dir / 'review.md'
        response_file = item_dir / 'codex-response.txt'
        stdout_file = item_dir / 'codex.stdout.txt'
        stderr_file = item_dir / 'codex.stderr.txt'
        result_json.unlink(missing_ok=True)
        result_md.unlink(missing_ok=True)
        prompt = _review_prompt(session_dir, repo_root, finding_file)
        try:
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
            )
            response = require_successful_response(artifacts.returncode, response_file)
            review = validate_review(parse_json_object_response(response), expected_finding=finding_file.name)
            write_json(result_json, review)
            atomic_write_text(result_md, _render_review_markdown(review))
            results.append({'finding': str(finding_file), 'ok': True, 'json': str(result_json), 'markdown': str(result_md)})
        except (OSError, RuntimeError, ValueError) as exc:
            results.append({'finding': str(finding_file), 'ok': False, 'error': str(exc)})

    summary_path = review_dir / 'REVIEW_SUMMARY.md'
    index_path = review_dir / 'review_index.json'
    successful_paths = [Path(item['json']) for item in results if item['ok']]
    _write_review_summary(successful_paths, summary_path, index_path)
    failed = [item for item in results if not item['ok']]
    return {
        'review_dir': str(review_dir),
        'summary': str(summary_path),
        'index': str(index_path),
        'requested': str(len(finding_files)),
        'succeeded': str(len(successful_paths)),
        'failed': str(len(failed)),
        'success': str(not failed).lower(),
    }


def _review_prompt(session_dir: Path, repo_root: Path, finding_file: Path) -> str:
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

Output requirement:
- Return exactly one JSON object as the final response. Do not write or modify files.

JSON schema:
{{
  "finding_file": "{finding_file.name}",
  "title": "",
  "tier": "S|A|B|C|D",
  "confidence": "high|medium|low",
  "disposition": "confirmed|strong|plausible|weak|reject",
  "summary": "",
  "entrypoint": "",
  "reachability": "",
  "attacker_control": "",
  "sink": "",
  "impact": "",
  "key_evidence": ["..."],
  "blocking_gaps": ["..."],
  "next_actions": ["..."]
}}

Be strict. Do not rubber-stamp. Downgrade findings that lack a concrete attacker-controlled entrypoint, a sensitive sink, or a realistic impact path.
For S or A, every proof field and at least one key_evidence item must be concrete. Placeholder values are invalid.
'''


def _write_review_summary(review_paths: list[Path], summary_path: Path, index_path: Path) -> None:
    items: list[dict] = []
    for review_json in sorted(review_paths):
        try:
            data = validate_review(json.loads(review_json.read_text(encoding='utf-8')))
        except Exception:
            continue
        data['_path'] = str(review_json)
        items.append(data)
    items.sort(key=lambda item: (-TIER_ORDER.get(str(item.get('tier', 'D')).upper(), 0), str(item.get('title', ''))))
    write_json(index_path, {'reviews': items})

    lines = ['# Review Summary', '']
    for tier in ['S', 'A', 'B', 'C', 'D']:
        tier_items = [item for item in items if str(item.get('tier', '')).upper() == tier]
        if not tier_items:
            continue
        lines.extend([f'## {tier} Tier', ''])
        for item in tier_items:
            lines.append(f"- {item.get('title') or item.get('finding_file')}: {item.get('summary', '')}")
        lines.append('')
    atomic_write_text(summary_path, '\n'.join(lines).rstrip() + '\n')


def _render_review_markdown(item: dict) -> str:
    lines = [f"# {item['title']}", '', f"Tier: {item['tier']}", '', item['summary'], '', '## Evidence', '']
    lines.extend(f'- {value}' for value in item['key_evidence'])
    lines.extend(['', '## Gaps', ''])
    lines.extend(f'- {value}' for value in item['blocking_gaps'])
    lines.extend(['', '## Next actions', ''])
    lines.extend(f'- {value}' for value in item['next_actions'])
    return '\n'.join(lines).rstrip() + '\n'
