from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.outputs import parse_json_object_response, require_successful_response, write_json
from oss_harness.paths import atomic_write_text, validate_repo_target


POLICY_HEADINGS = (
    'Project Summary', 'In Scope', 'Out of Scope', 'Focus Areas',
    'Forbidden Findings', 'Entry Points', 'Include Paths', 'Exclude Paths',
    'Languages', 'Framework Hints', 'Hot Paths', 'Preferred Sinks',
    'Preferred Bug Classes', 'Ignore Patterns', 'Notes',
)
ALLOWED_SIGNAL_SOURCES = {'syzbot', 'oss-fuzz', 'clusterfuzz', 'sanitizer', 'advisory', 'cve', 'issue', 'pr', 'git', 'hardening', 'manual'}


def run_bootstrap(
    repo_root: Path,
    *,
    policy_path: Path,
    signals_path: Path,
    out_dir: Path,
    timeout_spec: str,
    model: str,
    sandbox: str,
    full_auto: bool,
    unsafe_bypass: bool,
) -> dict[str, str]:
    repo_root = repo_root.expanduser().resolve()
    policy_path = policy_path.expanduser().resolve()
    signals_path = signals_path.expanduser().resolve()
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / 'BOOTSTRAP_SUMMARY.md'
    response_file = out_dir / 'bootstrap-response.txt'
    stdout_file = out_dir / 'bootstrap.stdout.txt'
    stderr_file = out_dir / 'bootstrap.stderr.txt'

    prompt = _bootstrap_prompt(repo_root, policy_path, signals_path, summary_path)
    success = False
    error = ''
    returncode = -1
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
        returncode = artifacts.returncode
        response = require_successful_response(returncode, response_file)
        payload = parse_json_object_response(response)
        policy_markdown, signals, summary_markdown = _validate_bootstrap_payload(payload, repo_root)
        atomic_write_text(policy_path, policy_markdown.rstrip() + '\n')
        write_json(signals_path, signals)
        atomic_write_text(summary_path, summary_markdown.rstrip() + '\n')
        success = True
    except (OSError, RuntimeError, ValueError) as exc:
        error = str(exc)
    return {
        'policy': str(policy_path),
        'signals': str(signals_path),
        'summary': str(summary_path),
        'response_file': str(response_file),
        'stdout_file': str(stdout_file),
        'stderr_file': str(stderr_file),
        'returncode': str(returncode),
        'success': str(success).lower(),
        'error': error,
    }


def _bootstrap_prompt(repo_root: Path, policy_path: Path, signals_path: Path, summary_path: Path) -> str:
    today = datetime.now(UTC).strftime('%Y-%m-%d')
    return f'''You are preparing a Codex OSS vulnerability-hunting harness bootstrap for a repository.

Repository root: {repo_root}
Today (UTC): {today}

You must use both:
1. web search for latest project policy / advisory / security-process data
2. local repository analysis for actual attack surface, entrypoints, hot paths, and likely sinks

Return exactly one JSON object as your final response. Do not write or modify files.
The harness will validate and write these outputs:
- policy file: {policy_path}
- external signals json: {signals_path}
- short bootstrap summary: {summary_path}

Requirements for the policy file:
- Write a final `.codex-harness.md` ready for direct harness use.
- Use the exact section structure below and fill every section with concrete content.
- Keep section semantics strict:
  - `In Scope`: vulnerability classes and security boundaries only, no paths
  - `Out of Scope`: excluded bug classes / operational exclusions only, no paths
  - `Entry Points`: real attacker-controlled inputs only
  - `Include Paths` / `Exclude Paths`: repository paths only
  - `Hot Paths`: high-priority paths or files only
  - `Preferred Sinks`: sink categories only
  - `Preferred Bug Classes`: bug classes only
- Keep the scope narrow enough for reachable, CVE-quality hunting.
- Use absolute dates when summarizing policy, releases, or advisories.

Exact policy file structure:
# Project Policy

## Project Summary
## In Scope
## Out of Scope
## Focus Areas
## Forbidden Findings
## Entry Points
## Include Paths
## Exclude Paths
## Languages
## Framework Hints
## Hot Paths
## Preferred Sinks
## Preferred Bug Classes
## Ignore Patterns
## Notes

Final response schema:
{{
  "policy_markdown": "# Project Policy\\n...",
  "signals": {{"signals": [/* entries below */]}},
  "summary_markdown": "# Bootstrap Summary\\n..."
}}

Requirements for the signals object:
- Use exactly this shape:
  {{
    "signals": [
      {{
        "path": "...",
        "source": "...",
        "weight": 9,
        "summary": "...",
        "metadata": {{...}}
      }}
    ]
  }}
- Use only repository-internal paths.
- Exclude tests, examples, docs, generated code, and vendor dependencies.
- Identify the project type first, then prioritize the strongest matching artifact sources.
- Include high-signal evidence only:
  - recent security / fix / hardening / follow-up / revert commits
  - advisory / CVE / security bulletin references
  - crash / sanitizer / fuzz artifacts
  - panic / overflow / use-after-free / OOB / traversal / auth bypass issues or PRs
  - files adjacent to recent fixes or on the same trust boundary
- Allowed source labels: syzbot, oss-fuzz, clusterfuzz, sanitizer, advisory, cve, issue, pr, git, hardening, manual
- Each signal should reflect confidence through weight and metadata.

Requirements for summary_markdown:
- Keep it short.
- Include:
  - project_type
  - best_external_sources
  - policy_basis
  - ambiguous_areas
  - output_files

Do not wrap the JSON in commentary and do not add a confirmation.
'''


def _validate_bootstrap_payload(payload: dict, repo_root: Path) -> tuple[str, dict, str]:
    if set(payload) != {'policy_markdown', 'signals', 'summary_markdown'}:
        raise ValueError('bootstrap response must contain exactly policy_markdown, signals, and summary_markdown')
    policy_markdown = payload['policy_markdown']
    summary_markdown = payload['summary_markdown']
    signals = payload['signals']
    if not isinstance(policy_markdown, str) or not policy_markdown.strip():
        raise ValueError('policy_markdown must be a non-empty string')
    missing = [heading for heading in POLICY_HEADINGS if f'## {heading}' not in policy_markdown]
    if missing:
        raise ValueError(f'policy is missing headings: {", ".join(missing)}')
    if not isinstance(summary_markdown, str) or not summary_markdown.strip():
        raise ValueError('summary_markdown must be a non-empty string')
    if not isinstance(signals, dict) or set(signals) != {'signals'} or not isinstance(signals['signals'], list):
        raise ValueError('signals must have exactly one list field named signals')
    normalized_signals = []
    for item in signals['signals']:
        if not isinstance(item, dict):
            raise ValueError('every external signal must be an object')
        path = validate_repo_target(repo_root, str(item.get('path', '')))
        if '::' in path:
            raise ValueError('external signal path must identify a file, not a symbol')
        source = str(item.get('source', '')).strip().lower()
        if source not in ALLOWED_SIGNAL_SOURCES:
            raise ValueError(f'unsupported external signal source: {source!r}')
        try:
            weight = int(item.get('weight'))
        except (TypeError, ValueError) as exc:
            raise ValueError('external signal weight must be an integer') from exc
        if not 1 <= weight <= 20:
            raise ValueError('external signal weight must be between 1 and 20')
        summary = str(item.get('summary', '')).strip()
        metadata = item.get('metadata', {})
        if not summary or not isinstance(metadata, dict):
            raise ValueError('external signal requires a summary and object metadata')
        normalized_signals.append({'path': path, 'source': source, 'weight': weight, 'summary': summary, 'metadata': metadata})
    return policy_markdown, {'signals': normalized_signals}, summary_markdown
