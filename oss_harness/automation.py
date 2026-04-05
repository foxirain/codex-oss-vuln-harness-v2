from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec


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
        add_dirs=[out_dir, policy_path.parent, signals_path.parent],
    )
    return {
        'policy': str(policy_path),
        'signals': str(signals_path),
        'summary': str(summary_path),
        'response_file': str(response_file),
        'stdout_file': str(stdout_file),
        'stderr_file': str(stderr_file),
        'returncode': str(artifacts.returncode),
    }


def _bootstrap_prompt(repo_root: Path, policy_path: Path, signals_path: Path, summary_path: Path) -> str:
    today = datetime.now(UTC).strftime('%Y-%m-%d')
    return f'''You are preparing a Codex OSS vulnerability-hunting harness bootstrap for a repository.

Repository root: {repo_root}
Today (UTC): {today}

You must use both:
1. web search for latest project policy / advisory / security-process data
2. local repository analysis for actual attack surface, entrypoints, hot paths, and likely sinks

Create exactly these files:
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

Requirements for the signals file:
- Produce JSON with exactly this top-level shape:
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

Requirements for the bootstrap summary:
- Keep it short.
- Include:
  - project_type
  - best_external_sources
  - policy_basis
  - ambiguous_areas
  - output_files

Do not merely print the content in the final response. Write the files directly at the paths above, then print a short confirmation summarizing what you wrote.
'''
