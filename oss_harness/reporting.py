from __future__ import annotations

from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.findings import finding_slug


def run_report(
    session_dir: Path,
    *,
    repo_root: Path,
    finding_files: list[Path],
    template_text: str,
    timeout_spec: str,
    model: str,
    sandbox: str,
    full_auto: bool,
    unsafe_bypass: bool,
) -> dict[str, str]:
    session_dir = session_dir.expanduser().resolve()
    report_dir = session_dir / 'reports'
    report_dir.mkdir(parents=True, exist_ok=True)

    for finding_file in finding_files:
        slug = finding_slug(finding_file)
        item_dir = report_dir / slug
        item_dir.mkdir(parents=True, exist_ok=True)
        report_file = item_dir / 'report.md'
        response_file = item_dir / 'codex-response.txt'
        stdout_file = item_dir / 'codex.stdout.txt'
        stderr_file = item_dir / 'codex.stderr.txt'
        prompt = _report_prompt(session_dir, repo_root, finding_file, template_text, report_file)
        run_codex_exec(
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
            add_dirs=[session_dir, report_dir, item_dir],
        )
    return {'report_dir': str(report_dir), 'count': str(len(finding_files))}


def _report_prompt(session_dir: Path, repo_root: Path, finding_file: Path, template_text: str, report_file: Path) -> str:
    slug = finding_slug(finding_file)
    review_json = session_dir / 'review' / slug / 'review.json'
    review_md = session_dir / 'review' / slug / 'review.md'
    repro_dir = session_dir / 'repro' / slug
    return f'''You are writing a final vulnerability report from harness artifacts.

Repository root: {repo_root}
Finding file: {finding_file}
Review json: {review_json}
Review markdown: {review_md}
Repro directory: {repro_dir}
Output file: {report_file}

Formatting instruction or template:
{template_text}

Requirements:
- Use the finding, review, repro result, and any helper files as source material.
- Produce the strongest final report possible.
- If the provided format is loose text, infer a high-quality structure that matches the requested style.
- If evidence is incomplete, say exactly what is confirmed vs still inferred.
- Prefer exact files, functions, boundaries, and impact statements over generic language.
- If a repro exists, include the repro command and observed effect.
- If no repro exists, state that clearly.

Write the final report directly to {report_file} and then print a short confirmation.
'''
