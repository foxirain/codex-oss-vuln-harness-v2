from __future__ import annotations

from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.findings import finding_slug
from oss_harness.outputs import require_successful_response
from oss_harness.paths import atomic_write_text


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
    if report_dir.is_symlink():
        raise RuntimeError(f'report output directory must not be a symlink: {report_dir}')
    report_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for finding_file in finding_files:
        slug = finding_slug(finding_file)
        item_dir = report_dir / slug
        if item_dir.is_symlink():
            raise RuntimeError(f'report item directory must not be a symlink: {item_dir}')
        item_dir.mkdir(parents=True, exist_ok=True)
        report_file = item_dir / 'report.md'
        response_file = item_dir / 'codex-response.txt'
        stdout_file = item_dir / 'codex.stdout.txt'
        stderr_file = item_dir / 'codex.stderr.txt'
        report_file.unlink(missing_ok=True)
        prompt = _report_prompt(session_dir, repo_root, finding_file, template_text, report_file)
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
            report = require_successful_response(artifacts.returncode, response_file).strip()
            if len(report) < 80:
                raise ValueError('generated report is too short to be credible')
            atomic_write_text(report_file, report + '\n')
            results.append({'finding': str(finding_file), 'ok': True, 'report': str(report_file)})
        except (OSError, RuntimeError, ValueError) as exc:
            results.append({'finding': str(finding_file), 'ok': False, 'error': str(exc)})
    failed = [item for item in results if not item['ok']]
    return {
        'report_dir': str(report_dir),
        'requested': str(len(finding_files)),
        'succeeded': str(len(results) - len(failed)),
        'failed': str(len(failed)),
        'success': str(not failed).lower(),
    }


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
Intended output file: {report_file}

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

Return only the final report Markdown as the final response. Do not write or modify files and do not add a confirmation.
'''
