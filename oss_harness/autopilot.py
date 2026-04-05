from __future__ import annotations

import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from oss_harness.ingest import parse_response
from oss_harness.session import completed_ranks, load_state, record_review, response_archive_dir, response_path, save_state, set_pending_review

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
MAX_MANUAL_FOLLOWUPS = 2
MAX_SAME_TARGET_ATTEMPTS = 3
STALLING_VERDICTS = {'needs_more_context', 'not_cve_candidate'}
STRONG_FINDING_VERDICTS = {'cve_candidate', 'plausible_security_bug'}
MAX_SUBSYSTEM_STALLS = 4
AUTOPILOT_DIRNAME = 'autopilot'


def run_autopilot(session_dir: Path, *, include_snippet: bool, duration_spec: str, per_run_timeout_spec: str, model: str, sandbox: str, full_auto: bool, unsafe_bypass: bool, stop_on_finding: bool) -> int:
    session_dir = session_dir.expanduser().resolve()
    manifest = _load_manifest(session_dir)
    autopilot_dir = session_dir / AUTOPILOT_DIRNAME
    prompts_dir = autopilot_dir / 'prompts'
    exec_dir = autopilot_dir / 'exec'
    findings_dir = autopilot_dir / 'findings'
    for path in (autopilot_dir, prompts_dir, exec_dir, findings_dir):
        path.mkdir(parents=True, exist_ok=True)

    progress_path = autopilot_dir / 'AUTOPILOT_PROGRESS.txt'
    findings_path = autopilot_dir / 'AUTOPILOT_FINDINGS.txt'
    status_path = autopilot_dir / 'AUTOPILOT_STATUS.txt'
    duration_seconds = _parse_duration(duration_spec)
    per_run_timeout_seconds = _parse_duration(per_run_timeout_spec)
    started_at = datetime.now(UTC)
    deadline = time.monotonic() + duration_seconds
    run_index = _existing_run_count(prompts_dir)

    _append_text(progress_path, f"\n== AUTOPILOT START {started_at.strftime('%Y-%m-%d %H:%M:%SZ')} ==\nsession={session_dir}\nrepo_root={manifest.get('repo_root', '')}\nduration={duration_spec}\nper_run_timeout={per_run_timeout_spec}\ninclude_snippet={int(include_snippet)}\nmodel={model or '<default>'}\n")
    _write_status(status_path, stage='starting', session_dir=session_dir, repo_root=manifest.get('repo_root', ''), started_at=started_at, duration_spec=duration_spec, runs=run_index, candidate_count=manifest.get('candidate_count', 0))

    while time.monotonic() < deadline:
        result = _ingest_pending_response(session_dir, findings_dir, findings_path, progress_path)
        if result is not None:
            _write_status(status_path, stage='ingested', session_dir=session_dir, repo_root=manifest.get('repo_root', ''), started_at=started_at, duration_spec=duration_spec, runs=run_index, last_target=result['target'], last_verdict=result['verdict'], last_next_target=result['next_target'], completed=len(load_state(session_dir).get('history', [])), subsystem_stalls=len(_stalled_subsystems(load_state(session_dir), manifest)))
            if stop_on_finding and result['verdict'] in STRONG_FINDING_VERDICTS:
                _append_text(progress_path, 'stop_reason=strong_finding_detected\n')
                return 0

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        try:
            next_prompt = _render_next_prompt(session_dir, include_snippet=include_snippet)
        except SystemExit as exc:
            _append_text(progress_path, f'stop_reason={exc}\n')
            _write_status(status_path, stage='finished', session_dir=session_dir, repo_root=manifest.get('repo_root', ''), started_at=started_at, duration_spec=duration_spec, runs=run_index)
            return 0

        run_index += 1
        prompt_path = prompts_dir / f'run-{run_index:04d}.prompt.txt'
        stdout_path = exec_dir / f'run-{run_index:04d}.stdout.txt'
        stderr_path = exec_dir / f'run-{run_index:04d}.stderr.txt'
        prompt_text = _build_autopilot_prompt(next_prompt)
        prompt_path.write_text(prompt_text, encoding='utf-8')
        _append_text(progress_path, f"\n== RUN {run_index:04d} {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')} ==\nrank={next_prompt['rank']}\ntarget={next_prompt['target']}\nprompt_source={next_prompt['prompt_source']}\nfixed_response_file={response_path(session_dir)}\n")
        _write_status(status_path, stage='running', session_dir=session_dir, repo_root=manifest.get('repo_root', ''), started_at=started_at, duration_spec=duration_spec, runs=run_index, current_target=next_prompt['target'], current_rank=next_prompt['rank'], target_attempts=_target_attempts(load_state(session_dir), next_prompt['target']), subsystem_stalls=len(_stalled_subsystems(load_state(session_dir), manifest)))

        proc = _run_codex_exec(repo_root=next_prompt['repo_root'], prompt_text=prompt_text, response_file=response_path(session_dir), stdout_path=stdout_path, stderr_path=stderr_path, timeout_seconds=max(1, min(int(remaining), per_run_timeout_seconds)), model=model, sandbox=sandbox, full_auto=full_auto, unsafe_bypass=unsafe_bypass)
        _append_text(progress_path, f'codex_exit_code={proc.returncode}\nstdout_file={stdout_path}\nstderr_file={stderr_path}\n')
        if proc.returncode != 0 and not _has_nonempty_response(response_path(session_dir)):
            _append_text(progress_path, 'stop_reason=codex_exec_failed_without_response\n')
            return proc.returncode or 1

    _ingest_pending_response(session_dir, findings_dir, findings_path, progress_path)
    _write_status(status_path, stage='finished', session_dir=session_dir, repo_root=manifest.get('repo_root', ''), started_at=started_at, duration_spec=duration_spec, runs=run_index)
    _append_text(progress_path, f"== AUTOPILOT END {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')} ==\n")
    return 0


def _run_codex_exec(*, repo_root: str, prompt_text: str, response_file: Path, stdout_path: Path, stderr_path: Path, timeout_seconds: int, model: str, sandbox: str, full_auto: bool, unsafe_bypass: bool) -> subprocess.CompletedProcess[str]:
    cmd = ['codex', 'exec', '-C', repo_root, '--skip-git-repo-check', '--add-dir', str(PACKAGE_ROOT), '-o', str(response_file), '--color', 'never']
    if unsafe_bypass:
        cmd.append('--dangerously-bypass-approvals-and-sandbox')
    else:
        if full_auto:
            cmd.append('--full-auto')
        cmd.extend(['--sandbox', sandbox])
    if model:
        cmd.extend(['-m', model])
    try:
        proc = subprocess.run(cmd, input=prompt_text, text=True, capture_output=True, cwd=str(PACKAGE_ROOT), timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired as exc:
        stdout_text = _ensure_text(exc.stdout)
        stderr_text = _ensure_text(exc.stderr) + '\nTIMEOUT\n'
        stdout_path.write_text(stdout_text, encoding='utf-8')
        stderr_path.write_text(stderr_text, encoding='utf-8')
        return subprocess.CompletedProcess(cmd, 124, stdout_text, stderr_text)
    stdout_path.write_text(proc.stdout or '', encoding='utf-8')
    stderr_path.write_text(proc.stderr or '', encoding='utf-8')
    return proc


def _ingest_pending_response(session_dir: Path, findings_dir: Path, findings_path: Path, progress_path: Path) -> dict | None:
    fixed_response = response_path(session_dir)
    state = load_state(session_dir)
    pending_target = (state.get('pending_target') or '').strip()
    if not pending_target or not fixed_response.exists() or fixed_response.stat().st_size == 0:
        return None
    text = fixed_response.read_text(encoding='utf-8')
    try:
        parsed = parse_response(text)
    except ValueError as exc:
        archive_path = _archive_response_file(session_dir, fixed_response)
        record_review(session_dir=session_dir, rank=state.get('pending_rank'), target=pending_target, verdict='needs_more_context', notes=f'parse_error: {exc}', next_target='', next_prompt='', auto_advance=True)
        _append_text(progress_path, f'ingested_target={pending_target}\ningested_verdict=needs_more_context\nresponse_archive={archive_path}\n')
        return {'target': pending_target, 'rank': state.get('pending_rank'), 'verdict': 'needs_more_context', 'next_target': ''}

    next_target = parsed['next_target'] if parsed['should_continue'] else ''
    current_attempts = _target_attempts(state, pending_target)
    if next_target and int(state.get('manual_followup_depth', 0)) >= MAX_MANUAL_FOLLOWUPS:
        next_target = ''
    if next_target and (next_target == pending_target or _target_attempts(state, next_target) >= MAX_SAME_TARGET_ATTEMPTS or _is_target_in_stalled_subsystem(next_target, state, _load_manifest(session_dir))):
        next_target = ''
    if parsed['verdict'] in STALLING_VERDICTS and current_attempts >= MAX_SAME_TARGET_ATTEMPTS:
        next_target = ''
    record_review(session_dir=session_dir, rank=state.get('pending_rank'), target=pending_target, verdict=parsed['verdict'], notes=parsed['notes'], next_target=next_target, next_prompt='', auto_advance=True)
    archive_path = _archive_response_file(session_dir, fixed_response)
    _append_text(progress_path, f"ingested_target={pending_target}\ningested_verdict={parsed['verdict']}\ningested_next_target={next_target}\nresponse_archive={archive_path}\n")
    if parsed['verdict'] in STRONG_FINDING_VERDICTS:
        finding_path = findings_dir / f"finding-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.txt"
        finding_path.write_text(text, encoding='utf-8')
        _append_text(findings_path, f"\n== FINDING {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')} ==\ntarget={pending_target}\nverdict={parsed['verdict']}\ndetails={finding_path}\narchive={archive_path}\n")
    return {'target': pending_target, 'rank': state.get('pending_rank'), 'verdict': parsed['verdict'], 'next_target': next_target}


def _archive_response_file(session_dir: Path, fixed_response: Path) -> Path:
    archive_dir = response_archive_dir(session_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"response-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.txt"
    fixed_response.replace(archive_path)
    return archive_path


def _render_next_prompt(session_dir: Path, *, include_snippet: bool) -> dict:
    manifest = _load_manifest(session_dir)
    state = load_state(session_dir)
    manual_target = (state.get('manual_next_target') or '').strip()
    manual_prompt = (state.get('manual_next_prompt') or '').strip()
    depth = int(state.get('manual_followup_depth', 0))
    if manual_target and (depth >= MAX_MANUAL_FOLLOWUPS or _target_attempts(state, manual_target) >= MAX_SAME_TARGET_ATTEMPTS or _is_target_in_stalled_subsystem(manual_target, state, manifest)):
        state['manual_next_target'] = ''
        state['manual_next_prompt'] = ''
        state['manual_followup_depth'] = 0
        save_state(session_dir, state)
        manual_target = ''
        manual_prompt = ''
    if manual_target:
        prompt_source = session_dir / 'review_state.json'
        prompt = _manual_followup_prompt(state, manual_target, manual_prompt)
        set_pending_review(session_dir, None, manual_target, str(prompt_source))
        return {'repo_root': manifest['repo_root'], 'prompt': prompt, 'prompt_source': prompt_source, 'snippet_path': None, 'include_snippet': False, 'target': manual_target, 'rank': None}

    rank, candidate = _next_pending_rank(state, manifest)
    prompt_path, snippet_path = _bundle_paths(session_dir, rank, candidate['path'])
    if not prompt_path.exists():
        raise SystemExit(f'missing prompt bundle for rank {rank}: {prompt_path}. Rerun oss-harness scan for this repository and use the new session directory.')
    prompt = prompt_path.read_text(encoding='utf-8')
    set_pending_review(session_dir, rank, candidate['path'], str(prompt_path))
    return {'repo_root': manifest['repo_root'], 'prompt': prompt, 'prompt_source': prompt_path, 'snippet_path': snippet_path, 'include_snippet': include_snippet, 'target': candidate['path'], 'rank': rank}


def _build_autopilot_prompt(rendered: dict) -> str:
    parts = [rendered['prompt'].rstrip()]
    if rendered.get('include_snippet') and rendered.get('snippet_path') and Path(rendered['snippet_path']).exists():
        snippet = Path(rendered['snippet_path']).read_text(encoding='utf-8').rstrip()
        if snippet:
            parts.extend(['', 'Supplemental snippet from the harness:', snippet])
    parts.extend(['', 'Final response contract:', 'Strict verdict:', '- one of: cve_candidate, plausible_security_bug, latent_bug, not_cve_candidate, needs_more_context', '', 'Single best next target:', '- <file/function>', '- use `none` if this branch should stop and the harness should move to the next ranked target', '', 'Summary:', '- 3 to 8 short lines only', '- include exact entrypoint, attacker control, sensitive sink or invariant break, and impact reasoning'])
    return '\n'.join(parts) + '\n'


def _manual_followup_prompt(state: dict, manual_target: str, manual_prompt: str) -> str:
    history = state.get('history', [])
    previous = history[-1] if history else {}
    lines = ['Continue from the previous audit.', 'Do not restart broad review.', '', f"Previous verdict: {previous.get('verdict', '')}", f"Previous target: {previous.get('target', '')}"]
    notes = (previous.get('notes') or '').strip()
    if notes:
        lines.append(f'Previous notes: {notes}')
    lines.extend(['', f'Now focus only on: {manual_target}'])
    if manual_prompt:
        lines.extend(['', manual_prompt.strip()])
    else:
        lines.extend(['', 'Requirements:', '1. Confirm the exact attacker-reachable path into this target.', '2. Validate concrete attacker control, trust-boundary crossing, and security impact.', '3. If nothing concrete exists, give a strict verdict and the single best next target.'])
    return '\n'.join(lines) + '\n'


def _next_pending_rank(state: dict, manifest: dict) -> tuple[int, dict]:
    done = completed_ranks(state)
    candidates = manifest.get('candidates', [])
    start = max(1, int(state.get('current_rank', 1)))
    for rank in range(start, len(candidates) + 1):
        if rank in done:
            continue
        candidate = candidates[rank - 1]
        target = candidate.get('path', '')
        if _is_actionable_candidate(target) and _target_attempts(state, target) < MAX_SAME_TARGET_ATTEMPTS and not _is_target_in_stalled_subsystem(target, state, manifest):
            return rank, candidate
    raise SystemExit('all ranked targets in this session have already been reviewed')






def _stalled_subsystems(state: dict, manifest: dict) -> set[str]:
    candidate_map = {item.get('path', ''): item for item in manifest.get('candidates', [])}
    counts: dict[str, int] = {}
    for item in state.get('history', []):
        if item.get('verdict') not in STALLING_VERDICTS:
            continue
        target = str(item.get('target', '')).strip()
        subsystem = _target_subsystem(target, candidate_map)
        if not subsystem:
            continue
        counts[subsystem] = counts.get(subsystem, 0) + 1
    return {name for name, count in counts.items() if count >= MAX_SUBSYSTEM_STALLS}


def _is_target_in_stalled_subsystem(target: str, state: dict, manifest: dict) -> bool:
    subsystem = _target_subsystem(target, {item.get('path', ''): item for item in manifest.get('candidates', [])})
    return bool(subsystem) and subsystem in _stalled_subsystems(state, manifest)


def _target_subsystem(target: str, candidate_map: dict[str, dict]) -> str:
    if not target:
        return ''
    if target in candidate_map:
        return str(candidate_map[target].get('subsystem', '')).strip()
    return target.split('/', 1)[0] if '/' in target else ''

def _target_attempts(state: dict, target: str) -> int:
    if not target:
        return 0
    return sum(1 for item in state.get('history', []) if str(item.get('target', '')).strip() == target)

def _is_actionable_candidate(path: str) -> bool:
    lowered = path.lower()
    if lowered.startswith(('docs/', 'examples/', 'samples/', 'vendor/', 'third_party/')):
        return False
    if '/test/' in lowered or '/tests/' in lowered or '/spec/' in lowered or '/specs/' in lowered:
        return False
    if lowered.endswith(('_test.go', '.spec.js', '.test.js', '.spec.ts', '.test.ts')):
        return False
    return True


def _bundle_paths(session_dir: Path, rank: int, rel_path: str) -> tuple[Path, Path]:
    bundle_dir = session_dir / 'bundles'
    prefix = f"{rank:02d}-{rel_path.replace('/', '__')}"
    return bundle_dir / f'{prefix}.md', bundle_dir / f'{prefix}.snippet.txt'


def _load_manifest(session_dir: Path) -> dict:
    manifest_path = session_dir / 'targets.json'
    if not manifest_path.exists():
        raise SystemExit(f'missing session manifest: {manifest_path}')
    return json.loads(manifest_path.read_text(encoding='utf-8'))


def _existing_run_count(prompts_dir: Path) -> int:
    return len(list(prompts_dir.glob('run-*.prompt.txt')))


def _append_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as handle:
        handle.write(text)


def _write_status(path: Path, **fields: object) -> None:
    path.write_text('\n'.join(f'{key}={value}' for key, value in fields.items() if value not in {None, ''}) + '\n', encoding='utf-8')


def _parse_duration(spec: str) -> int:
    spec = spec.strip().lower()
    units = {'s': 1, 'm': 60, 'h': 3600}
    if spec[-1] in units:
        return max(1, int(float(spec[:-1]) * units[spec[-1]]))
    return max(1, int(float(spec)))


def _ensure_text(value: str | bytes | None) -> str:
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='ignore')
    return value


def _has_nonempty_response(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0
