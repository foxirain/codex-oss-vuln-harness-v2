from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent


@dataclass(slots=True)
class ExecArtifacts:
    response_file: Path
    stdout_file: Path
    stderr_file: Path
    returncode: int


def parse_duration(spec: str) -> int:
    spec = spec.strip().lower()
    units = {'s': 1, 'm': 60, 'h': 3600}
    if spec[-1] in units:
        return max(1, int(float(spec[:-1]) * units[spec[-1]]))
    return max(1, int(float(spec)))


def run_codex_exec(
    *,
    repo_root: Path,
    prompt_text: str,
    response_file: Path,
    stdout_file: Path,
    stderr_file: Path,
    timeout_seconds: int,
    model: str,
    sandbox: str,
    full_auto: bool,
    unsafe_bypass: bool,
    add_dirs: list[Path] | None = None,
) -> ExecArtifacts:
    repo_root = repo_root.expanduser().resolve()
    response_file = response_file.expanduser().resolve()
    stdout_file = stdout_file.expanduser().resolve()
    stderr_file = stderr_file.expanduser().resolve()
    response_file.parent.mkdir(parents=True, exist_ok=True)
    stdout_file.parent.mkdir(parents=True, exist_ok=True)
    stderr_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = ['codex', 'exec', '-C', str(repo_root), '--skip-git-repo-check', '--add-dir', str(PACKAGE_ROOT), '-o', str(response_file), '--color', 'never']
    seen_dirs: set[str] = {str(PACKAGE_ROOT)}
    for extra in add_dirs or []:
        resolved = str(extra.expanduser().resolve())
        if resolved in seen_dirs:
            continue
        seen_dirs.add(resolved)
        cmd.extend(['--add-dir', resolved])
    if unsafe_bypass:
        cmd.append('--dangerously-bypass-approvals-and-sandbox')
    else:
        if full_auto:
            cmd.append('--full-auto')
        cmd.extend(['--sandbox', sandbox])
    if model:
        cmd.extend(['-m', model])

    try:
        proc = subprocess.run(
            cmd,
            input=prompt_text,
            text=True,
            capture_output=True,
            cwd=str(PACKAGE_ROOT),
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout_text = _ensure_text(exc.stdout)
        stderr_text = _ensure_text(exc.stderr) + '\nTIMEOUT\n'
        stdout_file.write_text(stdout_text, encoding='utf-8')
        stderr_file.write_text(stderr_text, encoding='utf-8')
        return ExecArtifacts(response_file=response_file, stdout_file=stdout_file, stderr_file=stderr_file, returncode=124)

    stdout_file.write_text(proc.stdout or '', encoding='utf-8')
    stderr_file.write_text(proc.stderr or '', encoding='utf-8')
    return ExecArtifacts(response_file=response_file, stdout_file=stdout_file, stderr_file=stderr_file, returncode=proc.returncode)


def _ensure_text(value: str | bytes | None) -> str:
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='ignore')
    return value
