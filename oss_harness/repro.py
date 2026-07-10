from __future__ import annotations

from pathlib import Path
import re
import shutil

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.findings import finding_slug
from oss_harness.outputs import parse_json_object_response, require_successful_response
from oss_harness.paths import atomic_write_text


_WINDOWS_DRIVE = re.compile(r'^[A-Za-z]:')
STATUSES = {'success', 'partial', 'physically_impossible'}


def run_repro(
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
    repro_dir = session_dir / 'repro'
    if repro_dir.is_symlink():
        raise RuntimeError(f'repro output directory must not be a symlink: {repro_dir}')
    repro_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for finding_file in finding_files:
        slug = finding_slug(finding_file)
        item_dir = repro_dir / slug
        if item_dir.is_symlink():
            raise RuntimeError(f'repro output directory must not be a symlink: {item_dir}')
        if item_dir.exists():
            shutil.rmtree(item_dir)
        item_dir.mkdir(parents=True)
        response_file = item_dir / 'codex-response.txt'
        stdout_file = item_dir / 'codex.stdout.txt'
        stderr_file = item_dir / 'codex.stderr.txt'
        prompt = _repro_prompt(session_dir, repo_root, finding_file, item_dir)
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
            status, files = _validate_repro_payload(parse_json_object_response(response))
            for relative, content in files.items():
                output = item_dir / relative
                atomic_write_text(output, content.rstrip() + '\n', mode=0o700 if relative == 'repro.sh' else None)
            atomic_write_text(item_dir / 'repro_manifest.json', _manifest_text(status, files))
            results.append({'finding': str(finding_file), 'ok': True, 'status': status})
        except (OSError, RuntimeError, ValueError) as exc:
            results.append({'finding': str(finding_file), 'ok': False, 'error': str(exc)})
    failed = [item for item in results if not item['ok']]
    return {
        'repro_dir': str(repro_dir),
        'requested': str(len(finding_files)),
        'succeeded': str(len(results) - len(failed)),
        'failed': str(len(failed)),
        'success': str(not failed).lower(),
    }


def _repro_prompt(session_dir: Path, repo_root: Path, finding_file: Path, item_dir: Path) -> str:
    review_json = session_dir / 'review' / finding_slug(finding_file) / 'review.json'
    return f'''You are building a realistic reproduction package for one vulnerability finding.

Repository root: {repo_root}
Session directory: {session_dir}
Finding file: {finding_file}
Optional review json: {review_json}
Intended output directory: {item_dir}

Return exactly one JSON object as the final response. Do not write or modify files.
Schema:
{{
  "status": "success|partial|physically_impossible",
  "files": {{
    "repro.sh": "...",
    "result.md": "...",
    "optional-relative-helper": "..."
  }}
}}

Rules:
- Try to produce the strongest realistic reproduction or PoC path possible.
- Use the repository's real build, test, demo, or runtime surfaces when practical.
- If exact end-to-end reproduction is blocked, still produce the best achievable harness and explain the blockers.
- Mark `physically_impossible` only if reproduction truly requires unavailable hardware or impossible external conditions.
- A missing dependency, local setup gap, or lack of time is not enough to mark impossible.
- If QEMU, containers, local fixtures, crafted payloads, or config files would help, generate the closest realistic repro assets you can.

Requirements for repro.sh:
- one-shot shell script
- use bash
- be as automated as practical
- create or reuse any helper files in the same directory
- include comments only when they materially clarify a tricky setup step

Requirements for result.md:
- begin with: `Status: success`, `Status: partial`, or `Status: physically_impossible`
- explain exactly what was reproduced or what remains blocked
- list the command to run repro.sh
- describe expected output or observable security effect

All helper names must be relative, must not contain `..`, and must remain in the output directory.
Do not add commentary outside the JSON object.
'''


def _validate_repro_payload(payload: dict) -> tuple[str, dict[str, str]]:
    if set(payload) != {'status', 'files'}:
        raise ValueError('repro response must contain exactly status and files')
    status = str(payload['status']).strip().lower()
    files = payload['files']
    if status not in STATUSES:
        raise ValueError('invalid repro status')
    if not isinstance(files, dict) or not 2 <= len(files) <= 20:
        raise ValueError('repro files must be an object containing 2-20 files')
    normalized: dict[str, str] = {}
    for name, content in files.items():
        if not isinstance(name, str) or not isinstance(content, str):
            raise ValueError('repro filenames and contents must be strings')
        if not name or '\x00' in name or '\n' in name or '\\' in name or name.startswith(('/', '//')) or _WINDOWS_DRIVE.match(name):
            raise ValueError(f'unsafe repro filename: {name!r}')
        path = Path(name)
        if path.is_absolute() or any(part in {'', '.', '..'} for part in path.parts):
            raise ValueError(f'unsafe repro filename: {name!r}')
        if len(content.encode('utf-8')) > 1_000_000:
            raise ValueError(f'repro file is too large: {name!r}')
        normalized[path.as_posix()] = content
    if 'repro.sh' not in normalized or 'result.md' not in normalized:
        raise ValueError('repro response must include repro.sh and result.md')
    expected_prefix = f'Status: {status}'
    if not normalized['result.md'].lstrip().startswith(expected_prefix):
        raise ValueError(f'result.md must begin with {expected_prefix!r}')
    return status, normalized


def _manifest_text(status: str, files: dict[str, str]) -> str:
    import json
    return json.dumps({'status': status, 'files': sorted(files)}, indent=2) + '\n'
