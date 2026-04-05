from __future__ import annotations

from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.findings import finding_slug


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
    repro_dir.mkdir(parents=True, exist_ok=True)

    for finding_file in finding_files:
        slug = finding_slug(finding_file)
        item_dir = repro_dir / slug
        item_dir.mkdir(parents=True, exist_ok=True)
        response_file = item_dir / 'codex-response.txt'
        stdout_file = item_dir / 'codex.stdout.txt'
        stderr_file = item_dir / 'codex.stderr.txt'
        prompt = _repro_prompt(session_dir, repo_root, finding_file, item_dir)
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
            add_dirs=[session_dir, repro_dir, item_dir],
        )
    return {'repro_dir': str(repro_dir), 'count': str(len(finding_files))}


def _repro_prompt(session_dir: Path, repo_root: Path, finding_file: Path, item_dir: Path) -> str:
    review_json = session_dir / 'review' / finding_slug(finding_file) / 'review.json'
    return f'''You are building a realistic reproduction package for one vulnerability finding.

Repository root: {repo_root}
Session directory: {session_dir}
Finding file: {finding_file}
Optional review json: {review_json}
Output directory: {item_dir}

You must create files directly in {item_dir}.
Always create all of the following:
- {item_dir / 'repro.sh'}
- {item_dir / 'result.md'}
- any helper files needed by repro.sh

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

After writing files, print a short confirmation with the chosen status.
'''
