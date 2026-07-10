from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from oss_harness import __version__
from oss_harness.paths import is_within, iter_repo_files


def file_sha256(path: Path | None) -> str:
    if path is None or not path.exists() or not path.is_file() or path.is_symlink():
        return ''
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(path: Path | None) -> str:
    if path is None or not path.exists() or not path.is_dir():
        return ''
    root = path.expanduser().resolve()
    digest = hashlib.sha256()
    for file_path in sorted(iter_repo_files(root)):
        relative = file_path.relative_to(root).as_posix().encode('utf-8')
        digest.update(len(relative).to_bytes(8, 'big'))
        digest.update(relative)
        digest.update(bytes.fromhex(file_sha256(file_path)))
    return digest.hexdigest()


def repository_state(repo_root: Path) -> dict[str, object]:
    root = repo_root.expanduser().resolve()
    commit = _git_output(root, ['rev-parse', 'HEAD'])
    tracked_status = _git_output(root, ['status', '--porcelain=v1', '--untracked-files=no'])
    untracked = _git_output(root, ['ls-files', '--others', '--exclude-standard'])
    tracked_dirty = bool(tracked_status)
    untracked_present = bool(untracked)
    return {
        'commit': commit,
        'tracked_dirty': tracked_dirty,
        'untracked_present': untracked_present,
        'worktree_dirty': tracked_dirty or untracked_present,
    }


def scan_provenance(
    repo_root: Path,
    *,
    policy: Path | None = None,
    config: Path | None = None,
    signals: Path | None = None,
    crash_dir: Path | None = None,
    sbom: Path | None = None,
) -> dict[str, object]:
    def file_entry(path: Path | None, *, trust: str) -> dict[str, str] | None:
        if path is None:
            return None
        return {'path': str(path), 'sha256': file_sha256(path), 'trust': trust}

    policy_trust = 'analyst-provided'
    if policy is not None and is_within(policy.expanduser().resolve(), repo_root.expanduser().resolve()):
        policy_trust = 'repository-provided-untrusted'
    return {
        'harness_version': __version__,
        'repository': repository_state(repo_root),
        'inputs': {
            'policy': file_entry(policy, trust=policy_trust),
            'config': file_entry(config, trust='analyst-provided'),
            'signals': file_entry(signals, trust='analyst-provided'),
            'crash_dir': ({'path': str(crash_dir), 'sha256': tree_sha256(crash_dir), 'trust': 'analyst-provided'} if crash_dir else None),
            'sbom': file_entry(sbom, trust='analyst-provided'),
        },
    }


def _git_output(repo_root: Path, args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ['git', '-C', str(repo_root), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ''
    return proc.stdout.strip() if proc.returncode == 0 else ''
