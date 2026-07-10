from __future__ import annotations

import json
import fcntl
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from oss_harness.paths import atomic_write_text

STATE_FILENAME = 'review_state.json'
DEFAULT_RESPONSE_FILENAME = 'codex_response.txt'
DEFAULT_RESPONSE_ARCHIVE_DIRNAME = 'responses'
LOCK_FILENAME = '.review_state.lock'
RESPONSE_LOCK_FILENAME = '.response.lock'


def state_path(session_dir: Path) -> Path:
    return session_dir / STATE_FILENAME


def response_path(session_dir: Path) -> Path:
    return session_dir / DEFAULT_RESPONSE_FILENAME


def response_archive_dir(session_dir: Path) -> Path:
    return session_dir / DEFAULT_RESPONSE_ARCHIVE_DIRNAME


def _tail_followup_depth(history: list[dict]) -> int:
    depth = 0
    for item in reversed(history):
        if item.get('rank') is None:
            depth += 1
            continue
        break
    return depth


def _normalize_state(session_dir: Path, state: dict) -> dict:
    normalized = {
        'current_rank': int(state.get('current_rank', 1) or 1),
        'history': list(state.get('history', [])),
        'manual_next_target': state.get('manual_next_target', '') or '',
        'manual_next_prompt': state.get('manual_next_prompt', '') or '',
        'manual_followup_depth': state.get('manual_followup_depth'),
        'pending_rank': state.get('pending_rank'),
        'pending_target': state.get('pending_target', '') or '',
        'pending_prompt_source': state.get('pending_prompt_source', '') or '',
        'pending_response_file': state.get('pending_response_file') or str(response_path(session_dir)),
        'attempt_failures': list(state.get('attempt_failures', [])),
        'terminal_failures': list(state.get('terminal_failures', [])),
        'retry_counts': dict(state.get('retry_counts', {})),
    }
    if normalized['manual_followup_depth'] is None:
        normalized['manual_followup_depth'] = _tail_followup_depth(normalized['history'])
    else:
        normalized['manual_followup_depth'] = int(normalized['manual_followup_depth'] or 0)
    return normalized


def _initialize_state_unlocked(session_dir: Path) -> dict:
    state = _normalize_state(session_dir, {})
    _save_state_unlocked(session_dir, state)
    return state


def _load_state_unlocked(session_dir: Path) -> dict:
    path = state_path(session_dir)
    if not path.exists():
        return _initialize_state_unlocked(session_dir)
    raw = json.loads(path.read_text(encoding='utf-8'))
    state = _normalize_state(session_dir, raw)
    if state != raw:
        _save_state_unlocked(session_dir, state)
    return state


def _save_state_unlocked(session_dir: Path, state: dict) -> None:
    atomic_write_text(state_path(session_dir), json.dumps(_normalize_state(session_dir, state), indent=2) + '\n')


@contextmanager
def _state_lock(session_dir: Path):
    session_dir.mkdir(parents=True, exist_ok=True)
    with (session_dir / LOCK_FILENAME).open('a+', encoding='utf-8') as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def exclusive_response_lock(session_dir: Path):
    session_dir.mkdir(parents=True, exist_ok=True)
    with (session_dir / RESPONSE_LOCK_FILENAME).open('a+', encoding='utf-8') as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(f'another response consumer is already using {session_dir}') from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def initialize_state(session_dir: Path) -> dict:
    with _state_lock(session_dir):
        return _initialize_state_unlocked(session_dir)


def load_state(session_dir: Path) -> dict:
    with _state_lock(session_dir):
        return _load_state_unlocked(session_dir)


def save_state(session_dir: Path, state: dict) -> None:
    with _state_lock(session_dir):
        _save_state_unlocked(session_dir, state)


def set_pending_review(session_dir: Path, rank: int | None, target: str, prompt_source: str) -> dict:
    with _state_lock(session_dir):
        state = _load_state_unlocked(session_dir)
        state['pending_rank'] = rank
        state['pending_target'] = target
        state['pending_prompt_source'] = prompt_source
        state['pending_response_file'] = str(response_path(session_dir))
        _save_state_unlocked(session_dir, state)
        return state


def record_review(
    session_dir: Path,
    rank: int | None,
    target: str,
    verdict: str,
    notes: str,
    next_target: str,
    next_prompt: str,
    auto_advance: bool,
) -> dict:
    with _state_lock(session_dir):
        state = _load_state_unlocked(session_dir)
        state['retry_counts'].pop(_retry_key(rank, target), None)
        state['history'].append(
            {
                'rank': rank,
                'target': target,
                'verdict': verdict,
                'notes': notes,
                'next_target': next_target,
                'next_prompt': next_prompt,
            }
        )
        if next_target:
            state['manual_next_target'] = next_target
            state['manual_next_prompt'] = next_prompt
            state['manual_followup_depth'] = int(state.get('manual_followup_depth', 0)) + 1
            if auto_advance and rank is not None and rank >= state.get('current_rank', 1):
                state['current_rank'] = rank + 1
        elif auto_advance and rank is not None and rank >= state.get('current_rank', 1):
            state['current_rank'] = rank + 1
            state['manual_next_target'] = ''
            state['manual_next_prompt'] = ''
            state['manual_followup_depth'] = 0
        else:
            state['manual_next_target'] = ''
            state['manual_next_prompt'] = ''
            state['manual_followup_depth'] = 0
        state['pending_rank'] = None
        state['pending_target'] = ''
        state['pending_prompt_source'] = ''
        state['pending_response_file'] = str(response_path(session_dir))
        _save_state_unlocked(session_dir, state)
        return state


def completed_ranks(state: dict) -> set[int]:
    return {int(item.get('rank', 0)) for item in state.get('history', []) if item.get('rank') is not None}


def failed_ranks(state: dict) -> set[int]:
    return {
        int(item['rank'])
        for item in state.get('terminal_failures', [])
        if item.get('rank') is not None
    }


def record_attempt_failure(
    session_dir: Path,
    *,
    rank: int | None,
    target: str,
    kind: str,
    detail: str,
    max_attempts: int,
) -> tuple[dict, bool, int]:
    """Record an operational failure without turning it into an audit verdict."""
    with _state_lock(session_dir):
        state = _load_state_unlocked(session_dir)
        retry_key = _retry_key(rank, target)
        attempts = int(state.get('retry_counts', {}).get(retry_key, 0)) + 1
        state['retry_counts'][retry_key] = attempts
        item = {
            'rank': rank,
            'target': target,
            'kind': kind,
            'detail': detail,
            'attempt': attempts,
            'at': datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
        }
        state['attempt_failures'].append(item)
        terminal = attempts >= max_attempts
        if terminal:
            state['terminal_failures'].append(item)
            if rank is not None and rank >= int(state.get('current_rank', 1)):
                state['current_rank'] = rank + 1
            state['pending_rank'] = None
            state['pending_target'] = ''
            state['pending_prompt_source'] = ''
            state['manual_next_target'] = ''
            state['manual_next_prompt'] = ''
            state['manual_followup_depth'] = 0
        _save_state_unlocked(session_dir, state)
        return state, terminal, attempts


def clear_manual_followup(session_dir: Path, *, clear_pending: bool = False) -> dict:
    with _state_lock(session_dir):
        state = _load_state_unlocked(session_dir)
        state['manual_next_target'] = ''
        state['manual_next_prompt'] = ''
        state['manual_followup_depth'] = 0
        if clear_pending:
            state['pending_rank'] = None
            state['pending_target'] = ''
            state['pending_prompt_source'] = ''
        _save_state_unlocked(session_dir, state)
        return state


def _retry_key(rank: int | None, target: str) -> str:
    return f'{rank if rank is not None else "manual"}:{target}'
