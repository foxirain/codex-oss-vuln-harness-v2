from __future__ import annotations

import json
from pathlib import Path

from oss_harness.paths import atomic_write_text


def parse_json_object_response(text: str) -> dict:
    value = text.strip()
    if value.startswith('```'):
        lines = value.splitlines()
        if len(lines) < 3 or not lines[-1].strip().startswith('```'):
            raise ValueError('unterminated JSON code fence')
        value = '\n'.join(lines[1:-1]).strip()
    try:
        data = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f'response is not an exact JSON object: {exc}') from exc
    if not isinstance(data, dict):
        raise ValueError('response JSON must be an object')
    return data


def require_successful_response(returncode: int, response_file: Path) -> str:
    if returncode != 0:
        raise RuntimeError(f'codex exec failed with return code {returncode}')
    if not response_file.exists() or response_file.stat().st_size == 0:
        raise RuntimeError('codex exec returned no response')
    return response_file.read_text(encoding='utf-8')


def write_json(path: Path, data: dict) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + '\n')
