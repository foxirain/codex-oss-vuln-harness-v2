from __future__ import annotations

import subprocess
from collections import Counter, defaultdict
from pathlib import Path

from oss_harness.models import ExternalSignal

SECURITY_KEYWORDS = (
    "cve",
    "security",
    "overflow",
    "out-of-bounds",
    "uaf",
    "use-after-free",
    "sanitize",
    "hardening",
    "escape",
    "auth bypass",
    "ssrf",
    "rce",
    "xss",
    "fixes",
)


def collect_git_history_signals(repo_root: Path, max_commits: int = 400) -> dict[str, list[ExternalSignal]]:
    if not _is_git_repo(repo_root):
        return {}
    cmd = [
        "git",
        "-C",
        str(repo_root),
        "log",
        f"--max-count={max_commits}",
        "--date=short",
        "--format=commit:%H%x09%ad%x09%s",
        "--name-only",
        "--",
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        return {}

    recent_touches: Counter[str] = Counter()
    security_touches: Counter[str] = Counter()
    latest_subject: dict[str, str] = {}
    current_subject = ""
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        if line.startswith("commit:"):
            parts = line.split("\t", 2)
            current_subject = parts[2] if len(parts) >= 3 else ""
            continue
        rel_path = line.strip()
        recent_touches[rel_path] += 1
        if rel_path not in latest_subject:
            latest_subject[rel_path] = current_subject
        lowered = current_subject.lower()
        if any(keyword in lowered for keyword in SECURITY_KEYWORDS):
            security_touches[rel_path] += 1

    signals: dict[str, list[ExternalSignal]] = defaultdict(list)
    for rel_path, count in recent_touches.items():
        if count >= 3:
            signals[rel_path].append(
                ExternalSignal(
                    source="git",
                    weight=min(6, count),
                    summary=f"recent git churn: {count} touches",
                    metadata={"touch_count": count, "latest_subject": latest_subject.get(rel_path, "")},
                )
            )
    for rel_path, count in security_touches.items():
        signals[rel_path].append(
            ExternalSignal(
                source="git",
                weight=8 + min(6, count),
                summary=f"security-like git history: {count} matching commits",
                metadata={"match_count": count, "latest_subject": latest_subject.get(rel_path, "")},
            )
        )
    return dict(signals)


def _is_git_repo(repo_root: Path) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--is-inside-work-tree"],
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "true"
