from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Signal:
    name: str
    weight: int
    line_no: int
    line: str
    rationale: str
    language: str


@dataclass(slots=True)
class ExternalSignal:
    source: str
    weight: int
    summary: str
    url: str = ""
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class SymbolHint:
    name: str
    kind: str
    line_start: int
    line_end: int
    score: int = 0
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "score": self.score,
            "tags": self.tags,
        }


@dataclass(slots=True)
class Candidate:
    path: Path
    language: str
    subsystem: str
    exposure: str
    score: int
    attack_surfaces: list[str] = field(default_factory=list)
    sink_kinds: list[str] = field(default_factory=list)
    framework_hints: list[str] = field(default_factory=list)
    entrypoint_markers: list[str] = field(default_factory=list)
    primary_symbols: list[SymbolHint] = field(default_factory=list)
    semantic_summary: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    path_signals: list[str] = field(default_factory=list)
    external_signals: list[ExternalSignal] = field(default_factory=list)

    def to_dict(self, repo_root: Path) -> dict:
        return {
            "path": str(self.path.relative_to(repo_root)),
            "language": self.language,
            "subsystem": self.subsystem,
            "exposure": self.exposure,
            "score": self.score,
            "attack_surfaces": self.attack_surfaces,
            "sink_kinds": self.sink_kinds,
            "framework_hints": self.framework_hints,
            "entrypoint_markers": self.entrypoint_markers,
            "primary_symbols": [symbol.to_dict() for symbol in self.primary_symbols],
            "semantic_summary": self.semantic_summary,
            "reasons": self.reasons,
            "path_signals": self.path_signals,
            "signals": [
                {
                    "name": signal.name,
                    "weight": signal.weight,
                    "line_no": signal.line_no,
                    "line": signal.line,
                    "rationale": signal.rationale,
                    "language": signal.language,
                }
                for signal in self.signals
            ],
            "external_signals": [
                {
                    "source": signal.source,
                    "weight": signal.weight,
                    "summary": signal.summary,
                    "url": signal.url,
                    "metadata": signal.metadata,
                }
                for signal in self.external_signals
            ],
        }


@dataclass(slots=True)
class LanguageStat:
    language: str
    file_count: int
    extensions: list[str]
