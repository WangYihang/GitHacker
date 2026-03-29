"""Typed data models for benchmark results."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field


@dataclass
class Tool:
    id: str
    name: str
    url: str
    version: str = "unknown"


@dataclass
class FeatureResult:
    supported: bool
    correct: int
    total: int
    ratio: float


@dataclass
class ScenarioResult:
    correct: int
    total: int
    ratio: float
    features: dict[str, FeatureResult]
    different_files: list[str] = field(default_factory=list)
    absent_files: list[str] = field(default_factory=list)
    duration: float | None = None
    exit_code: int | None = None
    http_requests: int | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "correct": self.correct,
            "total": self.total,
            "ratio": self.ratio,
            "different_files": self.different_files,
            "absent_files": self.absent_files,
            "features": {
                k: dataclasses.asdict(v) for k, v in self.features.items()
            },
            "duration": self.duration,
            "exit_code": self.exit_code,
            "http_requests": self.http_requests,
        }
        if self.error:
            d["error"] = self.error
        return d


@dataclass
class Metadata:
    generated_at: str
    git_commit: str
    test_repo_seed: int


@dataclass
class BenchmarkReport:
    metadata: Metadata
    tools: dict[str, Tool]
    scenarios: list[str]
    features: list[str]
    results: dict[str, dict[str, ScenarioResult]]

    def to_dict(self) -> dict:
        return {
            "metadata": dataclasses.asdict(self.metadata),
            "tools": {
                tid: {"name": t.name, "url": t.url, "version": t.version}
                for tid, t in self.tools.items()
            },
            "scenarios": self.scenarios,
            "features": self.features,
            "results": {
                tid: {sc: sr.to_dict() for sc, sr in scenarios.items()}
                for tid, scenarios in self.results.items()
            },
        }
