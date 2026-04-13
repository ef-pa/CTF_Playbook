"""Shared data models for the CTF Playbook Builder.

Typed dataclasses that define the interface between services,
replacing ad-hoc dicts passed between classifier, builder, and DB layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TechniqueMatch:
    """A single technique classification, optionally with a sub-technique.

    Carries level-specific recognition signals and solve steps:
    - recognition_signals / solve_steps: technique-family level
    - sub_recognition_signals / sub_solve_steps: sub-technique-specific
    """

    technique: str
    sub_technique: str | None = None
    recognition_signals: list[str] = field(default_factory=list)
    solve_steps: list[str] = field(default_factory=list)
    sub_recognition_signals: list[str] = field(default_factory=list)
    sub_solve_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {"technique": self.technique}
        if self.sub_technique:
            d["sub_technique"] = self.sub_technique
        if self.recognition_signals:
            d["recognition_signals"] = self.recognition_signals
        if self.solve_steps:
            d["solve_steps"] = self.solve_steps
        if self.sub_recognition_signals:
            d["sub_recognition_signals"] = self.sub_recognition_signals
        if self.sub_solve_steps:
            d["sub_solve_steps"] = self.sub_solve_steps
        return d

    @classmethod
    def from_dict(cls, d: dict | str) -> TechniqueMatch:
        if isinstance(d, str):
            return cls(technique=d)

        def _as_list(val) -> list[str]:
            """Normalize to list — handles missing, bare string, or list."""
            if val is None:
                return []
            if isinstance(val, str):
                return [val]
            return list(val)

        return cls(
            technique=d["technique"],
            sub_technique=d.get("sub_technique"),
            recognition_signals=_as_list(d.get("recognition_signals")),
            solve_steps=_as_list(d.get("solve_steps")),
            sub_recognition_signals=_as_list(d.get("sub_recognition_signals")),
            sub_solve_steps=_as_list(d.get("sub_solve_steps")),
        )


@dataclass
class ClassificationResult:
    """Structured output from the LLM classifier."""

    techniques: list[TechniqueMatch]
    tools_used: list[str]
    solve_steps: list[str]
    recognition_signals: list[str]
    difficulty: str
    summary: str

    @property
    def technique_slugs(self) -> list[str]:
        """Flat list of technique slugs for backward compat."""
        return [t.technique for t in self.techniques]

    @property
    def flat_recognition(self) -> list[str]:
        """Aggregate recognition signals: per-technique first, top-level fallback."""
        signals = []
        seen = set()
        for t in self.techniques:
            for s in t.recognition_signals:
                if s not in seen:
                    seen.add(s)
                    signals.append(s)
        if signals:
            return signals
        return list(self.recognition_signals)

    @property
    def flat_solve_steps(self) -> list[str]:
        """Aggregate solve steps: per-technique first, top-level fallback."""
        steps = []
        for t in self.techniques:
            if t.solve_steps:
                steps.extend(t.solve_steps)
        if steps:
            return steps
        return list(self.solve_steps)


@dataclass
class WriteupRecord:
    """A writeup row as passed between services (not a DB model)."""

    id: int
    url: str
    challenge_name: str
    category: str
    event_name: str
    year: int | None
    raw_path: str | None = None
    source: str | None = None


@dataclass
class WriteupExample:
    """A single example writeup within a technique's pattern data."""

    challenge: str
    event: str
    year: int | None
    url: str
    summary: str
    difficulty: str


@dataclass
class TechniqueData:
    """Aggregated data for a single technique, built from classified writeups."""

    slug: str
    recognition: dict[str, int] = field(default_factory=dict)
    tools: dict[str, int] = field(default_factory=dict)
    steps: list[list[str]] = field(default_factory=list)
    difficulties: dict[str, int] = field(default_factory=dict)
    examples: list[WriteupExample] = field(default_factory=list)
