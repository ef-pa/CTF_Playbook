"""Shared data models for the CTF Playbook Builder.

Typed dataclasses that define the interface between services,
replacing ad-hoc dicts passed between classifier, builder, and DB layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TechniqueMatch:
    """A single technique classification, optionally with a sub-technique."""

    technique: str
    sub_technique: str | None = None

    def to_dict(self) -> dict:
        d = {"technique": self.technique}
        if self.sub_technique:
            d["sub_technique"] = self.sub_technique
        return d

    @classmethod
    def from_dict(cls, d: dict | str) -> TechniqueMatch:
        if isinstance(d, str):
            return cls(technique=d)
        return cls(technique=d["technique"], sub_technique=d.get("sub_technique"))


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
