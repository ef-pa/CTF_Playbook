"""Shared data models for the CTF Playbook Builder.

Typed dataclasses that define the interface between services,
replacing ad-hoc dicts passed between classifier, builder, and DB layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ClassificationResult:
    """Structured output from the LLM classifier."""

    techniques: list[str]
    tools_used: list[str]
    solve_steps: list[str]
    recognition_signals: list[str]
    difficulty: str
    summary: str


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
