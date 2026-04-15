"""Match challenge descriptions against playbook recognition signals.

Given a text description of a CTF challenge, rank known techniques by
how well their recognition signals match the input. Uses TF-IDF-weighted
token overlap plus phrase-match bonuses — no external dependencies.
"""

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from ctf_playbook.config import PLAYBOOK_DIR

PLAYBOOK_JSON = PLAYBOOK_DIR / "playbook.json"

_STOPWORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "in", "on", "at", "to",
    "for", "of", "with", "by", "from", "as", "or", "and", "it", "be",
    "that", "this", "which", "not", "but", "has", "have", "do", "does",
    "can", "will", "been", "being", "into", "than", "its", "you", "your",
})

_TOKEN_RE = re.compile(r"[a-z0-9_]+(?:\(\))?")


def _tokenize(text: str) -> list[str]:
    """Lowercase, split on non-alphanum, filter stopwords."""
    tokens = _TOKEN_RE.findall(text.lower())
    return [t for t in tokens if t not in _STOPWORDS]


@dataclass
class MatchResult:
    technique: str
    category: str
    confidence: float
    matched_signals: list[dict] = field(default_factory=list)
    difficulty: str = "medium"
    tools: list[str] = field(default_factory=list)
    solve_steps: list[str] = field(default_factory=list)
    solve_steps_from_consensus: bool = False
    sub_technique: str | None = None
    example_count: int = 0


class ChallengeMatcher:
    """Match challenge descriptions against playbook recognition signals."""

    def __init__(self, playbook: dict):
        self._techniques = playbook.get("techniques", {})
        self._signal_index = self._build_signal_index()
        self._idf = self._build_idf()

    def _build_signal_index(self) -> list[dict]:
        """Pre-process all signals into a flat index."""
        index = []
        for slug, tech in self._techniques.items():
            cat = tech.get("category", "misc")
            for sig in tech.get("recognition_signals", []):
                tokens = _tokenize(sig["signal"])
                if tokens:
                    index.append({
                        "signal": sig["signal"],
                        "tokens": set(tokens),
                        "normalized": sig["signal"].strip().lower(),
                        "count": sig["count"],
                        "technique": slug,
                        "sub_technique": None,
                        "category": cat,
                    })
            for sub_slug, sub in tech.get("sub_techniques", {}).items():
                for sig in sub.get("recognition_signals", []):
                    tokens = _tokenize(sig["signal"])
                    if tokens:
                        index.append({
                            "signal": sig["signal"],
                            "tokens": set(tokens),
                            "normalized": sig["signal"].strip().lower(),
                            "count": sig["count"],
                            "technique": slug,
                            "sub_technique": sub_slug,
                            "category": cat,
                        })
        return index

    def _build_idf(self) -> dict[str, float]:
        """Compute inverse document frequency for each token."""
        n = len(self._signal_index)
        if n == 0:
            return {}
        df: dict[str, int] = {}
        for entry in self._signal_index:
            for token in entry["tokens"]:
                df[token] = df.get(token, 0) + 1
        return {token: math.log(n / count) for token, count in df.items()}

    def identify(self, text: str, max_results: int = 10,
                 min_confidence: float = 5.0) -> list[MatchResult]:
        """Match input text against recognition signals."""
        if not text.strip():
            return []

        input_tokens = set(_tokenize(text))
        input_lower = text.strip().lower()
        if not input_tokens:
            return []

        # Score each signal
        tech_scores: dict[str, float] = {}
        tech_signals: dict[str, list[dict]] = {}

        for entry in self._signal_index:
            shared = input_tokens & entry["tokens"]
            if not shared:
                continue

            # Token overlap score weighted by IDF
            shared_idf = sum(self._idf.get(t, 1.0) for t in shared)
            total_idf = sum(self._idf.get(t, 1.0) for t in entry["tokens"])
            token_score = shared_idf / total_idf if total_idf else 0

            # Phrase match bonus
            phrase_bonus = 2.0 if entry["normalized"] in input_lower else 0

            signal_score = (token_score + phrase_bonus) * math.log(1 + entry["count"])

            key = entry["technique"]
            tech_scores[key] = tech_scores.get(key, 0) + signal_score
            tech_signals.setdefault(key, []).append({
                "signal": entry["signal"],
                "count": entry["count"],
                "score": round(signal_score, 2),
                "match_type": "phrase" if phrase_bonus else "token",
                "sub_technique": entry["sub_technique"],
            })

        if not tech_scores:
            return []

        # Normalize to 0-100
        max_score = max(tech_scores.values())
        results = []
        for slug, score in sorted(tech_scores.items(), key=lambda x: -x[1]):
            confidence = (score / max_score) * 100 if max_score else 0
            if confidence < min_confidence:
                break

            tech = self._techniques[slug]
            signals = sorted(tech_signals[slug], key=lambda x: -x["score"])

            # Find best sub-technique match if any
            sub_scores: dict[str, float] = {}
            for sig in signals:
                if sig["sub_technique"]:
                    sub_scores[sig["sub_technique"]] = (
                        sub_scores.get(sig["sub_technique"], 0) + sig["score"]
                    )
            best_sub = max(sub_scores, key=sub_scores.get) if sub_scores else None

            # Use sub-technique solve_steps when available
            solve_steps = tech.get("solve_steps", [])
            steps_from_consensus = tech.get("solve_steps_from_consensus", False)
            if best_sub:
                sub_tech = tech.get("sub_techniques", {}).get(best_sub, {})
                sub_steps = sub_tech.get("solve_steps", [])
                if sub_steps:
                    solve_steps = sub_steps
                    steps_from_consensus = sub_tech.get(
                        "solve_steps_from_consensus", False)

            results.append(MatchResult(
                technique=slug,
                category=tech.get("category", "misc"),
                confidence=round(confidence, 1),
                matched_signals=signals[:5],
                difficulty=tech.get("difficulty", "medium"),
                tools=[t["tool"] for t in tech.get("tools", [])[:5]],
                solve_steps=solve_steps,
                solve_steps_from_consensus=steps_from_consensus,
                sub_technique=best_sub,
                example_count=tech.get("example_count", 0),
            ))

            if len(results) >= max_results:
                break

        return results


def identify_from_playbook(text: str, playbook_path: Path | None = None,
                           max_results: int = 10) -> list[MatchResult]:
    """Load the playbook and run identification. One-shot convenience."""
    path = playbook_path or PLAYBOOK_JSON
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        playbook = json.load(f)
    matcher = ChallengeMatcher(playbook)
    return matcher.identify(text, max_results=max_results)
