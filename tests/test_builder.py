"""Tests for the playbook builder."""

import json
from collections import defaultdict

from ctf_playbook.services.builder import (
    _merge_solve_steps, _dedup_step_strings,
    _normalize_signal, _merge_signals, _merge_tools,
    _tokenize_for_scoring, _build_context_keywords,
    _serialize_technique, _assemble_recon_patterns,
    _assemble_tool_reference, _assemble_cross_references,
    _render_pattern_content, _render_recon_trees, TECHNIQUES_DIR,
)


# ── _merge_solve_steps ───────────────────────────────────────────────────


class TestMergeSolveSteps:
    def test_empty(self):
        steps, is_consensus = _merge_solve_steps([])
        assert steps == []
        assert is_consensus is False

    def test_single_writeup(self):
        steps, is_consensus = _merge_solve_steps([["find vuln", "exploit", "get flag"]])
        assert steps == ["find vuln", "exploit", "get flag"]
        assert is_consensus is False

    def test_single_writeup_truncates(self):
        long_steps = [["step"] * 10]
        steps, _ = _merge_solve_steps(long_steps, max_steps=5)
        assert len(steps) == 5

    def test_consensus_preferred(self):
        """Steps appearing in 2+ writeups should be selected over unique steps."""
        data = [
            ["find vuln", "calculate offset", "build exploit", "get flag"],
            ["find vuln", "calculate offset", "craft payload", "get flag"],
            ["find vuln", "calculate offset", "write exploit", "get flag"],
        ]
        steps, is_consensus = _merge_solve_steps(data)
        # "find vuln", "calculate offset", and "get flag" appear in all 3
        assert "find vuln" in steps
        assert "calculate offset" in steps
        assert "get flag" in steps
        assert is_consensus is True

    def test_consensus_ordered_by_position(self):
        """Consensus steps should be ordered by their average position."""
        data = [
            ["step A", "step B", "step C"],
            ["step A", "step B", "step C"],
        ]
        steps, _ = _merge_solve_steps(data)
        assert steps == ["step A", "step B", "step C"]

    def test_fallback_to_longest_when_no_consensus(self):
        """With 3+ writeups and no consensus, fall back to longest list."""
        data = [
            ["unique-a1", "unique-a2"],
            ["unique-b1", "unique-b2", "unique-b3", "unique-b4"],
            ["unique-c1"],
        ]
        steps, is_consensus = _merge_solve_steps(data)
        assert len(steps) == 4  # longest list
        assert is_consensus is False

    def test_case_insensitive_dedup(self):
        """Matching should be case-insensitive."""
        data = [
            ["Find vulnerability", "Exploit"],
            ["find vulnerability", "exploit"],
        ]
        steps, _ = _merge_solve_steps(data)
        assert len(steps) == 2

    def test_max_steps_caps_consensus(self):
        """Consensus output should be capped at max_steps."""
        common = [f"step {i}" for i in range(10)]
        data = [common, common, common]
        steps, is_consensus = _merge_solve_steps(data, max_steps=5)
        assert len(steps) == 5
        assert is_consensus is True

    def test_two_writeups_partial_overlap(self):
        """Two writeups with some shared steps and some unique."""
        data = [
            ["decompile binary", "find overflow", "write exploit"],
            ["checksec binary", "find overflow", "build rop chain", "write exploit"],
        ]
        steps, is_consensus = _merge_solve_steps(data)
        # "find overflow" and "write exploit" appear twice = consensus
        # Only 2 consensus steps < 3, so falls back to longest
        assert len(steps) == 4  # longest list has 4 steps
        assert is_consensus is False

    def test_near_duplicate_steps_merged(self):
        """Steps that differ only by articles/prepositions should merge."""
        data = [
            ["load binary into disassembler/decompiler"],
            ["Load the binary into a disassembler or decompiler"],
        ]
        steps, _ = _merge_solve_steps(data)
        assert len(steps) == 1

    def test_distinct_steps_not_merged(self):
        """Steps with different semantics should remain separate."""
        data = [
            ["analyze the binary for vulnerabilities", "run the exploit"],
            ["analyze the binary for vulnerabilities", "patch the binary"],
        ]
        steps, _ = _merge_solve_steps(data)
        # "analyze the binary" appears in both — consensus
        # "run the exploit" and "patch the binary" are distinct
        assert any("analyze" in s for s in steps)


# ── Context-aware fallback scoring ──────────────────────────────────────


class TestTokenizeForScoring:
    def test_basic(self):
        result = _tokenize_for_scoring("RSA with small exponent")
        assert "rsa" in result
        assert "small" in result
        assert "exponent" in result
        assert "with" not in result  # stopword

    def test_tool_notation(self):
        result = _tokenize_for_scoring("printf() format string")
        assert "printf()" in result
        assert "format" in result
        assert "string" in result

    def test_empty(self):
        assert _tokenize_for_scoring("") == set()


class TestBuildContextKeywords:
    def test_combines_signals_and_tools(self):
        recognition = {"small public exponent": 3, "RSA modulus": 2}
        tools = {"sage": 5, "pycryptodome": 3}
        result = _build_context_keywords(recognition, tools)
        assert "rsa" in result
        assert "modulus" in result
        assert "exponent" in result
        assert "sage" in result
        assert "pycryptodome" in result

    def test_empty(self):
        assert _build_context_keywords({}, {}) == set()


class TestFallbackScoring:
    def test_prefers_relevant_steps(self):
        """Shorter list with relevant keywords should beat longer irrelevant list."""
        data = [
            # Long but irrelevant (git/forensics steps for an RSA technique)
            ["extract git objects from archive", "decompress zlib data",
             "reconstruct repository history", "find hidden files",
             "decode base64 encoded data", "identify the modulus",
             "perform integer factorization"],
            # Short but relevant to RSA
            ["identify weak RSA parameters", "factor the modulus",
             "compute private key", "decrypt the ciphertext"],
        ]
        context = {"rsa", "modulus", "factor", "exponent", "prime",
                   "decrypt", "sage", "pycryptodome"}
        steps, is_consensus = _merge_solve_steps(data, context_keywords=context)
        assert is_consensus is False
        # Should pick the RSA-relevant list, not the longer git list
        assert any("rsa" in s.lower() for s in steps)
        assert not any("git" in s.lower() for s in steps)

    def test_falls_back_to_longest_without_context(self):
        """Without context_keywords, longest list wins (backward compat)."""
        data = [
            ["short step"],
            ["longer step one", "longer step two", "longer step three"],
        ]
        steps, _ = _merge_solve_steps(data)
        assert len(steps) == 3

    def test_falls_back_to_longest_when_all_score_zero(self):
        """When no step list overlaps with context, pick longest."""
        data = [
            ["alpha procedure"],
            ["beta procedure one", "beta procedure two", "beta procedure three"],
        ]
        context = {"completely", "unrelated", "keywords"}
        steps, _ = _merge_solve_steps(data, context_keywords=context)
        assert len(steps) == 3  # longest list

    def test_tiebreak_prefers_longer(self):
        """Equal keyword scores should tie-break on list length."""
        data = [
            ["exploit the buffer overflow"],
            ["exploit the buffer overflow", "escalate privileges"],
        ]
        context = {"buffer", "overflow", "exploit"}
        steps, _ = _merge_solve_steps(data, context_keywords=context)
        assert len(steps) == 2  # longer list wins the tie


# ── _dedup_step_strings ─────────────────────────────────────────────────


class TestDedupStepStrings:
    def test_empty(self):
        assert _dedup_step_strings([]) == {}

    def test_no_duplicates(self):
        steps = ["find the bug", "write the exploit", "get the flag"]
        result = _dedup_step_strings(steps)
        assert len(set(result.values())) == 3

    def test_exact_case_merge(self):
        steps = ["Find the buffer overflow", "find the buffer overflow"]
        result = _dedup_step_strings(steps)
        assert result[steps[0]] == result[steps[1]]

    def test_substring_absorption(self):
        steps = [
            "load binary into disassembler",
            "load binary into disassembler/decompiler",
        ]
        result = _dedup_step_strings(steps)
        # Both should map to the shorter canonical form
        assert result[steps[0]] == result[steps[1]]

    def test_fuzzy_merge(self):
        steps = [
            "load binary into a disassembler or decompiler",
            "Load the binary into a disassembler or decompiler",
        ]
        result = _dedup_step_strings(steps)
        assert result[steps[0]] == result[steps[1]]

    def test_no_false_merge(self):
        steps = [
            "analyze the binary for vulnerabilities",
            "patch the binary with new values",
        ]
        result = _dedup_step_strings(steps)
        assert result[steps[0]] != result[steps[1]]

    def test_prefers_shorter_canonical(self):
        steps = [
            "load binary into disassembler/decompiler",
            "load binary into disassembler",
        ]
        result = _dedup_step_strings(steps)
        canonical = result[steps[0]]
        assert len(canonical) <= len(steps[0])


# ── _serialize_technique ─────────────────────────────────────────────────


def _make_bucket(recognition=None, tools=None, steps=None,
                 difficulties=None, examples=None):
    """Create a data bucket for testing."""
    bucket = {
        "recognition": defaultdict(int, recognition or {}),
        "tools": defaultdict(int, tools or {}),
        "steps": steps or [],
        "difficulties": defaultdict(int, difficulties or {}),
        "examples": examples or [],
    }
    return bucket


class TestSerializeTechnique:
    def test_basic(self):
        data = _make_bucket(
            recognition={"gets() call": 3, "no canary": 2},
            tools={"gdb": 5, "pwntools": 3},
            steps=[["find overflow", "exploit"]],
            difficulties={"medium": 2, "easy": 1},
            examples=[{
                "challenge": "pwn101", "event": "picoCTF",
                "year": 2024, "url": "https://x.com",
                "summary": "buffer overflow", "difficulty": "easy",
            }],
        )
        result = _serialize_technique("buffer-overflow", data)

        assert result["difficulty"] == "medium"
        assert result["example_count"] == 1
        assert result["recognition_signals"][0]["signal"] == "gets() call"
        assert result["recognition_signals"][0]["count"] == 3
        assert result["tools"][0]["tool"] == "gdb"
        assert result["solve_steps"] == ["find overflow", "exploit"]
        assert result["examples"][0]["challenge"] == "pwn101"
        assert "sub_techniques" not in result

    def test_with_sub_techniques(self):
        parent = _make_bucket(
            recognition={"RSA challenge": 5},
            tools={"sage": 4},
            steps=[["extract key", "attack"]],
            difficulties={"hard": 3},
            examples=[{
                "challenge": "rsa1", "event": "CTF",
                "year": 2024, "url": "https://x.com",
                "summary": "", "difficulty": "hard",
            }],
        )
        sub = {
            "wiener": _make_bucket(
                recognition={"large e": 2},
                tools={"python": 2},
                steps=[["continued fraction"]],
                difficulties={"medium": 1},
                examples=[{
                    "challenge": "rsa1", "event": "CTF",
                    "year": 2024, "url": "https://x.com",
                    "summary": "", "difficulty": "medium",
                }],
            ),
        }
        result = _serialize_technique("rsa-attacks", parent, sub)

        assert "sub_techniques" in result
        assert "wiener" in result["sub_techniques"]
        wiener = result["sub_techniques"]["wiener"]
        assert wiener["recognition_signals"][0]["signal"] == "large e"

    def test_empty_bucket(self):
        data = _make_bucket()
        result = _serialize_technique("empty", data)
        assert result["difficulty"] == "medium"  # default
        assert result["example_count"] == 0
        assert result["recognition_signals"] == []
        assert result["tools"] == []
        assert result["solve_steps"] == []

    def test_examples_sorted_by_year_desc(self):
        data = _make_bucket(examples=[
            {"challenge": "old", "event": "A", "year": 2020,
             "url": "x", "summary": "", "difficulty": "easy"},
            {"challenge": "new", "event": "B", "year": 2025,
             "url": "y", "summary": "", "difficulty": "hard"},
            {"challenge": "mid", "event": "C", "year": 2023,
             "url": "z", "summary": "", "difficulty": "medium"},
        ])
        result = _serialize_technique("test", data)
        years = [e["year"] for e in result["examples"]]
        assert years == [2025, 2023, 2020]

    def test_is_json_serializable(self):
        data = _make_bucket(
            recognition={"signal": 2},
            tools={"gdb": 1},
            steps=[["step1"]],
            difficulties={"easy": 1},
            examples=[{
                "challenge": "c", "event": "e", "year": 2024,
                "url": "u", "summary": "s", "difficulty": "easy",
            }],
        )
        result = _serialize_technique("test", data)
        # Should not raise — no defaultdicts, sets, or other non-serializable types
        text = json.dumps(result)
        roundtrip = json.loads(text)
        assert roundtrip["solve_steps"] == ["step1"]


# ── _assemble_recon_patterns ─────────────────────────────────────────────


class TestAssembleReconPatterns:
    def test_groups_by_category(self):
        techniques = {
            "buffer-overflow": {
                "category": "binary-exploitation",
                "recognition_signals": [
                    {"signal": "gets() call", "count": 5},
                    {"signal": "no canary", "count": 3},
                ],
            },
            "xss": {
                "category": "web",
                "recognition_signals": [
                    {"signal": "reflected input", "count": 4},
                ],
            },
        }
        result = _assemble_recon_patterns(techniques)
        assert "binary-exploitation" in result
        assert "web" in result
        assert "buffer-overflow" in result["binary-exploitation"]["techniques"]
        assert result["web"]["techniques"]["xss"] == ["reflected input"]

    def test_skips_techniques_without_signals(self):
        techniques = {
            "unknown-tech": {
                "category": "misc",
                "recognition_signals": [],
            },
        }
        result = _assemble_recon_patterns(techniques)
        assert result == {}

    def test_caps_at_five_signals(self):
        techniques = {
            "test": {
                "category": "web",
                "recognition_signals": [
                    {"signal": f"sig{i}", "count": 10 - i} for i in range(8)
                ],
            },
        }
        result = _assemble_recon_patterns(techniques)
        assert len(result["web"]["techniques"]["test"]) == 5


# ── _assemble_tool_reference ─────────────────────────────────────────────


class TestAssembleToolReference:
    def test_aggregates_across_techniques(self):
        techniques = {
            "buffer-overflow": {
                "tools": [
                    {"tool": "gdb", "count": 5},
                    {"tool": "pwntools", "count": 3},
                ],
            },
            "heap-exploitation": {
                "tools": [
                    {"tool": "gdb", "count": 4},
                    {"tool": "one_gadget", "count": 2},
                ],
            },
        }
        result = _assemble_tool_reference(techniques)
        gdb = next(t for t in result if t["tool"] == "gdb")
        assert gdb["count"] == 9
        assert set(gdb["techniques"]) == {"buffer-overflow", "heap-exploitation"}

    def test_sorted_by_count_desc(self):
        techniques = {
            "t": {
                "tools": [
                    {"tool": "rare", "count": 1},
                    {"tool": "common", "count": 10},
                    {"tool": "mid", "count": 5},
                ],
            },
        }
        result = _assemble_tool_reference(techniques)
        tools = [t["tool"] for t in result]
        assert tools == ["common", "mid", "rare"]

    def test_caps_at_thirty(self):
        techniques = {
            "t": {
                "tools": [{"tool": f"tool{i}", "count": i} for i in range(50)],
            },
        }
        result = _assemble_tool_reference(techniques)
        assert len(result) <= 30


# ── _assemble_cross_references ────────────────────────────────────────────


class TestAssembleCrossReferences:
    def _setup_db(self, tmp_path, writeups):
        """Create a temp DB with classified writeups and return a connection."""
        import sqlite3
        db = tmp_path / "test.db"
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        conn.execute("""
            CREATE TABLE writeups (
                id INTEGER PRIMARY KEY, class_status TEXT, techniques TEXT
            )
        """)
        for i, techs in enumerate(writeups):
            conn.execute(
                "INSERT INTO writeups (id, class_status, techniques) VALUES (?, 'classified', ?)",
                (i + 1, json.dumps(techs)),
            )
        conn.commit()
        return conn

    def test_basic_co_occurrence(self, tmp_path):
        conn = self._setup_db(tmp_path, [
            ["buffer-overflow", "rop-chains"],
            ["buffer-overflow", "rop-chains"],
            ["buffer-overflow", "format-string"],
            ["buffer-overflow", "format-string"],
        ])
        result = _assemble_cross_references(conn, min_count=2)
        assert "buffer-overflow" in result
        bo_refs = {x["technique"]: x["count"] for x in result["buffer-overflow"]}
        assert bo_refs["rop-chains"] == 2
        assert bo_refs["format-string"] == 2
        # Reverse direction
        assert "rop-chains" in result
        assert result["rop-chains"][0]["technique"] == "buffer-overflow"
        conn.close()

    def test_below_threshold_excluded(self, tmp_path):
        conn = self._setup_db(tmp_path, [
            ["xss", "ssrf"],  # only 1 co-occurrence
        ])
        result = _assemble_cross_references(conn, min_count=2)
        assert result == {}
        conn.close()

    def test_sorted_by_count(self, tmp_path):
        conn = self._setup_db(tmp_path, [
            ["a", "b"], ["a", "b"], ["a", "b"],  # a-b: 3
            ["a", "c"], ["a", "c"],               # a-c: 2
        ])
        result = _assemble_cross_references(conn, min_count=2)
        a_refs = result["a"]
        assert a_refs[0]["technique"] == "b"
        assert a_refs[0]["count"] == 3
        assert a_refs[1]["technique"] == "c"
        conn.close()

    def test_caps_at_five(self, tmp_path):
        # Create 7 different co-occurring pairs with "target"
        writeups = []
        for i in range(7):
            for _ in range(2):  # each pair appears 2x
                writeups.append(["target", f"tech-{i}"])
        conn = self._setup_db(tmp_path, writeups)
        result = _assemble_cross_references(conn, min_count=2)
        assert len(result["target"]) == 5
        conn.close()

    def test_deduplicates_within_writeup(self, tmp_path):
        conn = self._setup_db(tmp_path, [
            ["a", "a", "b"],  # duplicate "a" should be deduplicated
            ["a", "b"],
        ])
        result = _assemble_cross_references(conn, min_count=2)
        assert result["a"][0]["count"] == 2
        conn.close()


# ── _render_pattern_content ──────────────────────────────────────────────


class TestRenderPatternContent:
    def test_basic_structure(self):
        tech = {
            "difficulty": "medium",
            "example_count": 2,
            "recognition_signals": [{"signal": "test signal", "count": 3}],
            "tools": [{"tool": "gdb", "count": 5}],
            "solve_steps": ["step one", "step two"],
            "examples": [{
                "challenge": "pwn101", "event": "picoCTF", "year": 2024,
                "url": "https://example.com", "summary": "A buffer overflow",
                "difficulty": "easy",
            }],
        }
        md = _render_pattern_content("buffer-overflow", tech)
        assert "# Buffer Overflow" in md
        assert "test signal (seen 3x)" in md
        assert "**gdb** (used 5x)" in md
        assert "1. step one" in md
        assert "2. step two" in md
        assert "**pwn101**" in md

    def test_renders_cross_references(self):
        tech = {
            "difficulty": "medium",
            "example_count": 1,
            "recognition_signals": [],
            "tools": [],
            "solve_steps": [],
            "cross_references": [
                {"technique": "rop-chains", "count": 5},
                {"technique": "format-string", "count": 3},
            ],
            "examples": [],
        }
        md = _render_pattern_content("buffer-overflow", tech)
        assert "## See Also" in md
        assert "Rop Chains" in md
        assert "seen together 5x" in md
        assert "Format String" in md

    def test_no_see_also_without_xrefs(self):
        tech = {
            "difficulty": "easy",
            "example_count": 0,
            "recognition_signals": [],
            "tools": [],
            "solve_steps": [],
            "cross_references": [],
            "examples": [],
        }
        md = _render_pattern_content("test", tech)
        assert "See Also" not in md

    def test_caps_examples_at_ten(self):
        tech = {
            "difficulty": "easy",
            "example_count": 15,
            "recognition_signals": [],
            "tools": [],
            "solve_steps": [],
            "examples": [
                {"challenge": f"c{i}", "event": "e", "year": 2024,
                 "url": f"https://x.com/{i}", "summary": "", "difficulty": "easy"}
                for i in range(15)
            ],
        }
        md = _render_pattern_content("test", tech)
        # Count challenge references — should be capped at 10
        assert md.count("**c") == 10


# ── _render_recon_trees ──────────────────────────────────────────────────


class TestRenderReconTrees:
    def test_generates_recon_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "ctf_playbook.services.builder.TECHNIQUES_DIR", tmp_path
        )
        techniques = {
            "rsa-attacks": {
                "category": "crypto",
                "sub_techniques": {
                    "wiener": {
                        "example_count": 3,
                        "recognition_signals": [
                            {"signal": "large public exponent e", "count": 3},
                        ],
                    },
                    "coppersmith": {
                        "example_count": 5,
                        "recognition_signals": [
                            {"signal": "partial plaintext known", "count": 4},
                        ],
                    },
                },
            },
        }
        _render_recon_trees(techniques)
        recon = tmp_path / "crypto" / "rsa-attacks" / "_recon.md"
        assert recon.exists()
        content = recon.read_text(encoding="utf-8")
        assert "Decision Tree" in content
        # Coppersmith first (5 writeups > 3)
        assert content.index("Coppersmith") < content.index("Wiener")
        assert "large public exponent e" in content
        assert "partial plaintext known" in content
        assert "→ [Wiener](wiener.md)" in content

    def test_skips_single_sub_technique(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "ctf_playbook.services.builder.TECHNIQUES_DIR", tmp_path
        )
        techniques = {
            "xss": {
                "category": "web",
                "sub_techniques": {
                    "dom-xss": {
                        "example_count": 2,
                        "recognition_signals": [],
                    },
                },
            },
        }
        _render_recon_trees(techniques)
        recon = tmp_path / "web" / "xss" / "_recon.md"
        assert not recon.exists()

    def test_skips_no_sub_techniques(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "ctf_playbook.services.builder.TECHNIQUES_DIR", tmp_path
        )
        techniques = {
            "ssrf": {"category": "web"},
        }
        _render_recon_trees(techniques)
        assert not (tmp_path / "web" / "ssrf" / "_recon.md").exists()

    def test_handles_empty_signals(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "ctf_playbook.services.builder.TECHNIQUES_DIR", tmp_path
        )
        techniques = {
            "test": {
                "category": "misc",
                "sub_techniques": {
                    "sub-a": {"example_count": 1, "recognition_signals": []},
                    "sub-b": {"example_count": 1, "recognition_signals": []},
                },
            },
        }
        _render_recon_trees(techniques)
        content = (tmp_path / "misc" / "test" / "_recon.md").read_text(
            encoding="utf-8"
        )
        assert "no distinguishing signals yet" in content


# ── _normalize_signal ──────────────────────────────────────────────────


class TestNormalizeSignal:
    def test_lowercase(self):
        assert _normalize_signal("RSA With Unusual Parameters") == "rsa with unusual parameters"

    def test_strip_whitespace(self):
        assert _normalize_signal("  some signal  ") == "some signal"

    def test_strip_trailing_punctuation(self):
        assert _normalize_signal("signal with period.") == "signal with period"
        assert _normalize_signal("signal;") == "signal"

    def test_collapse_internal_whitespace(self):
        assert _normalize_signal("multiple   spaces   here") == "multiple spaces here"

    def test_empty_string(self):
        assert _normalize_signal("") == ""
        assert _normalize_signal("   ") == ""


# ── _merge_signals ─────────────────────────────────────────────────────


class TestMergeSignals:
    def test_case_insensitive_merge(self):
        raw = {"RSA with unusual parameters": 1, "rsa with unusual parameters": 1}
        result = _merge_signals(raw)
        assert len(result) == 1
        assert sum(result.values()) == 2

    def test_whitespace_and_punctuation_merge(self):
        raw = {"input reflected in page.": 1, "  input reflected in page  ": 1}
        result = _merge_signals(raw)
        assert len(result) == 1
        assert sum(result.values()) == 2

    def test_substring_absorption(self):
        raw = {"APK file": 1, "APK file provided": 1, "Android APK file format": 1}
        result = _merge_signals(raw)
        assert len(result) == 1
        assert sum(result.values()) == 3

    def test_fuzzy_merge(self):
        raw = {
            "user input passed directly to printf()": 1,
            "user input passed directly to printf": 1,
        }
        result = _merge_signals(raw)
        assert len(result) == 1
        assert sum(result.values()) == 2

    def test_no_false_fuzzy_merge(self):
        raw = {
            "cryptographic algorithm with unknown parameters": 1,
            "cryptographic algorithm with reversible operations": 1,
        }
        result = _merge_signals(raw)
        assert len(result) == 2

    def test_canonical_prefers_shorter(self):
        raw = {
            "APK file provided for analysis": 2,
            "APK file": 1,
        }
        result = _merge_signals(raw)
        assert "APK file" in result

    def test_empty_signals(self):
        assert _merge_signals({}) == {}

    def test_single_signal(self):
        raw = {"only one signal": 5}
        result = _merge_signals(raw)
        assert result == {"only one signal": 5}

    def test_combined_counts(self):
        raw = {
            "RSA challenge": 3,
            "rsa challenge.": 2,
            "An RSA challenge problem": 1,
        }
        result = _merge_signals(raw)
        assert len(result) == 1
        assert sum(result.values()) == 6


# ── _merge_tools ───────────────────────────────────────────────────────


class TestMergeTools:
    def test_case_merge(self):
        raw = {"wireshark": 3, "Wireshark": 5}
        result = _merge_tools(raw)
        assert len(result) == 1
        assert sum(result.values()) == 8
        # Should keep "Wireshark" (higher count) as canonical
        assert "Wireshark" in result

    def test_no_false_merge(self):
        raw = {"gdb": 5, "pwndbg": 3}
        result = _merge_tools(raw)
        assert len(result) == 2

    def test_empty(self):
        assert _merge_tools({}) == {}

    def test_whitespace_normalization(self):
        raw = {"  gdb ": 2, "gdb": 3}
        result = _merge_tools(raw)
        assert len(result) == 1
        assert sum(result.values()) == 5
