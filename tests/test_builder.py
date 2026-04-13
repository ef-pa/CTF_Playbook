"""Tests for the playbook builder."""

from ctf_playbook.services.builder import _merge_solve_steps


class TestMergeSolveSteps:
    def test_empty(self):
        assert _merge_solve_steps([]) == []

    def test_single_writeup(self):
        steps = [["find vuln", "exploit", "get flag"]]
        assert _merge_solve_steps(steps) == ["find vuln", "exploit", "get flag"]

    def test_single_writeup_truncates(self):
        long_steps = [["step"] * 10]
        result = _merge_solve_steps(long_steps, max_steps=5)
        assert len(result) == 5

    def test_consensus_preferred(self):
        """Steps appearing in 2+ writeups should be selected over unique steps."""
        steps = [
            ["find vuln", "calculate offset", "build exploit", "get flag"],
            ["find vuln", "calculate offset", "craft payload", "get flag"],
            ["find vuln", "calculate offset", "write exploit", "get flag"],
        ]
        result = _merge_solve_steps(steps)
        # "find vuln", "calculate offset", and "get flag" appear in all 3
        assert "find vuln" in result
        assert "calculate offset" in result
        assert "get flag" in result

    def test_consensus_ordered_by_position(self):
        """Consensus steps should be ordered by their average position."""
        steps = [
            ["step A", "step B", "step C"],
            ["step A", "step B", "step C"],
        ]
        result = _merge_solve_steps(steps)
        assert result == ["step A", "step B", "step C"]

    def test_falls_back_to_longest_when_no_consensus(self):
        """When no step appears in 2+ writeups, use the longest list."""
        steps = [
            ["unique-a1", "unique-a2"],
            ["unique-b1", "unique-b2", "unique-b3", "unique-b4"],
            ["unique-c1"],
        ]
        result = _merge_solve_steps(steps)
        assert result == ["unique-b1", "unique-b2", "unique-b3", "unique-b4"]

    def test_case_insensitive_dedup(self):
        """Matching should be case-insensitive."""
        steps = [
            ["Find vulnerability", "Exploit"],
            ["find vulnerability", "exploit"],
            ["FIND VULNERABILITY", "EXPLOIT"],
        ]
        result = _merge_solve_steps(steps)
        assert len(result) == 2

    def test_max_steps_caps_consensus(self):
        """Consensus output should be capped at max_steps."""
        common = [f"step {i}" for i in range(10)]
        steps = [common, common, common]
        result = _merge_solve_steps(steps, max_steps=5)
        assert len(result) == 5

    def test_two_writeups_partial_overlap(self):
        """Two writeups with some shared steps and some unique."""
        steps = [
            ["decompile binary", "find overflow", "write exploit"],
            ["checksec binary", "find overflow", "build rop chain", "write exploit"],
        ]
        result = _merge_solve_steps(steps)
        # "find overflow" and "write exploit" appear twice = consensus
        # Only 2 consensus steps < 3, so falls back to longest
        assert len(result) == 4  # longest list has 4 steps
