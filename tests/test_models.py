"""Tests for data models."""

from ctf_playbook.models import TechniqueMatch, ClassificationResult


class TestTechniqueMatch:
    def test_from_dict_string(self):
        tm = TechniqueMatch.from_dict("buffer-overflow")
        assert tm.technique == "buffer-overflow"
        assert tm.sub_technique is None
        assert tm.recognition_signals == []
        assert tm.solve_steps == []

    def test_from_dict_minimal(self):
        tm = TechniqueMatch.from_dict({"technique": "xss"})
        assert tm.technique == "xss"
        assert tm.recognition_signals == []
        assert tm.sub_recognition_signals == []

    def test_from_dict_full(self):
        tm = TechniqueMatch.from_dict({
            "technique": "rsa-attacks",
            "sub_technique": "wiener",
            "recognition_signals": ["RSA with unusual params"],
            "solve_steps": ["extract key", "apply attack"],
            "sub_recognition_signals": ["very large e"],
            "sub_solve_steps": ["continued fraction expansion"],
        })
        assert tm.technique == "rsa-attacks"
        assert tm.sub_technique == "wiener"
        assert tm.recognition_signals == ["RSA with unusual params"]
        assert tm.solve_steps == ["extract key", "apply attack"]
        assert tm.sub_recognition_signals == ["very large e"]
        assert tm.sub_solve_steps == ["continued fraction expansion"]

    def test_from_dict_normalizes_bare_string(self):
        """A bare string value for a list field gets wrapped in a list."""
        tm = TechniqueMatch.from_dict({
            "technique": "xss",
            "recognition_signals": "reflected input",
        })
        assert tm.recognition_signals == ["reflected input"]

    def test_to_dict_minimal(self):
        tm = TechniqueMatch("buffer-overflow")
        d = tm.to_dict()
        assert d == {"technique": "buffer-overflow"}

    def test_to_dict_full(self):
        tm = TechniqueMatch(
            technique="rsa-attacks",
            sub_technique="wiener",
            recognition_signals=["sig1"],
            solve_steps=["step1"],
            sub_recognition_signals=["sub_sig1"],
            sub_solve_steps=["sub_step1"],
        )
        d = tm.to_dict()
        assert d["technique"] == "rsa-attacks"
        assert d["sub_technique"] == "wiener"
        assert d["recognition_signals"] == ["sig1"]
        assert d["sub_recognition_signals"] == ["sub_sig1"]

    def test_to_dict_omits_empty(self):
        tm = TechniqueMatch("xss", sub_technique="reflected-xss")
        d = tm.to_dict()
        assert "recognition_signals" not in d
        assert "solve_steps" not in d
        assert "sub_recognition_signals" not in d


class TestClassificationResult:
    def _make_result(self, techniques, recognition_signals=None, solve_steps=None):
        return ClassificationResult(
            techniques=techniques,
            tools_used=["gdb"],
            solve_steps=solve_steps or [],
            recognition_signals=recognition_signals or [],
            difficulty="medium",
            summary="test",
        )

    def test_technique_slugs(self):
        r = self._make_result([
            TechniqueMatch("rsa-attacks", "wiener"),
            TechniqueMatch("buffer-overflow"),
        ])
        assert r.technique_slugs == ["rsa-attacks", "buffer-overflow"]

    def test_flat_recognition_from_techniques(self):
        r = self._make_result([
            TechniqueMatch("xss", recognition_signals=["input reflected"]),
            TechniqueMatch("ssrf", recognition_signals=["internal URL"]),
        ])
        assert r.flat_recognition == ["input reflected", "internal URL"]

    def test_flat_recognition_deduplicates(self):
        r = self._make_result([
            TechniqueMatch("xss", recognition_signals=["same signal"]),
            TechniqueMatch("ssrf", recognition_signals=["same signal"]),
        ])
        assert r.flat_recognition == ["same signal"]

    def test_flat_recognition_falls_back_to_top_level(self):
        r = self._make_result(
            [TechniqueMatch("buffer-overflow")],
            recognition_signals=["gets() call"],
        )
        assert r.flat_recognition == ["gets() call"]

    def test_flat_solve_steps_from_techniques(self):
        r = self._make_result([
            TechniqueMatch("xss", solve_steps=["find injection", "craft payload"]),
        ])
        assert r.flat_solve_steps == ["find injection", "craft payload"]

    def test_flat_solve_steps_falls_back_to_top_level(self):
        r = self._make_result(
            [TechniqueMatch("buffer-overflow")],
            solve_steps=["find vuln", "exploit"],
        )
        assert r.flat_solve_steps == ["find vuln", "exploit"]
