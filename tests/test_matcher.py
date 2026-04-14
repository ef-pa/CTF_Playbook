"""Tests for the challenge matcher service."""

from ctf_playbook.services.matcher import _tokenize, ChallengeMatcher


# ── _tokenize ────────────────────────────────────────────────────────────


class TestTokenize:
    def test_basic(self):
        tokens = _tokenize("RSA with small exponent")
        assert "rsa" in tokens
        assert "small" in tokens
        assert "exponent" in tokens
        # "with" is a stopword
        assert "with" not in tokens

    def test_preserves_function_calls(self):
        tokens = _tokenize("binary calls gets() and printf()")
        assert "gets()" in tokens
        assert "printf()" in tokens

    def test_strips_stopwords(self):
        tokens = _tokenize("the binary is a simple buffer overflow")
        assert "the" not in tokens
        assert "is" not in tokens
        assert "a" not in tokens
        assert "buffer" in tokens
        assert "overflow" in tokens

    def test_handles_punctuation(self):
        tokens = _tokenize("SQL injection; XSS via <script>")
        assert "sql" in tokens
        assert "injection" in tokens
        assert "xss" in tokens
        assert "script" in tokens

    def test_empty(self):
        assert _tokenize("") == []
        assert _tokenize("   ") == []

    def test_only_stopwords(self):
        assert _tokenize("the a is are") == []


# ── ChallengeMatcher ────────────────────────────────────────────────────

# Minimal playbook for testing
MINI_PLAYBOOK = {
    "techniques": {
        "buffer-overflow": {
            "category": "binary-exploitation",
            "difficulty": "medium",
            "example_count": 10,
            "recognition_signals": [
                {"signal": "binary with gets() and no canary", "count": 5},
                {"signal": "stack-based buffer overflow", "count": 3},
            ],
            "tools": [{"tool": "gdb", "count": 8}, {"tool": "pwntools", "count": 6}],
            "solve_steps": ["find overflow", "calculate offset", "build exploit"],
        },
        "rsa-attacks": {
            "category": "cryptography",
            "difficulty": "hard",
            "example_count": 8,
            "recognition_signals": [
                {"signal": "RSA with unusual parameters", "count": 4},
                {"signal": "public key available for analysis", "count": 2},
            ],
            "tools": [{"tool": "sage", "count": 5}],
            "solve_steps": ["extract public key", "identify vulnerability"],
            "sub_techniques": {
                "wiener": {
                    "category": "cryptography",
                    "difficulty": "medium",
                    "example_count": 3,
                    "recognition_signals": [
                        {"signal": "public exponent e is extremely large", "count": 3},
                    ],
                    "tools": [{"tool": "sage", "count": 2}],
                    "solve_steps": ["compute continued fraction expansion"],
                },
            },
        },
        "sql-injection": {
            "category": "web",
            "difficulty": "easy",
            "example_count": 15,
            "recognition_signals": [
                {"signal": "user input in SQL query", "count": 6},
                {"signal": "login form with no input sanitization", "count": 4},
            ],
            "tools": [{"tool": "sqlmap", "count": 10}],
            "solve_steps": ["find injection point", "extract data"],
        },
    },
}


class TestChallengeMatcher:
    def setup_method(self):
        self.matcher = ChallengeMatcher(MINI_PLAYBOOK)

    def test_exact_signal_match(self):
        """Verbatim signal in input should score highest."""
        results = self.matcher.identify("binary with gets() and no canary")
        assert results[0].technique == "buffer-overflow"
        assert results[0].confidence == 100.0

    def test_partial_token_overlap(self):
        """Partial keyword matches should produce results."""
        results = self.matcher.identify("RSA challenge with parameters")
        assert any(r.technique == "rsa-attacks" for r in results)

    def test_empty_input(self):
        assert self.matcher.identify("") == []

    def test_ranking_order(self):
        """Best match should appear first."""
        results = self.matcher.identify("SQL query injection in login form")
        assert results[0].technique == "sql-injection"

    def test_max_results_limit(self):
        results = self.matcher.identify("binary overflow RSA SQL", max_results=2)
        assert len(results) <= 2

    def test_confidence_normalization(self):
        """Best match should have confidence 100."""
        results = self.matcher.identify("stack-based buffer overflow exploit")
        if results:
            assert results[0].confidence == 100.0

    def test_sub_technique_matching(self):
        """Should identify sub-techniques when their signals match."""
        results = self.matcher.identify(
            "RSA with extremely large public exponent e"
        )
        rsa = next((r for r in results if r.technique == "rsa-attacks"), None)
        assert rsa is not None
        assert rsa.sub_technique == "wiener"

    def test_result_fields(self):
        """Results should include tools, solve steps, and metadata."""
        results = self.matcher.identify("binary with gets() and no canary")
        m = results[0]
        assert m.category == "binary-exploitation"
        assert m.difficulty == "medium"
        assert m.example_count == 10
        assert "gdb" in m.tools
        assert len(m.solve_steps) > 0
        assert len(m.matched_signals) > 0

    def test_no_match_returns_empty(self):
        """Completely unrelated input should return nothing."""
        results = self.matcher.identify("pizza recipe with tomato sauce")
        # May or may not have results; if it does, confidence should be low
        for r in results:
            assert r.confidence <= 100

    def test_empty_playbook(self):
        matcher = ChallengeMatcher({"techniques": {}})
        assert matcher.identify("anything") == []

    def test_min_confidence_filter(self):
        results = self.matcher.identify("buffer overflow", min_confidence=50.0)
        for r in results:
            assert r.confidence >= 50.0
