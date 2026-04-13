"""Tests for configuration and taxonomy."""

from ctf_playbook.taxonomy import (
    TAXONOMY, TECHNIQUE_TO_CATEGORY, SUB_TECHNIQUE_TO_TECHNIQUE,
    get_category, get_techniques, get_technique_info,
    get_sub_techniques, get_parent_technique,
    all_slugs, all_sub_slugs, categories,
    infer_category_from_slug, _CATEGORY_KEYWORDS,
)


class TestTaxonomy:
    def test_has_required_categories(self):
        expected = {"binary-exploitation", "web", "cryptography",
                    "reverse-engineering", "forensics", "misc"}
        assert expected == set(TAXONOMY.keys())

    def test_categories_have_descriptions(self):
        for cat, info in TAXONOMY.items():
            assert "description" in info, f"{cat} missing description"
            assert isinstance(info["description"], str)
            assert len(info["description"]) > 0

    def test_categories_have_techniques(self):
        for cat, info in TAXONOMY.items():
            assert "techniques" in info, f"{cat} missing techniques"
            assert isinstance(info["techniques"], dict)
            assert len(info["techniques"]) > 0

    def test_technique_slugs_are_valid(self):
        """Technique slugs should be lowercase, hyphenated, no spaces."""
        for cat, info in TAXONOMY.items():
            for tech in info["techniques"]:
                assert tech == tech.lower(), f"{tech} not lowercase"
                assert " " not in tech, f"{tech} contains spaces"
                assert tech == tech.strip(), f"{tech} has leading/trailing whitespace"

    def test_no_duplicate_techniques(self):
        """No technique should appear in multiple categories."""
        seen = {}
        for cat, info in TAXONOMY.items():
            for tech in info["techniques"]:
                assert tech not in seen, (
                    f"'{tech}' in both '{seen[tech]}' and '{cat}'"
                )
                seen[tech] = cat

    def test_techniques_have_descriptions(self):
        for cat, info in TAXONOMY.items():
            for tech, tech_info in info["techniques"].items():
                assert "description" in tech_info, f"{tech} missing description"
                assert isinstance(tech_info["description"], str)
                assert len(tech_info["description"]) > 0


class TestTechniqueToCategory:
    def test_mapping_built(self):
        assert len(TECHNIQUE_TO_CATEGORY) > 0

    def test_every_technique_mapped(self):
        for cat, info in TAXONOMY.items():
            for tech in info["techniques"]:
                assert tech in TECHNIQUE_TO_CATEGORY
                assert TECHNIQUE_TO_CATEGORY[tech] == cat

    def test_known_mappings(self):
        assert TECHNIQUE_TO_CATEGORY["buffer-overflow"] == "binary-exploitation"
        assert TECHNIQUE_TO_CATEGORY["sql-injection"] == "web"
        assert TECHNIQUE_TO_CATEGORY["rsa-attacks"] == "cryptography"
        assert TECHNIQUE_TO_CATEGORY["static-analysis"] == "reverse-engineering"
        assert TECHNIQUE_TO_CATEGORY["file-carving"] == "forensics"
        assert TECHNIQUE_TO_CATEGORY["osint"] == "misc"


class TestSubTechniques:
    def test_sub_techniques_are_lists(self):
        for cat, info in TAXONOMY.items():
            for tech, tech_info in info["techniques"].items():
                if "sub_techniques" in tech_info:
                    assert isinstance(tech_info["sub_techniques"], list), \
                        f"{tech} sub_techniques should be a list"

    def test_sub_technique_slugs_valid(self):
        for cat, info in TAXONOMY.items():
            for tech, tech_info in info["techniques"].items():
                for sub in tech_info.get("sub_techniques", []):
                    assert sub == sub.lower(), f"{sub} not lowercase"
                    assert " " not in sub, f"{sub} contains spaces"
                    assert sub == sub.strip(), f"{sub} has whitespace"

    def test_no_duplicate_sub_techniques(self):
        """No sub-technique should appear under multiple techniques."""
        seen = {}
        for cat, info in TAXONOMY.items():
            for tech, tech_info in info["techniques"].items():
                for sub in tech_info.get("sub_techniques", []):
                    assert sub not in seen, \
                        f"'{sub}' in both '{seen[sub]}' and '{tech}'"
                    seen[sub] = tech

    def test_sub_technique_not_same_as_technique(self):
        """Sub-technique slugs shouldn't collide with technique slugs."""
        tech_slugs = all_slugs()
        for sub in all_sub_slugs():
            assert sub not in tech_slugs, \
                f"'{sub}' is both a technique and a sub-technique"

    def test_sub_technique_to_technique_mapping(self):
        assert SUB_TECHNIQUE_TO_TECHNIQUE["wiener"] == "rsa-attacks"
        assert SUB_TECHNIQUE_TO_TECHNIQUE["reflected-xss"] == "xss"
        assert SUB_TECHNIQUE_TO_TECHNIQUE["tcache-poisoning"] == "heap-exploitation"
        assert SUB_TECHNIQUE_TO_TECHNIQUE["lsb-steganography"] == "steganography"
        assert SUB_TECHNIQUE_TO_TECHNIQUE["union-based"] == "sql-injection"

    def test_get_sub_techniques(self):
        subs = get_sub_techniques("rsa-attacks")
        assert "wiener" in subs
        assert "coppersmith" in subs
        assert "factoring" in subs

    def test_get_sub_techniques_empty(self):
        assert get_sub_techniques("buffer-overflow") == []
        assert get_sub_techniques("osint") == []

    def test_get_sub_techniques_unknown(self):
        assert get_sub_techniques("nonexistent") == []

    def test_get_parent_technique(self):
        assert get_parent_technique("wiener") == "rsa-attacks"
        assert get_parent_technique("dom-xss") == "xss"
        assert get_parent_technique("buffer-overflow") is None
        assert get_parent_technique("nonexistent") is None

    def test_all_sub_slugs(self):
        subs = all_sub_slugs()
        assert "wiener" in subs
        assert "reflected-xss" in subs
        assert "tcache-poisoning" in subs
        assert "buffer-overflow" not in subs  # technique, not sub

    def test_seeded_counts(self):
        """Verify expected number of seeded sub-techniques."""
        assert len(get_sub_techniques("rsa-attacks")) == 5
        assert len(get_sub_techniques("xss")) == 3
        assert len(get_sub_techniques("sql-injection")) == 5
        assert len(get_sub_techniques("heap-exploitation")) == 4
        assert len(get_sub_techniques("steganography")) == 3


class TestHelpers:
    def test_get_category(self):
        assert get_category("buffer-overflow") == "binary-exploitation"
        assert get_category("xss") == "web"
        assert get_category("nonexistent") is None

    def test_get_techniques(self):
        techs = get_techniques("web")
        assert "xss" in techs
        assert "sql-injection" in techs
        assert get_techniques("nonexistent") == []

    def test_get_technique_info(self):
        info = get_technique_info("xss")
        assert info is not None
        assert info["description"] == "Cross-site scripting attacks"
        assert "reflected-xss" in info["sub_techniques"]

    def test_get_technique_info_no_subs(self):
        info = get_technique_info("buffer-overflow")
        assert info is not None
        assert "sub_techniques" not in info

    def test_get_technique_info_unknown(self):
        assert get_technique_info("nonexistent") is None

    def test_all_slugs(self):
        slugs = all_slugs()
        assert "buffer-overflow" in slugs
        assert "xss" in slugs
        assert "wiener" not in slugs  # sub-technique, not technique

    def test_categories(self):
        cats = categories()
        assert "web" in cats
        assert "misc" in cats
        assert len(cats) == 6


class TestInferCategoryFromSlug:
    """Tests for keyword-based category inference."""

    def test_category_name_as_slug(self):
        """Slugs that are literally category names get mapped correctly."""
        assert infer_category_from_slug("cryptography") == "cryptography"
        assert infer_category_from_slug("reverse-engineering") == "reverse-engineering"
        assert infer_category_from_slug("web") == "web"

    def test_web_techniques(self):
        assert infer_category_from_slug("css-injection") == "web"
        assert infer_category_from_slug("web-shell-upload") == "web"
        assert infer_category_from_slug("file-download-xss") == "web"
        assert infer_category_from_slug("php-filter-chain") == "web"

    def test_crypto_techniques(self):
        assert infer_category_from_slug("ecdsa-nonce-reuse") == "cryptography"
        assert infer_category_from_slug("signature-forgery") == "cryptography"
        assert infer_category_from_slug("xor-key-recovery") == "cryptography"
        assert infer_category_from_slug("substitution-cipher") == "cryptography"

    def test_binary_exploitation_techniques(self):
        assert infer_category_from_slug("syscall-manipulation") == "binary-exploitation"
        assert infer_category_from_slug("pie-bypass") == "binary-exploitation"
        assert infer_category_from_slug("cet-bypass") == "binary-exploitation"

    def test_reverse_engineering_techniques(self):
        assert infer_category_from_slug("algorithm-reversal") == "reverse-engineering"
        assert infer_category_from_slug("multi-stage-unpacking") == "reverse-engineering"

    def test_forensics_techniques(self):
        assert infer_category_from_slug("audio-steganography") == "forensics"
        assert infer_category_from_slug("usb-hid-keylogger-analysis") == "forensics"

    def test_unknown_returns_none(self):
        """Completely unknown slugs return None (will go to misc)."""
        assert infer_category_from_slug("simulated-annealing") is None
        assert infer_category_from_slug("de-bruijn-sequence") is None

    def test_ambiguous_returns_none(self):
        """Ambiguous slugs (equal scores in 2+ categories) return None."""
        # "binary-patching" — "binary" is BE, "patching" is RE, tie
        assert infer_category_from_slug("binary-patching") is None

    def test_known_techniques_also_resolve(self):
        """Known taxonomy technique slugs also resolve via token matching."""
        # buffer-overflow has tokens "buffer" + "overflow" — both BE keywords
        assert infer_category_from_slug("buffer-overflow") == "binary-exploitation"
        assert infer_category_from_slug("sql-injection") == "web"

    def test_generic_tokens_pruned(self):
        """Tokens appearing in 3+ categories should be pruned from keywords."""
        # Check that the keyword sets don't contain overly generic tokens
        all_tokens = set()
        shared = set()
        for cat, tokens in _CATEGORY_KEYWORDS.items():
            for t in tokens:
                if t in all_tokens:
                    shared.add(t)
                all_tokens.add(t)
        # Any token in _CATEGORY_KEYWORDS should appear in at most 2 categories
        from collections import Counter
        counts = Counter()
        for tokens in _CATEGORY_KEYWORDS.values():
            counts.update(tokens)
        for token, count in counts.items():
            assert count <= 2, f"Token '{token}' in {count} categories (should be pruned)"

    def test_self_improving(self):
        """Keywords are derived from TAXONOMY — adding techniques would expand them."""
        # "xss" should be a web keyword (from the xss technique)
        assert "xss" in _CATEGORY_KEYWORDS["web"]
        # "rsa" should be a crypto keyword (from rsa-attacks)
        assert "rsa" in _CATEGORY_KEYWORDS["cryptography"]
        # "heap" should be a BE keyword (from heap-exploitation)
        assert "heap" in _CATEGORY_KEYWORDS["binary-exploitation"]
