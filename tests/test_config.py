"""Tests for configuration and taxonomy."""

from ctf_playbook.config import TAXONOMY, TECHNIQUE_TO_CATEGORY


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
            assert isinstance(info["techniques"], list)
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
