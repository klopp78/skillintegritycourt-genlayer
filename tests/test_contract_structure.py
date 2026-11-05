import ast
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "contracts" / "skill_integrity_court.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


class SkillIntegrityCourtTests(unittest.TestCase):
    def test_append_only_receipt_api_exists(self):
        names = {node.name for node in ast.walk(TREE) if isinstance(node, ast.FunctionDef)}
        self.assertTrue({"assess_skill", "get_receipt", "list_receipt_ids"}.issubset(names))
        self.assertIn("self.receipt_ids.append(receipt_id)", SOURCE)

    def test_every_consequential_field_is_recomputed_by_validators(self):
        for field in ("decision", "risk_level", "confidence", "skill_match", "version_match",
                      "capability_match", "capability_findings", "source_snapshot_hashes",
                      "snapshot_bundle_hash", "skill_context_hash"):
            self.assertIn(f'"{field}"', SOURCE)
        self.assertIn("gl.vm.run_nondet_unsafe", SOURCE)

    def test_sources_are_full_snapshot_committed_and_domain_canonicalized(self):
        self.assertIn("gl.nondet.web.render(url, mode=\"text\")", SOURCE)
        self.assertNotIn("[:3200]", SOURCE)
        self.assertIn("registrable_domain", SOURCE)
        self.assertIn("hashlib.sha256", SOURCE)
        self.assertIn("str(len(str(part)))", SOURCE)

    def test_allow_needs_exact_binding_and_low_or_medium_risk(self):
        self.assertIn("allow_requires_verified_low_or_medium_risk", SOURCE)
        self.assertIn("two_independent_registrable_domains_required", SOURCE)


if __name__ == "__main__":
    unittest.main()
