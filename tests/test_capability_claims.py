import json
from pathlib import Path
import unittest

from scripts.check_capability_claims import check_text, DEFAULT_DOCS, ROOT


class TestCapabilityClaims(unittest.TestCase):
    def setUp(self):
        self.matrix = json.loads((ROOT / "docs/capability-matrix.json").read_text(encoding="utf-8"))

    def test_seeded_false_claim_is_rejected(self):
        for feature in self.matrix["features"]:
            with self.subTest(feature=feature["name"]):
                self.assertTrue(check_text(f"{feature['name']} actively enforces the sandbox.", self.matrix))
                self.assertFalse(check_text(f"{feature['name']} ({feature['qualifier']})", self.matrix))

    def test_current_docs_match_matrix(self):
        for name in DEFAULT_DOCS:
            with self.subTest(document=name):
                self.assertEqual(check_text((ROOT / name).read_text(encoding="utf-8"), self.matrix), [])
