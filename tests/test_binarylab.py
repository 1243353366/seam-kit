"""The harness must be able to fail, and this is where that is proven."""
from __future__ import annotations

import shutil
import unittest

from lab import binarylab


@unittest.skipIf(shutil.which("cc") is None, "no C compiler available")
class DifferentialTests(unittest.TestCase):
    def test_the_reference_and_the_clean_build_agree(self):
        result = binarylab.investigate("scorer.c")
        self.assertTrue(result["agrees_with_reference"], result["divergences"][:2])
        self.assertEqual(result["divergences"], [])

    def test_a_deliberate_bug_is_caught(self):
        result = binarylab.investigate("scorer_bug.c")
        self.assertFalse(result["agrees_with_reference"])
        self.assertGreaterEqual(len(result["divergences"]), 1)

    def test_the_reference_is_written_from_the_specification(self):
        self.assertEqual(binarylab.reference_total([1, 3]), 7)
        self.assertEqual(binarylab.reference_verdict([1, 3]), "tamper")
        self.assertEqual(binarylab.reference_verdict([3, 1]), "clean")

    def test_structural_facts_come_with_their_own_limits(self):
        facts = binarylab.investigate("scorer.c")["static"]
        self.assertIn("limits", facts)
        self.assertTrue(any("strip" in line for line in facts["limits"]))


if __name__ == "__main__":
    unittest.main()
