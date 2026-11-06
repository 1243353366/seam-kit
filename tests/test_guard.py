"""The guard's job is to be inspectable later, so the tests are about the record, not the filter."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from guard import ingest as guard


def _rows(path: Path, rows: list[dict]) -> str:
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    return str(path)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.key = "a-long-test-key-for-the-guard-1234"
        os.environ["SEAM_KEY"] = self.key
        self.tmp = Path(tempfile.mkdtemp(prefix="guard-"))

    def _ingest(self, rows, seed=None):
        incoming = _rows(self.tmp / "in.jsonl", rows)
        return guard.ingest(
            incoming,
            str(self.tmp / "clean.jsonl"),
            str(self.tmp / "quarantine.jsonl"),
            str(self.tmp / "manifest.jsonl"),
            seed,
        )

    def test_a_flooded_label_is_quarantined_not_deleted(self):
        # Almost the same text with one word changed each time: exact duplicates would collapse
        # to a single row before clustering ever saw them, and that is a different test.
        body = "the same passage repeated verbatim in every row number {n}"
        rows = [{"title": body.format(n=n), "label": "spam"} for n in range(4)]
        rows.append({"title": body.format(n=9), "label": "ham"})
        result = self._ingest(rows)
        self.assertEqual(result["rows"], 5)
        self.assertGreaterEqual(result["quarantined"], 1)
        kept = (self.tmp / "quarantine.jsonl").read_text(encoding="utf-8")
        self.assertIn("near-duplicates", kept)
        self.assertIn("_reason", kept)

    def test_exact_duplicates_collapse_to_one_row(self):
        row = {"title": "unique text about firmware", "label": "ok"}
        result = self._ingest([row, dict(row), dict(row)])
        self.assertEqual(result["rows"], 1)

    def test_the_manifest_detects_an_edit_after_the_fact(self):
        self._ingest([{"title": "one", "label": "ok"}, {"title": "two", "label": "ok"}])
        ok, total, bad = guard.verify(str(self.tmp / "manifest.jsonl"))
        self.assertTrue(ok)
        self.assertEqual(bad, 0)
        manifest = self.tmp / "manifest.jsonl"
        lines = manifest.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["status"] = "clean" if entry["status"] == "suspect" else "suspect"
        lines[0] = json.dumps(entry, sort_keys=True)
        manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, total, bad = guard.verify(str(manifest))
        self.assertFalse(ok, "an edited manifest must not verify")
        self.assertEqual(bad, 1)

    def test_a_missing_key_is_refused_rather_than_defaulted(self):
        del os.environ["SEAM_KEY"]
        with self.assertRaises(SystemExit):
            guard.key()

    def test_the_canary_is_stable_and_per_row(self):
        material = self.key.encode()
        self.assertEqual(guard.canary("abc", material), guard.canary("abc", material))
        self.assertNotEqual(guard.canary("abc", material), guard.canary("abd", material))

    def test_a_thin_seed_set_is_refused(self):
        seed = _rows(self.tmp / "seed.jsonl", [{"title": "only one", "label": "ok"}])
        with self.assertRaises(SystemExit):
            self._ingest([{"title": "x", "label": "ok"}], seed=seed)


if __name__ == "__main__":
    unittest.main()


class SizeLimitTests(unittest.TestCase):
    """A parser eats whatever it is handed. This is the ceiling."""

    def test_a_record_too_large_to_parse_refuses_the_file(self):
        """Skipping an over-long line used to fail open: the row vanished and the file verified."""
        with tempfile.TemporaryDirectory() as tmp:
            manifest = os.path.join(tmp, "m.jsonl")
            with open(manifest, "w", encoding="utf-8") as fh:
                fh.write('{"a": "' + "x" * (guard.MAX_LINE_CHARS + 10) + '"}\n')
            with self.assertRaises(ValueError):
                guard.verify(manifest)

    def test_a_record_flood_is_refused_rather_than_absorbed(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = os.path.join(tmp, "flood.jsonl")
            with open(manifest, "w", encoding="utf-8") as fh:
                fh.write("{}\n" * (guard.MAX_RECORDS + 1))
            with self.assertRaises(ValueError):
                guard.verify(manifest)

    def test_the_manifest_is_written_whole_or_not_at_all(self):
        """A half-written seal is worse than no seal: it verifies as a shorter record."""
        with tempfile.TemporaryDirectory() as tmp:
            manifest = os.path.join(tmp, "m.jsonl")
            guard.write_manifest(manifest, [{"row": 1}, {"row": 2}])
            self.assertFalse(os.path.exists(manifest + ".part"), "a partial manifest was left behind")
            ok, rows, _ = guard.verify(manifest)
            self.assertTrue(ok)
            self.assertEqual(rows, 2)
