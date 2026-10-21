"""Synthetic end-to-end tests for the persistent report pipeline."""

from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from traceguard.__main__ import main


class PipelineTests(unittest.TestCase):
    """Exercise parsing through private report publication without a model."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        fixture = Path(__file__).resolve().parents[1] / "examples" / "auth.log"
        self.log = self.root / "auth.log"
        self.log.write_bytes(fixture.read_bytes())
        self.database = self.root / "traceguard.sqlite3"
        self.report = self.root / "report.json"

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_pipeline(self, *extra: str) -> tuple[int, dict[str, object] | None, str]:
        output, errors = io.StringIO(), io.StringIO()
        arguments = [
            "pipeline", str(self.log), "--year", "2026",
            "--failure-threshold", "2", "--database", str(self.database),
            "--report", str(self.report), *extra,
        ]
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(arguments)
        summary = json.loads(output.getvalue()) if output.getvalue() else None
        return code, summary, errors.getvalue()

    def test_pipeline_persists_evidence_and_exports_linked_report(self) -> None:
        """Connect every MVP layer using the repository's synthetic fixture."""
        with patch("traceguard.explanations.OllamaClient") as transport:
            code, summary, errors = self.run_pipeline()
        self.assertEqual(code, 0, errors)
        self.assertEqual(summary, {
            "parsed": 3, "skipped": 1, "occurrences": 3,
            "findings": 2, "schema_version": 1,
        })
        transport.assert_not_called()
        document = json.loads(self.report.read_text(encoding="ascii"))
        self.assertEqual(document["source_digest"], sha256(self.log.read_bytes()).hexdigest())
        self.assertEqual([item["line_number"] for item in document["evidence"]], [1, 2, 3])
        self.assertEqual(len(document["findings"]), 2)
        self.assertTrue(all(item["explanation_status"] == "offline"
                            for item in document["findings"]))
        known = {item["occurrence_id"] for item in document["evidence"]}
        self.assertTrue(all(set(item["occurrence_ids"]) <= known
                            for item in document["findings"]))

    def test_rerun_is_idempotent_and_report_is_byte_stable(self) -> None:
        """Reprocessing one source preserves occurrence and finding counts."""
        first_code, first, _ = self.run_pipeline()
        first_report = self.report.read_bytes()
        second_code, second, errors = self.run_pipeline()
        self.assertEqual((first_code, second_code), (0, 0), errors)
        self.assertEqual(second, first)
        self.assertEqual(self.report.read_bytes(), first_report)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM event_occurrences").fetchone()[0], 3)
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM findings").fetchone()[0], 2)
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM finding_evidence").fetchone()[0], 5)

    def test_pipeline_preserves_duplicate_line_occurrences(self) -> None:
        """Identical fingerprints remain separate source-position evidence."""
        failure = ("Oct 20 00:00:00 lab sshd[1]: Failed password for demo "
                   "from 192.0.2.1 port 22 ssh2\n")
        success = failure.replace("Failed", "Accepted").replace(
            "00:00:00", "00:00:01")
        self.log.write_text(failure + failure + success, encoding="utf-8")
        self.run_pipeline()
        document = json.loads(self.report.read_text(encoding="ascii"))
        first, second = document["evidence"][:2]
        self.assertEqual(first["event_id"], second["event_id"])
        self.assertNotEqual(first["occurrence_id"], second["occurrence_id"])

    def test_repeated_identical_bursts_receive_disjoint_evidence(self) -> None:
        """Do not silently link later bursts back to earlier duplicate lines."""
        failure = ("Oct 20 00:00:00 lab sshd[1]: Failed password for demo "
                   "from 192.0.2.1 port 22 ssh2\n")
        self.log.write_text(failure * 4, encoding="utf-8")
        code, summary, errors = self.run_pipeline()
        self.assertEqual(code, 0, errors)
        self.assertEqual(summary["findings"], 2)
        findings = json.loads(self.report.read_text(encoding="ascii"))["findings"]
        first, second = (set(item["occurrence_ids"]) for item in findings)
        self.assertTrue(first.isdisjoint(second))

    def test_offline_overrides_model_without_transport(self) -> None:
        """The full pipeline retains an explicit offline mode."""
        with patch("traceguard.explanations.OllamaClient") as transport:
            code, _, errors = self.run_pipeline("--ai-model", "local-test", "--offline")
        self.assertEqual(code, 0, errors)
        transport.assert_not_called()
        document = json.loads(self.report.read_text(encoding="ascii"))
        self.assertTrue(all(item["explanation_status"] == "offline"
                            for item in document["findings"]))

    def test_distinct_paths_are_required_before_any_write(self) -> None:
        """Never replace a log or database with the exported report."""
        original = self.log.read_bytes()
        for database, report in ((self.log, self.report),
                                 (self.database, self.log),
                                 (self.database, self.database)):
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                code = main(["pipeline", str(self.log), "--year", "2026",
                             "--database", str(database), "--report", str(report)])
            self.assertEqual(code, 2)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("must be distinct", errors.getvalue())
            self.assertEqual(self.log.read_bytes(), original)

    def test_invalid_utf8_does_not_create_database_or_report(self) -> None:
        """Decode failures stop before persistent artifacts are opened."""
        self.log.write_bytes(b"\xff private-secret")
        code, summary, errors = self.run_pipeline()
        self.assertEqual(code, 2)
        self.assertIsNone(summary)
        self.assertFalse(self.database.exists())
        self.assertFalse(self.report.exists())
        self.assertNotIn("private-secret", errors)


if __name__ == "__main__":
    unittest.main()
