"""Tests for bounded, privacy-safe log ingestion."""

from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest

from traceguard.__main__ import main
from traceguard.ingest import (
    MAX_FILE_BYTES,
    MAX_INGEST_EVENTS,
    IngestError,
    ingest_file,
)


EVENT = (
    "Oct 22 08:00:00 lab sshd[1]: Failed password for demo "
    "from 192.0.2.10 port 2201 ssh2\n"
)


class IngestTests(unittest.TestCase):
    """Verify hard input bounds and aggregate-only rejection reporting."""

    def test_caps_events_and_counts_rejections_without_retaining_lines(self) -> None:
        """Keep only the configured batch and aggregate every excluded record."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            secret = "private-token-should-not-escape"
            payload = (EVENT * 3 + secret + "\n").encode("utf-8")
            path.write_bytes(payload)
            batch = ingest_file(path, year=2026, max_events=2)

        self.assertEqual(batch.source_digest, sha256(payload).hexdigest())
        self.assertEqual([line for line, _ in batch.records], [1, 2])
        self.assertEqual(batch.rejections.unsupported, 1)
        self.assertEqual(batch.rejections.event_limit, 1)
        self.assertEqual(batch.rejections.total, 2)
        self.assertNotIn(secret, repr(batch))

    def test_rejects_file_over_limit_without_disclosing_content(self) -> None:
        """Stop before parsing an oversized file and keep its bytes private."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            secret = "highly-private-record"
            path.write_text(secret, encoding="utf-8")
            with self.assertRaises(IngestError) as raised:
                ingest_file(path, year=2026, max_file_bytes=8)

        self.assertIn("8-byte ingestion limit", str(raised.exception))
        self.assertNotIn(secret, str(raised.exception))

    def test_rejects_invalid_utf8_with_safe_error(self) -> None:
        """Do not echo undecodable source bytes in an ingestion failure."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_bytes(b"\xffprivate")
            with self.assertRaisesRegex(IngestError, "not valid UTF-8"):
                ingest_file(path, year=2026)

    def test_pipeline_emits_aggregate_rejection_counts(self) -> None:
        """Expose actionable counts while omitting the rejected record text."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "auth.log"
            secret = "rejected-private-value"
            log.write_text(EVENT + secret + "\n", encoding="utf-8")
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                code = main([
                    "pipeline", str(log), "--year", "2026",
                    "--database", str(root / "events.sqlite3"),
                    "--report", str(root / "report.json"),
                ])

        self.assertEqual(code, 0, errors.getvalue())
        self.assertEqual(json.loads(output.getvalue())["skipped"], 1)
        self.assertIn(
            "rejected_records=1 unsupported=1 event_limit=0",
            errors.getvalue(),
        )
        self.assertNotIn(secret, errors.getvalue())

    def test_limit_configuration_must_be_positive_integers(self) -> None:
        """Reject disabled or ambiguous bounds before opening the source."""
        path = Path("not-opened.log")
        for arguments in (
            {"max_file_bytes": 0}, {"max_events": 0},
            {"max_file_bytes": True}, {"max_events": 1.5},
            {"max_file_bytes": MAX_FILE_BYTES + 1},
            {"max_events": MAX_INGEST_EVENTS + 1},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    ingest_file(path, year=2026, **arguments)


if __name__ == "__main__":
    unittest.main()
