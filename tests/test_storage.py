"""Regression tests for transactional, source-aware occurrence storage."""

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import json
import sqlite3
import tempfile
import unittest

from traceguard.parser import AuthEvent, parse_line
from traceguard.config import DetectionConfig
from traceguard.detector import (
    correlate_success_after_failure_bursts,
    detect_failure_bursts,
)
from traceguard.storage import (
    MAX_STORED_OCCURRENCES,
    EventStore,
    StorageError,
)

LINE = "Oct  8 09:10:11 lab sshd[1]: Failed password for invalid user demo from 192.0.2.10 port 2201 ssh2"
SOURCE = sha256(b"synthetic auth log").hexdigest()


def event(line: str = LINE) -> AuthEvent:
    """Parse a valid synthetic event for storage tests."""
    parsed = parse_line(line, year=2026)
    if parsed is None:
        raise AssertionError("Synthetic test event must parse")
    return parsed


class EventStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        """Create an isolated file-backed SQLite store."""
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "traceguard.sqlite3"
        self.store = EventStore(self.path)

    def tearDown(self) -> None:
        """Close SQLite before removing its temporary directory."""
        self.store.close()
        self.directory.cleanup()

    def test_round_trip_preserves_source_position_and_event(self):
        first = event()
        stored = self.store.store_occurrences(SOURCE, [(7, first)])

        self.assertEqual(len(stored), 1)
        self.assertEqual(stored, self.store.list_occurrences())
        self.assertEqual(stored[0].source_digest, SOURCE)
        self.assertEqual(stored[0].line_number, 7)
        self.assertEqual(stored[0].event, first)

    def test_repeated_import_is_idempotent(self):
        records = [(1, event()), (3, event(LINE.replace("2201", "2203")))]

        first = self.store.store_occurrences(SOURCE, records)
        second = self.store.store_occurrences(SOURCE, records)

        self.assertEqual(second, first)
        self.assertEqual(self.store.list_occurrences(SOURCE), first)

    def test_identical_lines_at_different_positions_survive(self):
        duplicate = event()
        stored = self.store.store_occurrences(
            SOURCE, [(1, duplicate), (2, duplicate)],
        )

        self.assertEqual(len(stored), 2)
        self.assertEqual(stored[0].event.event_id, stored[1].event.event_id)
        self.assertNotEqual(stored[0].occurrence_id, stored[1].occurrence_id)

    def test_conflict_rolls_back_the_whole_batch(self):
        original = event()
        self.store.store_occurrences(SOURCE, [(1, original)])
        different = event(LINE.replace("2201", "2299"))

        with self.assertRaisesRegex(StorageError, "conflicts"):
            self.store.store_occurrences(
                SOURCE, [(2, different), (1, different)],
            )

        self.assertEqual(
            [(item.line_number, item.event) for item in self.store.list_occurrences()],
            [(1, original)],
        )

    def test_file_store_persists_after_reopen(self):
        expected = self.store.store_occurrences(SOURCE, [(4, event())])
        self.store.close()

        self.store = EventStore(self.path)

        self.assertEqual(self.store.list_occurrences(), expected)

    def test_rejects_invalid_inputs_without_writes(self):
        invalid_event = replace(event(), source_port=0)
        cases = (
            ("not-a-digest", [(1, event())]),
            (SOURCE, [(0, event())]),
            (SOURCE, [(True, event())]),
            (SOURCE, [(1, invalid_event)]),
            (SOURCE, [(1, object())]),
            (SOURCE, [(1, event()), (1, event())]),
        )
        for digest, records in cases:
            with self.subTest(digest=digest, records=records):
                with self.assertRaises(ValueError):
                    self.store.store_occurrences(digest, records)
                self.assertEqual(self.store.list_occurrences(), [])

    def test_rejects_oversized_batch_and_stops_consumption(self):
        consumed = 0

        def records():
            nonlocal consumed
            for line_number in range(1, MAX_STORED_OCCURRENCES + 3):
                consumed += 1
                yield line_number, event()

        with self.assertRaisesRegex(ValueError, "exceeds 10000"):
            self.store.store_occurrences(SOURCE, records())

        self.assertEqual(consumed, MAX_STORED_OCCURRENCES + 1)
        self.assertEqual(self.store.list_occurrences(), [])

    def test_schema_excludes_raw_logs_and_paths(self):
        self.store.close()
        with sqlite3.connect(self.path) as connection:
            columns = {
                row[1] for row in connection.execute(
                    "PRAGMA table_info(event_occurrences)"
                )
            }

        self.assertNotIn("raw_line", columns)
        self.assertNotIn("source_path", columns)
        self.assertIn("source_digest", columns)
        self.assertIn("line_number", columns)

    def test_closed_store_fails_predictably(self):
        self.store.close()

        with self.assertRaisesRegex(StorageError, "closed"):
            self.store.list_occurrences()


class FindingStoreTests(unittest.TestCase):
    """Exercise detector-to-storage provenance using synthetic duplicate lines."""

    def setUp(self) -> None:
        """Store duplicate failure occurrences and a subsequent success."""
        self.store = EventStore(":memory:")
        self.failures = [event(), event()]
        self.success = event(LINE.replace("Failed", "Accepted").replace(
            "invalid user ", "").replace("09:10:11", "09:10:12"))
        self.events = [*self.failures, self.success]
        self.occurrences = self.store.store_occurrences(
            SOURCE, list(enumerate(self.events, 1)),
        )
        policy = DetectionConfig(failure_threshold=2)
        self.burst, = detect_failure_bursts(self.events, policy)
        self.correlation, = correlate_success_after_failure_bursts(
            self.events, [self.burst], policy,
        )
        self.refs = tuple(item.occurrence_id for item in self.occurrences)

    def tearDown(self) -> None:
        """Close the isolated store."""
        self.store.close()

    def test_round_trip_and_idempotent_import(self) -> None:
        """Preserve the payload, ordered duplicate evidence, and correlations."""
        records = [(self.burst, self.refs[:2]), (self.correlation, self.refs)]
        first = self.store.store_findings(records)
        self.assertEqual(self.store.store_findings(records), first)
        self.assertEqual(self.store.list_findings(),
                         sorted(first, key=lambda item: item.storage_id))
        self.assertEqual(json.loads(first[0].payload_json)["finding_type"],
                         "failure_burst")
        self.assertEqual(json.loads(first[1].payload_json)["success_event_id"],
                         self.success.event_id)
        self.assertEqual(first[0].occurrence_ids, self.refs[:2])

    def test_orphan_rolls_back_preceding_valid_finding(self) -> None:
        """A later orphan must undo earlier finding and evidence insertions."""
        with self.assertRaisesRegex(StorageError, "orphaned"):
            self.store.store_findings([
                (self.burst, self.refs[:2]),
                (self.correlation, (*self.refs[:2], "f" * 64)),
            ])
        self.assertEqual(self.store.list_findings(), [])
        self.assertEqual(len(self.store.list_occurrences()), 3)
        self.assertEqual(self.store._require_connection().execute(
            "SELECT count(*) FROM finding_evidence").fetchone()[0], 0)

    def test_mismatched_fingerprint_is_rejected(self) -> None:
        """Existing evidence is insufficient if it belongs to another event."""
        with self.assertRaisesRegex(StorageError, "mismatched"):
            self.store.store_findings([(self.correlation, tuple(reversed(self.refs)))])
        self.assertEqual(self.store.list_findings(), [])

    def test_reusing_occurrence_is_rejected(self) -> None:
        """Two identical fingerprints still require two distinct occurrences."""
        with self.assertRaisesRegex(ValueError, "reuse"):
            self.store.store_findings([(self.burst, (self.refs[0], self.refs[0]))])

    def test_source_aware_finding_identity(self) -> None:
        """The same detector output from another source is distinct evidence."""
        other = self.store.store_occurrences(
            sha256(b"second source").hexdigest(),
            list(enumerate(self.events, 1)),
        )
        first, second = self.store.store_findings([
            (self.burst, self.refs[:2]),
            (self.burst, tuple(item.occurrence_id for item in other[:2])),
        ])
        self.assertNotEqual(first.storage_id, second.storage_id)
        self.assertEqual(first.payload_json, second.payload_json)

    def test_limits_and_invalid_findings(self) -> None:
        """Reject malformed references and bounded-batch violations."""
        for records in ([(object(), self.refs)], [(self.burst, ())],
                        [(self.burst, ("not-a-digest", self.refs[1]))],
                        [(self.burst, self.refs[:2])] * 10_001):
            with self.assertRaises(ValueError):
                self.store.store_findings(records)
        with self.assertRaisesRegex(ValueError, "20000"):
            self.store.store_findings([(self.correlation, self.refs)] * 6667)
        for limit in (0, True, 10_001):
            with self.assertRaises(ValueError):
                self.store.list_findings(limit=limit)
        self.assertEqual(self.store.list_findings(), [])

    def test_database_enforces_foreign_keys(self) -> None:
        """Direct SQL cannot attach a finding to a missing occurrence."""
        stored, = self.store.store_findings([(self.burst, self.refs[:2])])
        connection = self.store._require_connection()
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO finding_evidence VALUES (?, ?, ?)",
                               (stored.storage_id, 2, "f" * 64))

    def test_sql_failure_rolls_back_payload_and_links(self) -> None:
        """A database failure after payload insertion cannot leave partial data."""
        connection = self.store._require_connection()
        connection.execute(
            "CREATE TRIGGER reject_evidence BEFORE INSERT ON finding_evidence "
            "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"
        )
        with self.assertRaisesRegex(StorageError, "Unable to store findings"):
            self.store.store_findings([(self.burst, self.refs[:2])])
        self.assertEqual(self.store.list_findings(), [])
        self.assertEqual(connection.execute(
            "SELECT count(*) FROM finding_evidence").fetchone()[0], 0)

    def test_upgrade_preserves_occurrences_and_reopen_preserves_findings(self) -> None:
        """Upgrade a Day 6 schema without deleting its existing evidence."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "version1.db"
            with EventStore(path) as initial:
                occurrences = initial.store_occurrences(
                    SOURCE, list(enumerate(self.events, 1)))
            with sqlite3.connect(path) as connection:
                connection.executescript(
                    "DROP TABLE finding_evidence; DROP TABLE findings; "
                    "PRAGMA user_version = 1;"
                )
            with EventStore(path) as upgraded:
                self.assertEqual(upgraded.list_occurrences(), occurrences)
                expected = upgraded.store_findings([(self.burst, self.refs[:2])])
            with EventStore(path) as reopened:
                self.assertEqual(reopened.list_findings(), expected)
                self.assertEqual(reopened._require_connection().execute(
                    "PRAGMA user_version").fetchone()[0], 2)


if __name__ == "__main__":
    unittest.main()
