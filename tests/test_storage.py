"""Regression tests for transactional, source-aware occurrence storage."""

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import sqlite3
import tempfile
import unittest

from traceguard.parser import AuthEvent, parse_line
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


if __name__ == "__main__":
    unittest.main()
