"""Synthetic regression cases for sliding windows and evidence accounting."""

from dataclasses import replace
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from itertools import permutations
import unittest

from traceguard.config import DetectionConfig
from traceguard.detector import MAX_BATCH_EVENTS, detect_failure_bursts
from traceguard.parser import AuthEvent


def event(second: float, *, identifier: str = "e", **changes: object) -> AuthEvent:
    """Build a synthetic event using a documentation-only source address."""
    stamp = datetime(2026, 10, 10, tzinfo=timezone.utc) + timedelta(seconds=second)
    record = AuthEvent(identifier, stamp.isoformat(), "lab", "demo", "192.0.2.10",
                       2222, "failure", "password")
    return replace(record, **changes)


class DetectorTests(unittest.TestCase):
    """Check the precise policy before integrating it with the CLI."""

    def setUp(self) -> None:
        """Use a short window and small threshold for transparent cases."""
        self.config = DetectionConfig(failure_threshold=3, failure_window_seconds=10)

    def test_exact_threshold_and_evidence(self) -> None:
        """Emit only once the threshold is reached, with exact evidence."""
        records = [event(i, identifier=str(i)) for i in range(3)]
        self.assertEqual(detect_failure_bursts(records[:2], self.config), [])
        finding, = detect_failure_bursts(records, self.config)
        self.assertEqual(finding.evidence_ids, ("0", "1", "2"))
        self.assertEqual(finding.failure_count, 3)
        self.assertEqual(finding.started_at, records[0].timestamp)
        self.assertEqual(finding.ended_at, records[-1].timestamp)

    def test_inclusive_window_and_expiration(self) -> None:
        """Include the exact boundary and expire an event just outside it."""
        self.assertEqual(len(detect_failure_bursts(
            [event(0), event(5), event(10)], self.config)), 1)
        self.assertEqual(detect_failure_bursts(
            [event(0), event(5), event(10.000001)], self.config), [])
        self.assertEqual(len(detect_failure_bursts(
            [event(0), event(5), event(11), event(12)], self.config)), 1)

    def test_isolated_failures(self) -> None:
        """Sparse attempts and an empty batch do not trigger findings."""
        self.assertEqual(detect_failure_bursts([event(0), event(20), event(40)], self.config), [])
        self.assertEqual(detect_failure_bursts([], self.config), [])

    def test_group_isolation(self) -> None:
        """Accounts, hosts, and source addresses cannot share a threshold."""
        for field, other in (("host", "other-lab"), ("username", "other-user"),
                             ("source_ip", "192.0.2.11")):
            with self.subTest(field=field):
                self.assertEqual(detect_failure_bursts(
                    [event(0), event(1), event(2, **{field: other})], self.config), [])

    def test_success_is_ignored_without_reset(self) -> None:
        """Successes neither count as failures nor clear preceding evidence."""
        records = [event(0), event(1, outcome="success"), event(2), event(3)]
        finding, = detect_failure_bursts(records, self.config)
        self.assertEqual(finding.failure_count, 3)
        self.assertEqual(detect_failure_bursts(records[:3], self.config), [])

    def test_input_order_invariance(self) -> None:
        """Unsorted batches and timestamp ties yield identical findings."""
        records = [event(0, identifier="b"), event(0, identifier="a"), event(1, identifier="c")]
        expected = detect_failure_bursts(records, self.config)
        for ordering in permutations(records):
            self.assertEqual(detect_failure_bursts(ordering, self.config), expected)

    def test_offsets_normalize_to_utc(self) -> None:
        """Equivalent local times are compared chronologically in UTC."""
        records = [event(0), event(1), event(2, timestamp="2026-10-10T08:00:02+08:00")]
        finding, = detect_failure_bursts(records, self.config)
        self.assertEqual(finding.ended_at, "2026-10-10T00:00:02+00:00")

    def test_evidence_is_consumed_and_duplicates_preserved(self) -> None:
        """Seven identical occurrences form two groups with an incomplete tail."""
        records = [event(0)] * 7
        findings = detect_failure_bursts(records, self.config)
        self.assertEqual(len(findings), 2)
        self.assertEqual(sum(f.failure_count for f in findings), 6)
        self.assertEqual(findings[0].evidence_ids, ("e", "e", "e"))
        self.assertNotEqual(findings[0].finding_id, findings[1].finding_id)
        self.assertEqual(len(records), 7)

    def test_invalid_event_data(self) -> None:
        """Reject malformed or naive timestamps and unknown outcomes."""
        for record in (event(0, timestamp="bad"), event(0, timestamp="2026-10-10T00:00:00"),
                       event(0, outcome="unknown"), None):
            with self.subTest(record=record):
                with self.assertRaises(ValueError):
                    detect_failure_bursts([record], self.config)
        with self.assertRaises(ValueError):
            detect_failure_bursts([], {})

    def test_default_policy(self) -> None:
        """The default five-failure threshold applies when no policy is supplied."""
        self.assertEqual(detect_failure_bursts([event(0)] * 4), [])
        self.assertEqual(len(detect_failure_bursts([event(0)] * 5)), 1)

    def test_batch_limit_and_generator_consumption(self) -> None:
        """Accept the cap and stop reading an unbounded source at cap plus one."""
        record = event(0, outcome="success")
        self.assertEqual(detect_failure_bursts([record] * MAX_BATCH_EVENTS), [])
        consumed = 0

        def source() -> Iterator[AuthEvent]:
            nonlocal consumed
            while True:
                consumed += 1
                yield record

        with self.assertRaisesRegex(ValueError, "exceeds 10000"):
            detect_failure_bursts(source())
        self.assertEqual(consumed, MAX_BATCH_EVENTS + 1)


if __name__ == "__main__":
    unittest.main()
