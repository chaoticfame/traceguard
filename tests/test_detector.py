"""Synthetic regression cases for sliding windows and evidence accounting."""

from dataclasses import replace
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from itertools import permutations
import unittest

from traceguard.config import DetectionConfig
from traceguard.detector import (
    MAX_BATCH_EVENTS,
    DistributedAccountAttempt,
    FailureBurst,
    correlate_success_after_failure_bursts,
    detect_distributed_account_attempts,
    detect_failure_bursts,
)
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


class CorrelationTests(unittest.TestCase):
    """Check success-after-failure correlation and evidence provenance."""

    def setUp(self) -> None:
        """Build one threshold-sized burst for the common test identity."""
        self.config = DetectionConfig(
            failure_threshold=3, failure_window_seconds=10,
            success_window_seconds=20,
        )
        self.failures = [event(i, identifier=f"f{i}") for i in range(3)]
        self.burst, = detect_failure_bursts(self.failures, self.config)

    def correlate(self, successes: list[AuthEvent]) -> list[object]:
        """Correlate test successes against the standard preceding burst."""
        return correlate_success_after_failure_bursts(
            [*self.failures, *successes], [self.burst], self.config,
        )

    def test_matching_success_includes_complete_evidence(self) -> None:
        """Link the burst and success fingerprints without losing failures."""
        success = event(5, identifier="s1", outcome="success")
        finding, = self.correlate([success])
        self.assertEqual(finding.burst_finding_id, self.burst.finding_id)
        self.assertEqual(finding.success_event_id, "s1")
        self.assertEqual(finding.evidence_ids, ("f0", "f1", "f2", "s1"))
        self.assertEqual(finding.failure_count, 3)
        self.assertEqual(finding.succeeded_at, success.timestamp)

    def test_follow_up_window_is_inclusive(self) -> None:
        """Accept immediate and exact-timeout successes, but not later ones."""
        self.assertEqual(len(self.correlate([
            event(2, identifier="now", outcome="success")
        ])), 1)
        self.assertEqual(len(self.correlate([
            event(22, identifier="edge", outcome="success")
        ])), 1)
        self.assertEqual(self.correlate([
            event(22.000001, identifier="late", outcome="success")
        ]), [])

    def test_identity_must_match_exactly(self) -> None:
        """Host, account, and source address are all correlation boundaries."""
        for field, other in (("host", "other-lab"), ("username", "other-user"),
                             ("source_ip", "192.0.2.11")):
            with self.subTest(field=field):
                success = event(5, identifier="s", outcome="success", **{field: other})
                self.assertEqual(self.correlate([success]), [])

    def test_success_before_burst_end_does_not_match(self) -> None:
        """Chronologically earlier successes cannot explain a later burst."""
        success = event(1, identifier="early", outcome="success")
        self.assertEqual(self.correlate([success]), [])

    def test_one_to_one_matching_prefers_latest_burst(self) -> None:
        """One success closes the newest eligible burst; later success gets older."""
        second_failures = [event(5 + i, identifier=f"g{i}") for i in range(3)]
        second_burst, = detect_failure_bursts(second_failures, self.config)
        successes = [event(10, identifier="s1", outcome="success"),
                     event(11, identifier="s2", outcome="success")]
        findings = correlate_success_after_failure_bursts(
            [*self.failures, *second_failures, *reversed(successes)],
            [second_burst, self.burst], self.config,
        )
        self.assertEqual([item.burst_finding_id for item in findings],
                         [second_burst.finding_id, self.burst.finding_id])
        self.assertEqual([item.success_event_id for item in findings], ["s1", "s2"])

    def test_one_success_cannot_close_multiple_bursts(self) -> None:
        """A single success produces at most one correlated finding."""
        duplicate = FailureBurst(
            "other-burst", self.burst.host, self.burst.source_ip,
            self.burst.username, self.burst.started_at, self.burst.ended_at,
            ("x", "y", "z"),
        )
        findings = correlate_success_after_failure_bursts(
            [event(5, identifier="s", outcome="success")],
            [self.burst, duplicate], self.config,
        )
        self.assertEqual(len(findings), 1)

    def test_order_and_timezone_offsets_are_normalized(self) -> None:
        """Input order and equivalent timestamp offsets do not alter output."""
        success = event(5, identifier="s", outcome="success",
                        timestamp="2026-10-10T08:00:05+08:00")
        expected = self.correlate([success])
        actual = correlate_success_after_failure_bursts(
            [success, *reversed(self.failures)], [self.burst], self.config,
        )
        self.assertEqual(actual, expected)
        self.assertEqual(actual[0].succeeded_at, "2026-10-10T00:00:05+00:00")

    def test_invalid_bursts_and_limits(self) -> None:
        """Reject malformed findings, invalid policies, and oversized batches."""
        malformed = FailureBurst(
            "bad", "lab", "192.0.2.10", "demo",
            "2026-10-10T00:00:02+00:00", "2026-10-10T00:00:01+00:00", ("f",),
        )
        for bursts in ([None], [malformed], [replace(self.burst, evidence_ids=())],
                       [replace(self.burst, ended_at="not-a-time")]):
            with self.subTest(bursts=bursts):
                with self.assertRaises(ValueError):
                    correlate_success_after_failure_bursts([], bursts, self.config)
        with self.assertRaises(ValueError):
            correlate_success_after_failure_bursts([], [], {})
        with self.assertRaisesRegex(ValueError, "exceeds 10000"):
            correlate_success_after_failure_bursts(
                [], [self.burst] * (MAX_BATCH_EVENTS + 1), self.config,
            )


class DistributedAccountTests(unittest.TestCase):
    """Check distinct-source account targeting and exact provenance."""

    def setUp(self) -> None:
        self.config = DetectionConfig(
            distributed_source_threshold=3, failure_window_seconds=10,
        )

    @staticmethod
    def source(second: float, address: str, identifier: str) -> AuthEvent:
        """Build one failed authentication from a chosen source."""
        return event(
            second, identifier=identifier, source_ip=address,
            source_port=2000 + int(identifier.removeprefix("e")),
        )

    def test_exact_distinct_source_threshold_and_evidence(self) -> None:
        """Emit at the threshold with one exact occurrence per source."""
        records = [
            self.source(0, "192.0.2.1", "e1"),
            self.source(1, "192.0.2.2", "e2"),
            self.source(2, "192.0.2.3", "e3"),
        ]
        self.assertEqual(
            detect_distributed_account_attempts(records[:2], self.config), [],
        )
        finding, = detect_distributed_account_attempts(records, self.config)
        self.assertIsInstance(finding, DistributedAccountAttempt)
        self.assertEqual(finding.source_count, 3)
        self.assertEqual(
            finding.source_ips, ("192.0.2.1", "192.0.2.2", "192.0.2.3"),
        )
        self.assertEqual(finding.evidence_ids, ("e1", "e2", "e3"))
        self.assertEqual((finding.started_at, finding.ended_at),
                         (records[0].timestamp, records[-1].timestamp))

    def test_repeated_source_uses_latest_exact_evidence(self) -> None:
        """Retries from one address count once and keep its latest evidence."""
        records = [
            self.source(0, "192.0.2.1", "e1"),
            self.source(1, "192.0.2.1", "e2"),
            self.source(2, "192.0.2.2", "e3"),
            self.source(3, "192.0.2.3", "e4"),
        ]
        finding, = detect_distributed_account_attempts(records, self.config)
        self.assertEqual(finding.source_count, 3)
        self.assertEqual(finding.evidence_ids, ("e2", "e3", "e4"))
        self.assertNotIn("e1", finding.evidence_ids)

    def test_window_boundary_is_inclusive_and_expiration_is_strict(self) -> None:
        """Accept exactly ten seconds and expire a source just beyond it."""
        inclusive = [
            self.source(0, "192.0.2.1", "e1"),
            self.source(5, "192.0.2.2", "e2"),
            self.source(10, "192.0.2.3", "e3"),
        ]
        self.assertEqual(len(detect_distributed_account_attempts(
            inclusive, self.config,
        )), 1)
        outside = [*inclusive[:2], self.source(10.000001, "192.0.2.3", "e3")]
        self.assertEqual(
            detect_distributed_account_attempts(outside, self.config), [],
        )

    def test_target_identity_and_failure_outcome_are_required(self) -> None:
        """Do not combine hosts/accounts or count successful logins."""
        base = [
            self.source(0, "192.0.2.1", "e1"),
            self.source(1, "192.0.2.2", "e2"),
        ]
        for changes in (
            {"host": "other-lab"}, {"username": "other-user"},
            {"outcome": "success"},
        ):
            with self.subTest(changes=changes):
                third = replace(
                    self.source(2, "192.0.2.3", "e3"), **changes,
                )
                self.assertEqual(detect_distributed_account_attempts(
                    [*base, third], self.config,
                ), [])

    def test_order_offsets_and_non_overlapping_groups_are_stable(self) -> None:
        """Normalize UTC, consume evidence, and ignore input ordering."""
        first = [
            self.source(0, "192.0.2.1", "e1"),
            self.source(1, "192.0.2.2", "e2"),
            replace(self.source(2, "192.0.2.3", "e3"),
                    timestamp="2026-10-10T08:00:02+08:00"),
        ]
        second = [
            self.source(3, "192.0.2.4", "e4"),
            self.source(4, "192.0.2.5", "e5"),
            self.source(5, "192.0.2.6", "e6"),
        ]
        expected = detect_distributed_account_attempts(
            [*first, *second], self.config,
        )
        actual = detect_distributed_account_attempts(
            [*reversed(second), *reversed(first)], self.config,
        )
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 2)
        self.assertTrue(set(actual[0].evidence_ids).isdisjoint(
            actual[1].evidence_ids,
        ))
        self.assertEqual(actual[0].ended_at, "2026-10-10T00:00:02+00:00")

    def test_defaults_validation_and_batch_limit(self) -> None:
        """Apply the default threshold and reuse bounded batch validation."""
        records = [
            self.source(i, f"192.0.2.{i + 1}", f"e{i + 1}")
            for i in range(5)
        ]
        self.assertEqual(detect_distributed_account_attempts(records[:4]), [])
        self.assertEqual(len(detect_distributed_account_attempts(records)), 1)
        with self.assertRaises(ValueError):
            detect_distributed_account_attempts([], {})
        with self.assertRaisesRegex(ValueError, "exceeds 10000"):
            detect_distributed_account_attempts(
                [event(0, outcome="success")] * (MAX_BATCH_EVENTS + 1),
                self.config,
            )


if __name__ == "__main__":
    unittest.main()
