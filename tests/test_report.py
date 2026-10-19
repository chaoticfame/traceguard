"""Synthetic storage-to-report regressions, without network or private logs."""

from collections.abc import Iterator
from dataclasses import replace
from hashlib import sha256
import json
import unittest

from traceguard.config import DetectionConfig
from traceguard.detector import detect_failure_bursts, correlate_success_after_failure_bursts
from traceguard.parser import parse_line
from traceguard.report import export_report
from traceguard.storage import EventOccurrence, EventStore


class ReportTests(unittest.TestCase):
    """Exercise the report contract with actual detector and storage outputs."""

    def setUp(self) -> None:
        """Store a duplicate-line burst and its following successful login."""
        self.source = sha256(b"synthetic source").hexdigest()
        self.config = DetectionConfig(failure_threshold=2)
        failed = "Oct 19 00:00:00 lab sshd[1]: Failed password for demo from 192.0.2.1 port 22 ssh2"
        accepted = failed.replace("Failed", "Accepted").replace("00:00:00", "00:00:01")
        events = [parse_line(line, year=2026) for line in (failed, failed, accepted)]
        bursts = detect_failure_bursts(events, self.config)
        correlations = correlate_success_after_failure_bursts(events, bursts, self.config)
        with EventStore(":memory:") as store:
            self.evidence = store.store_occurrences(self.source, list(enumerate(events, 1)))
            refs = tuple(item.occurrence_id for item in self.evidence)
            self.findings = store.store_findings([(bursts[0], refs[:2]), (correlations[0], refs)])

    def export(self, **overrides: object) -> str:
        """Export a private local report from the standard synthetic snapshot."""
        arguments = dict(source_digest=self.source, config=self.config,
                         occurrences=self.evidence, findings=self.findings)
        arguments.update(overrides)
        return export_report(**arguments)

    def test_version_configuration_and_ordered_evidence_links(self) -> None:
        """Keep occurrence multiplicity while retaining original fingerprints."""
        document = self.export()
        report = json.loads(document)
        self.assertTrue(document.endswith("\n"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["source_digest"], self.source)
        self.assertEqual(report["configuration"], self.config.to_dict())
        self.assertEqual([item["line_number"] for item in report["evidence"]], [1, 2, 3])
        self.assertEqual(report["evidence"][0]["event_id"], report["evidence"][1]["event_id"])
        self.assertNotEqual(report["evidence"][0]["occurrence_id"], report["evidence"][1]["occurrence_id"])
        self.assertTrue(all(item["explanation_status"] == "offline" for item in report["findings"]))

    def test_stable_serialization_and_no_input_mutation(self) -> None:
        """Reordered snapshots yield byte-identical JSON without clock metadata."""
        before = list(self.findings)
        self.assertEqual(self.export(), self.export(occurrences=reversed(self.evidence),
                                                  findings=reversed(self.findings)))
        report = json.loads(self.export())
        report["findings"][0]["finding"]["evidence_ids"].clear()
        self.assertEqual(self.findings, before)
        self.assertNotIn("raw_log", self.export())
        self.assertNotIn("source_path", self.export())

    def test_explanation_statuses_are_explicit_and_scoped(self) -> None:
        """Statuses are metadata only, and may not reference unrelated findings."""
        statuses = {self.findings[0].storage_id: "timeout", self.findings[1].storage_id: "valid"}
        report = json.loads(self.export(explanation_statuses=statuses))
        self.assertEqual({item["storage_id"]: item["explanation_status"] for item in report["findings"]}, statuses)
        for invalid in ({"f" * 64: "offline"}, {self.findings[0].storage_id: "private-secret"}):
            with self.assertRaises(ValueError) as raised:
                self.export(explanation_statuses=invalid)
            self.assertNotIn("private-secret", str(raised.exception))

    def test_orphans_and_cross_source_evidence_are_rejected(self) -> None:
        """No report may silently export detached or substituted evidence."""
        invalid = replace(self.findings[0], occurrence_ids=("f" * 64, "e" * 64))
        for overrides in (dict(occurrences=self.evidence[:1]), dict(findings=[invalid]),
                          dict(occurrences=[replace(self.evidence[0], source_digest="f" * 64)])):
            with self.assertRaises(ValueError):
                self.export(**overrides)

    def test_duplicate_positions_ids_and_mismatched_payloads(self) -> None:
        """Reject duplicate rows and payloads that don't match stored fingerprints."""
        for overrides in (dict(occurrences=[*self.evidence, self.evidence[0]]),
                          dict(findings=[self.findings[0]] * 2),
                          dict(occurrences=[replace(self.evidence[0], line_number=8)])):
            with self.assertRaises(ValueError):
                self.export(**overrides)
        payload = json.loads(self.findings[0].payload_json)
        payload["evidence_ids"][0] = "f" * 64
        with self.assertRaises(ValueError):
            self.export(findings=[replace(self.findings[0], payload_json=json.dumps(payload))])

    def test_unknown_or_malformed_payload_fields_fail_closed(self) -> None:
        """Never pass arbitrary stored JSON through the report boundary."""
        payload = json.loads(self.findings[0].payload_json)
        for document in ("not-json", "[]", '{"a":1,"a":2}',
                         json.dumps({**payload, "raw_log": "private-secret"})):
            with self.assertRaises(ValueError) as raised:
                self.export(findings=[replace(self.findings[0], payload_json=document)])
            self.assertNotIn("private-secret", str(raised.exception))

    def test_empty_report_and_invalid_configuration(self) -> None:
        """Empty input is valid, but invalid policy and source metadata are not."""
        report = json.loads(self.export(findings=[], occurrences=[]))
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["evidence"], [])
        for overrides in (dict(config={}), dict(source_digest="invalid")):
            with self.assertRaises(ValueError):
                self.export(**overrides)

    def test_generator_consumption_is_bounded(self) -> None:
        """Stop oversized sources at the maximum plus one rather than exhaust them."""
        consumed = 0

        def evidence() -> Iterator[EventOccurrence]:
            nonlocal consumed
            while True:
                consumed += 1
                yield self.evidence[0]

        with self.assertRaisesRegex(ValueError, "10000"):
            self.export(occurrences=evidence())
        self.assertEqual(consumed, 10_001)


if __name__ == "__main__":
    unittest.main()
