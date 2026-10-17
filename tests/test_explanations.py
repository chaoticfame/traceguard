"""Offline schema and provenance regressions using synthetic evidence."""

from collections.abc import Iterator
from dataclasses import FrozenInstanceError
import json
import unittest

from traceguard.detector import FailureBurst
from traceguard.explanations import Explanation, ExplanationError, validate_explanation
from traceguard.privacy import sanitize_findings


class ExplanationTests(unittest.TestCase):
    """Keep model annotations separate from immutable deterministic findings."""

    def setUp(self) -> None:
        """Build real privacy-layer aliases from a synthetic detector finding."""
        self.finding = FailureBurst(
            "a" * 64, "lab", "192.0.2.1", "demo",
            "2026-10-17T00:00:00+00:00", "2026-10-17T00:00:01+00:00",
            ("b" * 64, "c" * 64),
        )
        self.context, = sanitize_findings([self.finding])
        self.payload = {
            "finding_id": self.context["finding_id"],
            "summary": "Two failures met the configured threshold.",
            "evidence_ids": list(self.context["evidence_ids"]),
            "limitations": ["Retries may be legitimate; this is a review candidate."],
        }

    def validate(self, payload: object) -> Explanation:
        """Serialize a synthetic model result and validate against fixed context."""
        return validate_explanation(
            json.dumps(payload), finding_id=self.context["finding_id"],
            evidence_ids=self.context["evidence_ids"],
        )

    def test_valid_round_trip_immutable_and_does_not_change_finding(self) -> None:
        """Return a frozen annotation and independent snapshots, not new rules."""
        annotation = self.validate(self.payload)
        self.assertEqual(annotation.to_dict(), self.payload)
        self.assertEqual(self.finding.evidence_ids, ("b" * 64, "c" * 64))
        with self.assertRaises(FrozenInstanceError):
            annotation.summary = "replacement verdict"
        snapshot = annotation.to_dict()
        snapshot["evidence_ids"].clear()
        self.assertEqual(len(annotation.evidence_ids), 2)

    def test_missing_and_unknown_fields_are_rejected(self) -> None:
        """No partial annotations or model-added detector/remediation fields."""
        for field in self.payload:
            payload = dict(self.payload)
            del payload[field]
            with self.assertRaises(ExplanationError):
                self.validate(payload)
        for field in ("severity", "verdict", "command", "findings"):
            with self.assertRaises(ExplanationError):
                self.validate({**self.payload, field: "unexpected"})

    def test_cross_finding_and_unknown_evidence_rejected(self) -> None:
        """Well-formed aliases still need membership in this finding's context."""
        for changes in (
            {"finding_id": "finding-" + "f" * 32 + "-1"},
            {"evidence_ids": ["evidence-" + "f" * 32 + "-1"]},
            {"evidence_ids": ["b" * 64]},
            {"evidence_ids": [self.context["finding_id"]]},
            {"evidence_ids": [self.context["evidence_ids"][0]] * 2},
        ):
            with self.assertRaises(ExplanationError):
                self.validate({**self.payload, **changes})

    def test_subset_citations_and_duplicate_context_fingerprints(self) -> None:
        """Citations need not repeat every occurrence when fingerprints repeat."""
        reference = self.context["evidence_ids"][0]
        payload = {**self.payload, "evidence_ids": [reference]}
        annotation = validate_explanation(
            json.dumps(payload), finding_id=self.context["finding_id"],
            evidence_ids=[reference, reference],
        )
        self.assertEqual(annotation.evidence_ids, (reference,))

    def test_text_type_length_and_control_boundaries(self) -> None:
        """Enforce inclusive lengths and reject terminal/bidi/surrogate controls."""
        accepted = {**self.payload, "summary": "x" * 1000,
                    "limitations": ["x" * 300] * 5}
        self.assertEqual(len(self.validate(accepted).summary), 1000)
        for value in ("", " ", "x" * 1001, None, True, 42, {},
                      "bad\ntext", "bad\x1b[31m", "bad\u202etext", "\ud800"):
            with self.assertRaises(ExplanationError):
                self.validate({**self.payload, "summary": value})
        for values in ([], ["x"] * 6, ["x" * 301], [None], "text"):
            with self.assertRaises(ExplanationError):
                self.validate({**self.payload, "limitations": values})

    def test_non_objects_wrong_reference_types_and_empty_citations(self) -> None:
        """Reject JSON primitives, nested reference objects, and type coercion."""
        for payload in ([], None, 1, "text", True):
            with self.assertRaises(ExplanationError):
                self.validate(payload)
        for references in ([], "text", None, [None], [True], [{}]):
            with self.assertRaises(ExplanationError):
                self.validate({**self.payload, "evidence_ids": references})

    def test_ambiguous_malformed_and_oversized_documents(self) -> None:
        """Reject duplicate keys, NaN, trailing content, deep JSON and fences."""
        valid = json.dumps(self.payload)
        documents = ("", "x" * 16_385, "```json\n" + valid + "\n```",
                     valid + " {}", valid[:-1] + ',"summary":"duplicate"}',
                     valid.replace('"summary":', '"summary":NaN,"extra":'),
                     "[" * 2000 + "0" + "]" * 2000)
        for document in documents:
            with self.assertRaises(ExplanationError):
                validate_explanation(document, finding_id=self.context["finding_id"],
                                     evidence_ids=self.context["evidence_ids"])

    def test_context_is_bounded_and_invalid_input_is_private(self) -> None:
        """Stop infinite evidence input at cap plus one; do not echo bad data."""
        consumed = 0

        def references() -> Iterator[str]:
            nonlocal consumed
            while True:
                consumed += 1
                yield self.context["evidence_ids"][0]

        with self.assertRaises(ExplanationError):
            validate_explanation(json.dumps(self.payload),
                                 finding_id=self.context["finding_id"],
                                 evidence_ids=references())
        self.assertEqual(consumed, 10_001)
        for context in ([], None, "private-secret", ["private-secret"]):
            with self.assertRaises(ExplanationError) as raised:
                validate_explanation(json.dumps(self.payload),
                                     finding_id=self.context["finding_id"],
                                     evidence_ids=context)
            self.assertNotIn("private-secret", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
