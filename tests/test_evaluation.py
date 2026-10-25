"""Regression tests for bounded, offline rule evaluation."""

from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from traceguard.config import DetectionConfig
from traceguard.evaluation import (
    LabeledCase,
    MAX_CASES,
    evaluate_rules,
    load_labeled_cases,
)


FIXTURE = Path(__file__).parents[1] / "examples" / "labeled_cases.json"


class EvaluationTests(unittest.TestCase):
    """Measure the actual detectors and reject ambiguous evaluation data."""

    def setUp(self) -> None:
        self.cases = load_labeled_cases(FIXTURE)

    def test_fixture_scores_both_rules_against_real_events(self) -> None:
        """The documented synthetic set provides positives and negatives."""
        self.assertEqual(len(self.cases), 4)
        metrics = {item.rule: item for item in evaluate_rules(self.cases)}
        for rule in ("failure_burst", "distributed_account_attempt"):
            with self.subTest(rule=rule):
                self.assertEqual(
                    (metrics[rule].true_positives, metrics[rule].false_positives,
                     metrics[rule].false_negatives, metrics[rule].true_negatives),
                    (1, 0, 0, 3),
                )
                self.assertEqual(metrics[rule].precision, 1.0)
                self.assertEqual(metrics[rule].recall, 1.0)

    def test_empty_denominators_are_explicitly_undefined(self) -> None:
        """Never turn an undefined precision or recall into a flattering score."""
        negative = next(case for case in self.cases if not case.expected_rules)
        for metric in evaluate_rules([negative]):
            self.assertIsNone(metric.precision)
            self.assertIsNone(metric.recall)
            self.assertEqual(metric.true_negatives, 1)

    def test_false_negative_has_zero_recall_and_undefined_precision(self) -> None:
        """A labeled positive with no detector output has recall zero."""
        negative = next(case for case in self.cases if not case.expected_rules)
        mislabeled = replace(
            negative, case_id="known-positive",
            expected_rules=frozenset({"failure_burst"}),
        )
        metric = {item.rule: item for item in evaluate_rules([mislabeled])}[
            "failure_burst"
        ]
        self.assertIsNone(metric.precision)
        self.assertEqual(metric.recall, 0.0)
        self.assertEqual(metric.false_negatives, 1)

    def test_policy_is_applied_without_mutating_cases(self) -> None:
        """Changing a threshold changes predictions while fixture labels stay put."""
        original = self.cases
        metrics = {item.rule: item for item in evaluate_rules(
            self.cases, DetectionConfig(
                failure_threshold=6, distributed_source_threshold=6,
            ),
        )}
        self.assertEqual(metrics["failure_burst"].false_negatives, 1)
        self.assertEqual(metrics["distributed_account_attempt"].false_negatives, 1)
        self.assertEqual(self.cases, original)

    def test_loader_rejects_duplicate_keys_unknown_rules_and_private_echo(self) -> None:
        """Malformed labels fail with stable errors that do not quote input."""
        documents = (
            '{"schema_version":1,"schema_version":1,"cases":[]}',
            json.dumps({
                "schema_version": 1,
                "cases": [{
                    "case_id": "secret-case-value",
                    "events": [],
                    "expected_rules": ["not-a-rule"],
                }],
            }),
        )
        with TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            for document in documents:
                with self.subTest(document=document):
                    path.write_text(document, encoding="utf-8")
                    with self.assertRaises(ValueError) as context:
                        load_labeled_cases(path)
                    self.assertNotIn("secret-case-value", str(context.exception))

    def test_evaluation_batch_is_bounded_and_ids_are_unique(self) -> None:
        """Reject duplicate labels and consume at most the cap plus one."""
        case = self.cases[0]
        with self.assertRaisesRegex(ValueError, "identifiers"):
            evaluate_rules([case, case])
        consumed = 0

        def source():
            nonlocal consumed
            while True:
                consumed += 1
                yield replace(case, case_id=f"case-{consumed}")

        with self.assertRaisesRegex(ValueError, "1 through 100"):
            evaluate_rules(source())
        self.assertEqual(consumed, MAX_CASES + 1)


if __name__ == "__main__":
    unittest.main()
