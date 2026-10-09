"""Regression tests for configuration boundaries and ambiguous input."""

from dataclasses import FrozenInstanceError
import json
import unittest

from traceguard.config import DetectionConfig


class ConfigTests(unittest.TestCase):
    """Ensure every configuration entry point enforces the same policy."""

    def test_defaults_and_partial_override(self) -> None:
        """Missing fields use documented defaults without mutating input."""
        self.assertEqual(DetectionConfig().to_dict(), {
            "failure_threshold": 5, "failure_window_seconds": 300,
            "success_window_seconds": 600,
        })
        values = {"failure_threshold": 3}
        config = DetectionConfig.from_mapping(values)
        values["failure_threshold"] = 9
        self.assertEqual(config.failure_threshold, 3)
        self.assertEqual(config.failure_window_seconds, 300)

    def test_inclusive_boundaries(self) -> None:
        """Minimum and maximum policies are accepted at both entry points."""
        for threshold, duration in ((2, 1), (10_000, 86_400)):
            values = {"failure_threshold": threshold,
                      "failure_window_seconds": duration,
                      "success_window_seconds": duration}
            self.assertEqual(DetectionConfig(**values).to_dict(), values)
            self.assertEqual(DetectionConfig.from_json(json.dumps(values)).to_dict(), values)

    def test_reject_invalid_numbers_without_coercion(self) -> None:
        """Reject bool, floats, strings, null, and out-of-bounds integers."""
        for field, lower, upper in (("failure_threshold", 2, 10_000),
                                    ("failure_window_seconds", 1, 86_400),
                                    ("success_window_seconds", 1, 86_400)):
            for value in (True, False, 2.0, "5", None, -1, lower - 1, upper + 1):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        DetectionConfig.from_mapping({field: value})
                    with self.assertRaises(ValueError):
                        DetectionConfig(**{field: value})
                    with self.assertRaises(ValueError):
                        DetectionConfig.from_json(json.dumps({field: value}))

    def test_unknown_keys(self) -> None:
        """Typos and non-string mapping keys must not silently use defaults."""
        for values in ({"failure_thresold": 5}, {1: 5}):
            with self.assertRaisesRegex(ValueError, "Unknown configuration key"):
                DetectionConfig.from_mapping(values)

    def test_duplicate_keys(self) -> None:
        """Ambiguous JSON objects fail rather than adopting the last value."""
        with self.assertRaisesRegex(ValueError, "Invalid configuration JSON"):
            DetectionConfig.from_json('{"failure_threshold": 2, "failure_threshold": 9}')

    def test_invalid_json_and_non_objects(self) -> None:
        """Malformed, non-standard numeric, deep, or non-object input fails."""
        for document in ("", "{", "[]", "null", "true", "42", '"text"',
                         '{"failure_threshold": NaN}',
                         '{"failure_window_seconds": Infinity}', "[" * 1100 + "]" * 1100):
            with self.subTest(document=document[:60]):
                with self.assertRaises(ValueError):
                    DetectionConfig.from_json(document)

    def test_document_limit(self) -> None:
        """Reject oversized input before JSON parsing; accept the exact limit."""
        self.assertEqual(DetectionConfig.from_json("{}" + " " * 4094), DetectionConfig())
        with self.assertRaisesRegex(ValueError, "at most 4096"):
            DetectionConfig.from_json("{}" + " " * 4095)

    def test_errors_do_not_expose_input(self) -> None:
        """Error summaries omit unknown values and their private contents."""
        with self.assertRaises(ValueError) as captured:
            DetectionConfig.from_json('{"secret": "private-example"}')
        self.assertNotIn("private-example", str(captured.exception))

    def test_immutable_config_and_independent_snapshot(self) -> None:
        """A caller cannot silently change a policy after validation."""
        config = DetectionConfig()
        with self.assertRaises(FrozenInstanceError):
            config.failure_threshold = 1
        snapshot = config.to_dict()
        snapshot["failure_threshold"] = 1
        self.assertEqual(config.failure_threshold, 5)


if __name__ == "__main__":
    unittest.main()
