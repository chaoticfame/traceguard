"""Strict, immutable configuration for bounded authentication detection."""

from collections.abc import Mapping
from dataclasses import dataclass, fields
import json

_MAX_JSON_CHARS = 4096


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys instead of silently accepting the last value."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate configuration key")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Detection policy with integer seconds and inclusive numeric bounds.

    A burst requires 2–10,000 failures, and distributed-account detection
    requires 2–10,000 distinct sources. Both windows permit 1–86,400 seconds.
    Defaults are starting policies, not evidence of account compromise.
    Type validation is enforced at runtime, including direct construction;
    booleans, floating-point numbers, and numeric strings are not integers here.
    """

    failure_threshold: int = 5
    distributed_source_threshold: int = 5
    failure_window_seconds: int = 300
    success_window_seconds: int = 600

    def __post_init__(self) -> None:
        """Enforce limits before configuration can reach a detector."""
        limits = (
            ("failure_threshold", self.failure_threshold, 2, 10_000),
            ("distributed_source_threshold", self.distributed_source_threshold,
             2, 10_000),
            ("failure_window_seconds", self.failure_window_seconds, 1, 86_400),
            ("success_window_seconds", self.success_window_seconds, 1, 86_400),
        )
        for name, value, lower, upper in limits:
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError(f"{name} must be an integer between {lower} and {upper}")

    @classmethod
    def from_mapping(cls, values: Mapping[str, object]) -> "DetectionConfig":
        """Load known fields; omitted fields retain defaults, unknown keys fail."""
        if not isinstance(values, Mapping):
            raise ValueError("Configuration must be an object")
        allowed = {field.name for field in fields(cls)}
        if any(key not in allowed for key in values):
            raise ValueError("Unknown configuration key")
        # Runtime validation occurs in __post_init__; no coercion is performed.
        return cls(**dict(values))

    @classmethod
    def from_json(cls, document: str) -> "DetectionConfig":
        """Parse a small JSON object without coercion or duplicate-key ambiguity.

        Failures never echo the supplied document, which could contain private
        data accidentally placed in a configuration file.
        """
        if not isinstance(document, str) or len(document) > _MAX_JSON_CHARS:
            raise ValueError("Configuration must be text of at most 4096 characters")
        try:
            values = json.loads(document, object_pairs_hook=_unique_object)
        except (ValueError, RecursionError) as exc:
            raise ValueError("Invalid configuration JSON") from exc
        return cls.from_mapping(values)

    def to_dict(self) -> dict[str, int]:
        """Return an independent, serializable snapshot of the policy."""
        return {field.name: getattr(self, field.name) for field in fields(self)}
