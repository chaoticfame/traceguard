"""Offline evaluation of deterministic rules against labeled synthetic cases."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from itertools import islice
import json
from pathlib import Path

from .config import DetectionConfig
from .detector import detect_distributed_account_attempts, detect_failure_bursts
from .parser import AuthEvent

MAX_CASES = 100
MAX_CASE_EVENTS = 1_000
MAX_FIXTURE_BYTES = 256 * 1024
RULES = ("distributed_account_attempt", "failure_burst")
_EVENT_FIELDS = {
    "event_id", "timestamp", "host", "username", "source_ip",
    "source_port", "outcome", "method",
}


@dataclass(frozen=True, slots=True)
class LabeledCase:
    """A synthetic event batch and the rule names expected to fire."""

    case_id: str
    events: tuple[AuthEvent, ...]
    expected_rules: frozenset[str]


@dataclass(frozen=True, slots=True)
class RuleMetrics:
    """Binary classification counts and derived metrics for one rule.

    Precision is ``None`` when there are no predicted positives. Recall is
    ``None`` when there are no labeled positives; these ratios are undefined,
    rather than silently reported as perfect or zero performance.
    """

    rule: str
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float | None
    recall: float | None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys so fixture meaning is unambiguous."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key in labeled fixture")
        result[key] = value
    return result


def _text(value: object, label: str, maximum: int) -> str:
    """Validate a bounded printable text field without echoing its value."""
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or any(ord(character) < 32 or ord(character) == 127
                   for character in value)):
        raise ValueError(f"{label} must be printable bounded text")
    return value


def _event(value: object) -> AuthEvent:
    """Build one strictly validated normalized event from JSON data."""
    if not isinstance(value, Mapping) or set(value) != _EVENT_FIELDS:
        raise ValueError("Each event must contain exactly the normalized fields")
    event_id = _text(value["event_id"], "Event identifier", 128)
    timestamp = _text(value["timestamp"], "Event timestamp", 64)
    try:
        stamp = datetime.fromisoformat(timestamp)
        if stamp.utcoffset() is None:
            raise ValueError("missing timezone")
        address = str(ip_address(_text(value["source_ip"], "Source address", 45)))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Event timestamp and source address must be valid") from exc
    port = value["source_port"]
    if type(port) is not int or not 1 <= port <= 65_535:
        raise ValueError("Source port must be an integer from 1 through 65535")
    outcome = _text(value["outcome"], "Event outcome", 16)
    method = _text(value["method"], "Authentication method", 32)
    if outcome not in {"failure", "success"}:
        raise ValueError("Event outcome is unsupported")
    if method not in {"password", "publickey"}:
        raise ValueError("Authentication method is unsupported")
    return AuthEvent(
        event_id, stamp.isoformat(), _text(value["host"], "Host", 255),
        _text(value["username"], "Username", 255), address, port,
        outcome, method,
    )


def load_labeled_cases(path: Path) -> tuple[LabeledCase, ...]:
    """Read a bounded versioned JSON fixture without exposing its contents."""
    if not isinstance(path, Path):
        raise ValueError("Fixture path must be a pathlib.Path")
    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_FIXTURE_BYTES + 1)
    except OSError as exc:
        raise ValueError("Unable to read labeled fixture") from exc
    if len(payload) > MAX_FIXTURE_BYTES:
        raise ValueError("Labeled fixture exceeds 262144 bytes")
    try:
        document = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("non-finite number")
            ),
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("Invalid labeled fixture JSON") from exc
    if (not isinstance(document, Mapping)
            or set(document) != {"schema_version", "cases"}
            or document["schema_version"] != 1
            or not isinstance(document["cases"], list)):
        raise ValueError("Labeled fixture must use schema version 1")
    if not 1 <= len(document["cases"]) <= MAX_CASES:
        raise ValueError("Labeled fixture must contain 1 through 100 cases")

    cases: list[LabeledCase] = []
    seen_ids: set[str] = set()
    for raw_case in document["cases"]:
        if (not isinstance(raw_case, Mapping)
                or set(raw_case) != {"case_id", "events", "expected_rules"}):
            raise ValueError("Each case must contain exactly the labeled fields")
        case_id = _text(raw_case["case_id"], "Case identifier", 64)
        if case_id in seen_ids:
            raise ValueError("Case identifiers must be unique")
        seen_ids.add(case_id)
        raw_events = raw_case["events"]
        raw_rules = raw_case["expected_rules"]
        if (not isinstance(raw_events, list)
                or len(raw_events) > MAX_CASE_EVENTS):
            raise ValueError("A case may contain at most 1000 events")
        if (not isinstance(raw_rules, list)
                or any(not isinstance(rule, str) or rule not in RULES
                       for rule in raw_rules)
                or len(raw_rules) != len(set(raw_rules))):
            raise ValueError("Expected rules must be unique supported rule names")
        cases.append(LabeledCase(
            case_id, tuple(_event(item) for item in raw_events),
            frozenset(raw_rules),
        ))
    return tuple(cases)


def evaluate_rules(
    cases: Iterable[LabeledCase], config: DetectionConfig | None = None,
) -> tuple[RuleMetrics, ...]:
    """Run supported rules and calculate per-rule precision and recall."""
    policy = DetectionConfig() if config is None else config
    if not isinstance(policy, DetectionConfig):
        raise ValueError("Evaluation requires a validated DetectionConfig")
    batch = list(islice(cases, MAX_CASES + 1))
    if not batch or len(batch) > MAX_CASES:
        raise ValueError("Evaluation requires 1 through 100 labeled cases")
    if any(not isinstance(case, LabeledCase) for case in batch):
        raise ValueError("Evaluation requires LabeledCase records")
    if len({case.case_id for case in batch}) != len(batch):
        raise ValueError("Case identifiers must be unique")

    counts = {rule: [0, 0, 0, 0] for rule in RULES}
    for case in batch:
        predicted = {
            "failure_burst": bool(detect_failure_bursts(case.events, policy)),
            "distributed_account_attempt": bool(
                detect_distributed_account_attempts(case.events, policy)
            ),
        }
        for rule in RULES:
            expected = rule in case.expected_rules
            index = 0 if predicted[rule] and expected else (
                1 if predicted[rule] else 2 if expected else 3
            )
            counts[rule][index] += 1

    metrics: list[RuleMetrics] = []
    for rule in RULES:
        true_positive, false_positive, false_negative, true_negative = counts[rule]
        predicted_positive = true_positive + false_positive
        labeled_positive = true_positive + false_negative
        metrics.append(RuleMetrics(
            rule, true_positive, false_positive, false_negative, true_negative,
            true_positive / predicted_positive if predicted_positive else None,
            true_positive / labeled_positive if labeled_positive else None,
        ))
    return tuple(metrics)
