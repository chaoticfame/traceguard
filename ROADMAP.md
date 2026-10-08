# TraceGuard: 21 functional daily commits

## Development contract

Each day: 5 minutes to review the previous implementation, 15–30 minutes for one bounded behavior, and 5–10 minutes for tests and review. Time estimates exclude first-time tool setup, model downloads, and unfamiliar debugging. If a task overruns, split off a tested vertical slice; never manufacture an empty commit to fill a date.

This is a planning roadmap, not 20 unimplemented daily code prompts. Day 1 is implemented in this starter. Each subsequent daily handoff should include its complete code, exact changed files, one verification command, and a test-gated commit/push script against the current repository. Do not commit future days before implementing them.

Day 1–14 produce a CLI MVP. Day 15–21 harden ingestion, evaluation, and distribution. AI is optional: deterministic findings remain available without Ollama. No autonomous remediation or shell execution is planned.

## Daily milestones

All days use the single verification command `python -m unittest discover -s tests -v`. Each named test module is part of that discovery run. Files listed below are additions or updates; existing modules are updated only where integration needs them.

| Day | Conventional commit title | Exact planned files | Testable acceptance criterion |
| --- | --- | --- | --- |
| 1 | `feat(parser): normalize SSH authentication events with a tested CLI` | `traceguard/{__init__,parser,__main__}.py`, `tests/test_parser.py`, `examples/auth.log`, `.gitignore`, `README.md`, `ROADMAP.md` | Parse three fixture events; reject malformed IP/port/date and oversized input. |
| 2 | `feat(config): validate detection thresholds and time windows` | `traceguard/config.py`, `tests/test_config.py` | Typed stdlib configuration rejects invalid thresholds, durations, and unknown keys. |
| 3 | `feat(detector): identify bounded login failure bursts` | `traceguard/detector.py`, `tests/test_detector.py` | Sorted events trigger at the exact threshold; isolated failures do not; window-boundary behavior is explicit. |
| 4 | `feat(detector): correlate success after login failure bursts` | `traceguard/detector.py`, `tests/test_detector.py` | Correlate only the same source/account inside the configured follow-up window; include supporting fingerprints. |
| 5 | `feat(cli): emit deterministic triage findings` | `traceguard/__main__.py`, `tests/test_triage_cli.py` | A new triage subcommand runs detection on the fixture and returns stable JSON. Preserve the existing parse interface. |
| 6 | `feat(storage): persist source-aware event occurrences` | `traceguard/storage.py`, `tests/test_storage.py` | Transactionally store source digest plus line position; repeated imports are idempotent while identical lines at different positions survive. |
| 7 | `feat(storage): persist findings with evidence references` | `traceguard/storage.py`, `tests/test_storage.py` | Findings reference stored occurrences; failures roll back; orphan evidence is rejected. |
| 8 | `feat(privacy): alias identifiers in AI evidence payloads` | `traceguard/privacy.py`, `tests/test_privacy.py` | Replace IP, host, and username fields with per-report stable aliases. Do not send raw log text or private mappings. |
| 9 | `feat(ai): add a timeout-bound local Ollama transport` | `traceguard/ollama_client.py`, `tests/test_ollama_client.py` | Use stdlib HTTP, a loopback-only endpoint, timeout, response-size limit, and predictable offline errors; mock transport in tests. |
| 10 | `feat(ai): validate structured finding explanations` | `traceguard/explanations.py`, `tests/test_explanations.py` | Validate required fields, lengths, and evidence IDs; reject unknown references. No model output becomes a detector decision. |
| 11 | `feat(ai): explain sanitized findings with offline fallback` | `traceguard/explanations.py`, `traceguard/__main__.py`, `tests/test_ai_cli.py` | Optional AI flag sends only sanitized evidence; unavailable or invalid AI leaves deterministic findings intact with an explicit status. |
| 12 | `feat(report): export versioned evidence-linked JSON reports` | `traceguard/report.py`, `tests/test_report.py` | Produce a versioned report envelope with source digest, configuration, findings, and explanation status. |
| 13 | `feat(report): render terminal-safe finding summaries` | `traceguard/render.py`, `tests/test_render.py` | Escape control characters, bound display lengths, and show evidence/timestamps without terminal escape injection. |
| 14 | `feat(cli): integrate parsing detection storage and reports` | `traceguard/__main__.py`, `tests/test_pipeline.py`, `README.md` | One command processes the fixture, stores evidence, and exports a report; rerunning preserves occurrence counts. |
| 15 | `feat(ingest): cap batch size and report rejected records` | `traceguard/ingest.py`, `traceguard/__main__.py`, `tests/test_ingest.py` | Apply event/file limits and emit rejection counts without logging rejected private content. |
| 16 | `feat(parser): support offset-aware ISO syslog timestamps` | `traceguard/parser.py`, `tests/test_parser.py`, `examples/auth-iso.log` | Parse one documented ISO timestamp format and test offset/year rollover boundaries. |
| 17 | `feat(detector): report distributed attempts against one account` | `traceguard/detector.py`, `traceguard/config.py`, `tests/test_detector.py` | Flag one account targeted by a configurable number of distinct sources; include exact evidence. |
| 18 | `feat(evaluation): measure rules against labeled synthetic cases` | `traceguard/evaluation.py`, `tests/test_evaluation.py`, `examples/labeled_cases.json` | Compute precision/recall on a small labeled fixture set with explicit empty-denominator handling. |
| 19 | `test(ai): verify explanations preserve evidence under hostile inputs` | `tests/test_ai_adversarial.py`, `traceguard/explanations.py` | Mock malicious/irrelevant/oversized model responses and verify rejection and fallback. This checks enforcement, not universal prompt-injection immunity. |
| 20 | `ci(test): verify TraceGuard on Windows and Linux` | `.github/workflows/tests.yml` | Run the complete deterministic suite in a two-OS matrix with read-only workflow permissions; no model downloads or secrets. |
| 21 | `feat(package): distribute an installable TraceGuard CLI` | `pyproject.toml`, `traceguard/__main__.py`, `tests/test_entrypoint.py`, `README.md`, `LICENSE` | Add console entry point and packaging metadata; verify the entry point logic and document clean-environment installation with the synthetic demo. Use an OSI license with verified authorship details. |

## Scope discipline

Detection v1 operates on bounded sorted batches. Unsorted events are normalized into chronological order before evaluation, and input order must not change the result. Rules provide review candidates, not proof of account compromise. Document threshold choices and false positives such as legitimate retries.

Daily code review should check timestamp assumptions, limits, error behavior, stable ordering, privacy boundaries, and whether the new tests would catch a realistic regression. Avoid building a UI until the CLI and report contract are useful.

## Later-day commit templates

Replace the title and explicit file list with that day's deliverables. Inspect the staged diff before committing. Do not stage real authentication logs or generated private reports.

PowerShell:

```powershell
python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Verification failed' }
git add -- traceguard/config.py tests/test_config.py
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
git diff --cached --stat
git commit -m "feat(config): validate detection thresholds and time windows"
if ($LASTEXITCODE -ne 0) { throw 'Commit failed' }
git push
if ($LASTEXITCODE -ne 0) { throw 'Push failed' }
```

Bash:

```bash
(
set -e
python -m unittest discover -s tests -v
git add -- traceguard/config.py tests/test_config.py
git diff --cached --stat
git commit -m "feat(config): validate detection thresholds and time windows"
git push
)
```
