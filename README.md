# TraceGuard

TraceGuard is an evidence-first SSH authentication log triage CLI. It parses
bounded local logs, detects deterministic review candidates, persists exact
source-position evidence in SQLite, and exports versioned JSON reports.

Optional local Ollama explanations annotate findings only after identifiers are
sanitized. They never replace detector output. The default workflow is fully
offline and has no third-party runtime dependencies.

## Requirements

- Python 3.11 or newer
- Windows or Linux
- Ollama only when local AI explanations are explicitly requested

## Install from a clean environment

Clone the repository, enter its directory, and create an isolated environment.

Linux:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
traceguard --help
```

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python -m pip install .
.\.venv\Scripts\traceguard --help
```

The package installs one `traceguard` console command. Installation needs a
Python package builder, but the installed application has no runtime package
dependencies and does not download a model.

## Run the synthetic demonstration

The included fixture uses documentation-only network addresses and contains no
private authentication data.

```sh
python -c "from pathlib import Path; Path('reports').mkdir(exist_ok=True)"
traceguard pipeline examples/auth.log --year 2026 --failure-threshold 2 --database traceguard.sqlite3 --report reports/traceguard.json --offline
```

Expected stdout is a bounded summary containing three parsed occurrences and
two evidence-linked findings. The SQLite database and report are local runtime
artifacts and are ignored by Git.

## Commands

Normalize supported SSH authentication records as JSON Lines:

```sh
traceguard examples/auth.log --year 2026 --utc-offset-minutes 480
```

Emit deterministic findings without persistence:

```sh
traceguard triage examples/auth.log --year 2026 --failure-threshold 2
```

Run the persistent evidence pipeline:

```sh
traceguard pipeline LOG --year YEAR --database DATABASE --report REPORT
```

Use `--ai-model MODEL` with `triage` or `pipeline` to opt in to local Ollama
annotations. Add `--offline` to guarantee that no model request is attempted.
Only literal loopback Ollama endpoints are accepted.

## Security model

- Input is parsed as data and is never executed.
- Files, event batches, display fields, model requests, and responses are
  bounded.
- Reports link findings to exact stored occurrences instead of trusting model
  citations.
- AI receives report-local aliases rather than raw hosts, usernames, IP
  addresses, paths, or log lines.
- Model output must match a strict schema and remains an annotation.
- Generated databases and reports contain security metadata and should be
  handled as private data.

A finding is a review candidate, not proof of compromise. Thresholds may flag
legitimate retries, automation, or shared infrastructure. Operators should
validate the linked evidence and surrounding system context.

## Supported input

TraceGuard supports English-month legacy syslog timestamps and strict
`YYYY-MM-DDTHH:MM:SS±HH:MM` timestamps from `sshd[PID]` records containing
failed or accepted password/public-key authentication. Unsupported and malformed
records are counted without echoing their private contents.

Legacy syslog has no year or timezone, so callers must provide `--year` and, if
needed, `--utc-offset-minutes`. Automatic daylight-saving inference and Windows
Event Log input are outside the current scope.

## Development

Run the deterministic suite from the repository root:

```sh
python -m unittest discover -s tests -v
```

CI runs the same command on Python 3.13 for Windows and Linux with read-only
repository permissions. Tests use synthetic fixtures and mocked AI transport;
they require no secrets, running model, or external service.

## License

TraceGuard is distributed under the [MIT License](LICENSE).
