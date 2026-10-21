# TraceGuard

Evidence-first SSH authentication log triage, with local AI explanations planned after deterministic detection works.

## End-to-end CLI MVP

TraceGuard can now parse one local SSH log, detect review candidates, persist
source-position evidence in SQLite, and atomically export a versioned JSON
report with one command:

```sh
python -m traceguard pipeline examples/auth.log --year 2026 --failure-threshold 2 --database traceguard.sqlite3 --report reports/traceguard.json
```

Create the `reports` directory first. Repeating the command for unchanged input
is idempotent: identical log lines remain distinct occurrences, while existing
source positions and findings are not duplicated. The default is fully offline.
Local Ollama annotations are opt-in with `--ai-model MODEL`; `--offline` always
disables model requests. AI receives sanitized evidence only and never changes
detector results. Reports and SQLite databases contain normalized identifiers
and must be treated as private. Do not commit real logs, databases, or reports.

The command prints only bounded counts to stdout. The report contains its schema
version, SHA-256 source digest, detection configuration, exact evidence links,
and explanation statuses. A source digest records provenance, not authenticity.

## Day 1: normalized authentication events

Commit: `feat(parser): normalize SSH authentication events with a tested CLI`

Requirements: Python 3.11 or newer. No third-party dependencies, Ollama, administrator privileges, or network access are required today.

From this folder, verify with one command:

```sh
python -m unittest discover -s tests -v
```

Run the synthetic demonstration:

```sh
python -m traceguard examples/auth.log --year 2026 --utc-offset-minutes 480
```

Standard output contains three JSON event records. Standard error contains `parsed=3 skipped=1`. Use the UTC offset of the system that produced the log, not necessarily your computer's current offset. For UTC logs omit the offset option.

## Exact deliverables

- `traceguard/__init__.py`: package definition.
- `traceguard/parser.py`: immutable event model, bounded record parsing, IP/port validation, UTC normalization, content fingerprints.
- `traceguard/__main__.py`: streaming JSON Lines CLI and explicit error exit status.
- `tests/test_parser.py`: nine regression and CLI tests.
- `examples/auth.log`: synthetic fixture using documentation-only addresses.
- `.gitignore`: excludes runtime state, private logs, and generated reports.
- `README.md` and `ROADMAP.md`: operating instructions and functional development plan.

The complete implementation is included in these files; there are no placeholder functions or TODO blocks.

## Supported input and limitations

Day 1 supports legacy English-month syslog lines from `sshd[PID]` containing Failed/Accepted password or publickey authentication records, optionally with a public-key detail suffix. Other records are skipped and counted. RFC3339/journald/Windows logs are not supported yet.

Logs omit year and timezone, so you supply them. A file spanning a year boundary must currently be split by year. Daylight-saving changes require appropriate timestamp context; automatic inference is not implemented. Invalid UTF-8 and file errors return exit code 2; earlier output can exist if an error occurs midway through a file. Successful parsing, even with zero supported records, returns 0 and reports counts.

`event_id` is a content fingerprint, not an occurrence ID. Identical records may represent distinct occurrences. The planned persistence layer must preserve source identity and line position rather than silently deduplicating by fingerprint.

Run against trusted local files. Input is never executed. Parsed output includes usernames and IP addresses: use only synthetic data in public commits. The ignore file is convenience, not a privacy control.

## First commit and push

Create an empty GitHub repository named `traceguard` first, without an initial README. Extract this starter and open a terminal inside its `traceguard` folder. Replace `YOUR_USERNAME` below. The test gate prevents committing or pushing when verification fails.

PowerShell:

```powershell
python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Verification failed' }
git init -b main
if ($LASTEXITCODE -ne 0) { throw 'Git initialization failed' }
git add -- .gitignore README.md ROADMAP.md traceguard tests examples
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
git commit -m "feat(parser): normalize SSH authentication events with a tested CLI"
if ($LASTEXITCODE -ne 0) { throw 'Commit failed' }
git remote add origin https://github.com/YOUR_USERNAME/traceguard.git
if ($LASTEXITCODE -ne 0) { throw 'Remote setup failed' }
git push -u origin main
if ($LASTEXITCODE -ne 0) { throw 'Push failed' }
```

Bash:

```bash
(
set -e
python -m unittest discover -s tests -v
git init -b main
git add -- .gitignore README.md ROADMAP.md traceguard tests examples
git commit -m "feat(parser): normalize SSH authentication events with a tested CLI"
git remote add origin https://github.com/YOUR_USERNAME/traceguard.git
git push -u origin main
)
```

If you already have a repository, use its existing checkout and remote; skip initialization and remote creation. If Linux provides only `python3`, substitute it for `python` in these commands. GitHub authentication and your Git author identity must already be configured. No credentials are included in this starter.
