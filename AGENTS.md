# AGENTS.md

## Purpose
This repository provides a Windows-friendly Python workflow to:
- Discover candidate hosts with Nmap.
- Optionally issue HTTP(S) GET requests per discovered host.
- Parse XML responses using configurable XPath rules.
- Export discovery and result data to CSV.

Primary script: `scan_and_get.py`.
Equivalent dependency-free Go port: `cmd/scan-and-get` (standard library only).

## Repository File Map
- `scan_and_get.py`: Main CLI and runtime logic (arg parsing, Nmap discovery, HTTP fetch, XML parse, CSV write).
- `go.mod`: Go module definition (no third-party requirements).
- `cmd/scan-and-get/main.go`: Go CLI entrypoint, flag parsing, and orchestration.
- `cmd/scan-and-get/settings.go`: Go settings load/validation mirroring `load_settings`.
- `cmd/scan-and-get/nmap.go`: Go Nmap discovery, arg resolution, and grepable output parsing.
- `cmd/scan-and-get/xmltree.go`: Go XML parsing, namespace stripping, and XML field extraction.
- `cmd/scan-and-get/xpath.go`: Minimal ElementTree-compatible XPath subset evaluator.
- `cmd/scan-and-get/redfish.go`: Go JSON pointer resolution and Redfish enrichment requests.
- `cmd/scan-and-get/fetch.go`: Go concurrent HTTP fetch layer (TLS verification disabled for self-signed BMC certs).
- `cmd/scan-and-get/csvout.go`: Go CSV writers for discovery and full results.
- `tests/compare-python-go.ps1`: Cross-implementation harness; runs identical CLI cases through both implementations and compares exit codes and CSV output.
- `tests/mock_bmc_server.py`: Local iLO/Redfish stand-in used by the harness `-Live` mode.
- `settings.json`: Local runtime configuration used by default.
- `settings.example.json`: Template config for new environments.
- `nmap-ilo443.args.txt`: Default Nmap argument set referenced by settings.
- `requirements.txt`: Python dependencies.
- `README.md`: User-facing setup and usage docs.
- `.gitignore`: Exclusions for generated artifacts and local files.

Generated/working artifacts (do not treat as source of truth):
- `discovery.csv`, `smoke_discovery.csv`, `results.csv`, `results.xlsx`, `~$results.xlsx`.

## Runtime Design Constraints
1. Keep `scan_and_get.py` executable as a CLI script.
2. Preserve an entrypoint structure equivalent to:
   - `parse_args()`
   - `main()`
   - `if __name__ == "__main__": raise SystemExit(main())`
3. Helper functions should avoid hidden global dependencies.
   - Pass state explicitly (for example `debug` flags) instead of relying on module globals.
4. Discovery must remain safety-aware for large CIDRs.
   - Do not remove host count limits without explicit user intent.
5. Keep dry-run behavior stable.
   - `--dry-run` must skip HTTP requests.
   - It must still write discovery CSV (`ip`, `url`).

## Nmap and Discovery Conventions
- The script supports args from settings and from `--nmap-args-file`.
- Current operational assumption is selective discovery via open-port grepable output.
- If `-Pn` is used, ensure parsing logic does not regress into blindly accepting all hosts.
- Avoid changing regex patterns unless tests/manual validation confirm no behavior regression.

## CSV Output Conventions
- Discovery CSV is separate from full result CSV.
- Full result CSV should contain configured XML fields for all hosts processed.
- Debug-only columns should be controlled by explicit flags and should not silently appear in normal mode.

## Error Handling Conventions
- Use clear, actionable stderr messages for fatal issues.
- Continue per-host processing where safe (for request failures), and record errors in output.
- Avoid broad exception swallowing that hides scan/runtime failures.

## Editing Rules for Future Agents
1. Make minimal, targeted changes.
2. If broader changes would meaningfully improve clarity, interfaces, or architecture, do not apply them silently. Describe the proposed refactor, its scope and risk, and let the user choose whether to take it.
3. Do not remove or relocate the CLI entrypoint unless explicitly requested.
4. Keep `scan_and_get.py` and `cmd/scan-and-get` behaviorally equivalent: flags, defaults, console messages, and CSV columns must stay in sync.
5. Keep the Go port dependency-free; do not add `require` entries to `go.mod`.
6. After edits, run a smoke test:
   - `pwsh tests/compare-python-go.ps1 -Live` must report zero failures.
   - Small CIDR dry-run (example `/30`) to verify CLI execution and CSV write.
7. Validate no syntax or static-analysis errors remain (`go vet ./...` for the Go port).
8. After all tests pass, re-check the VS Code Problems panel and resolve any new diagnostics introduced by the change.
   - Treat a diagnostic as real only after confirming it against a fresh analyzer run; language-server results can be stale after an edit.
   - PowerShell: `Invoke-ScriptAnalyzer -Path <file>` (module ships with the PowerShell extension under `~/.vscode/extensions/ms-vscode.powershell-*/modules/PSScriptAnalyzer`). Clear stale results with the `PowerShell.RestartSession` command.
   - Python: rely on Pylance diagnostics; re-open or reload the file if results look stale.
   - Go: `go vet ./...`.
   - Do not silence a diagnostic with a suppression unless the underlying pattern is intentional, and say why.
9. Update `README.md` when behavior, flags, or output columns change.

## Recommended Smoke Tests
- Cross-implementation parity (preferred after any change to either implementation):
  - `pwsh tests/compare-python-go.ps1`
  - `pwsh tests/compare-python-go.ps1 -Live` (also compares real XML/Redfish field values)
- Dry-run small range:
  - `python scan_and_get.py --cidr 10.152.161.100/30 --settings settings.json --dry-run --csv-output smoke_discovery.csv`
  - `go build -o scan_and_get.exe ./cmd/scan-and-get; .\scan_and_get.exe --cidr 10.152.161.100/30 --settings settings.json --dry-run --csv-output smoke_discovery.csv`
- Optional full run against a constrained range when safe:
  - `python scan_and_get.py --cidr <small-cidr> --settings settings.json --csv-output results.csv`

## Documentation Discipline
When adding new flags or changing defaults:
- Update CLI docs in `README.md`.
- Document default behavior and any safety implications.
- Keep examples copy/paste-ready for PowerShell on Windows.
