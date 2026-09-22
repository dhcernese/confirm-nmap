# confirm-nmap
just to compare with SG nmap

Two interchangeable implementations are provided:

- [scan_and_get.py](scan_and_get.py) — Python version (requires `pip install -r requirements.txt`).
- [cmd/scan-and-get](cmd/scan-and-get) — Go version built only on the standard library (no third-party dependencies). See [Go port](README.md#go-port-no-third-party-dependencies).

## Python Nmap + HTTP GET helper

This repo includes [scan_and_get.py](scan_and_get.py), a Windows-friendly script that:

1. Runs Nmap against a target CIDR.
2. Collects hosts reported as `Up`.
3. Sends an unauthenticated GET request to each host using a URL pattern like:
	`https://<host>/xmldata?item=All`
4. Assumes HTTPS endpoints use self-signed certificates and skips TLS verification.
5. Parses XML response bodies and prints configured field name/value pairs.
6. Writes scan results to a CSV file with headings.
7. Uses concurrent HTTP requests and a safety cap so large CIDR runs do not fan out uncontrollably.
8. Supports dry-run discovery and periodic progress logging for large scans.
9. Can read Nmap arguments from a plain-text file to avoid PowerShell quoting problems.
10. Optionally performs per-host unauthenticated Redfish JSON queries and writes mapped fields as extra CSV columns.
11. Supports a Redfish-only mode that skips XML endpoint requests/parsing and outputs only Redfish columns.

### Requirements

- Python 3.10+
- Nmap installed on Windows (`nmap.exe` in PATH), or pass `--nmap-path`
- Python dependency from [requirements.txt](requirements.txt)
- JSON settings file for XML field extraction (see [settings.example.json](settings.example.json))

Install dependency:

```powershell
pip install -r requirements.txt
```

### Example usage

```powershell
copy settings.example.json settings.json
python scan_and_get.py --cidr 10.152.161.0/24 --settings settings.json
```

The default `settings.json`/`settings.example.json` now point to [nmap-ilo443.args.txt](nmap-ilo443.args.txt), which contains a safer selective scan for large HTTPS inventories:

```text
--unprivileged -Pn -n -p 443 --open --host-timeout 2s
```

Set a custom CSV output path:

```powershell
python scan_and_get.py --cidr 10.152.161.0/24 --settings settings.json --csv-output results.csv
```

For large ranges, override worker count or the safety cap if needed:

```powershell
python scan_and_get.py --cidr 10.152.160.0/20 --settings settings.json --workers 64 --max-targets 2500
```

Preview discovered targets without issuing HTTP requests:

```powershell
python scan_and_get.py --cidr 10.152.160.0/20 --settings settings.json --dry-run --csv-output discovery.csv
```

Test a single host use a `/32` CIDR:

```powershell
python scan_and_get.py --cidr 10.152.161.101/32 --settings settings.json --csv-output single_host_results.csv
```

Single-host dry-run (discovery only):

```powershell
python scan_and_get.py --cidr 10.152.161.101/32 --settings settings.json --dry-run --csv-output single_host_discovery.csv
```

You can also point at an explicit args file from the CLI instead of embedding a quoted string:

```powershell
python scan_and_get.py --cidr 10.152.160.0/20 --settings settings.json --nmap-args-file .\nmap-ilo443.args.txt --dry-run --csv-output discovery.csv
```

Produce only Redfish output columns (no XML request/parsing):

```powershell
python scan_and_get.py --cidr 10.152.161.0/24 --settings settings.json --redfish-only --csv-output redfish_only_results.csv
```

Override selected settings from CLI (JSON remains the base config):

```powershell
python scan_and_get.py --cidr 10.152.161.0/24 --settings settings.json --path "/xmldata?item=All" --nmap-args "-sn"
```

## Go port (no third-party dependencies)

[cmd/scan-and-get](cmd/scan-and-get) contains a functionally equivalent Go implementation that uses only the Go standard library. It reads the same `settings.json`, accepts the same flags, and produces the same console output and CSV columns as [scan_and_get.py](scan_and_get.py).

Build it once and run the resulting single executable — no Python, no `pip install`:

```powershell
go build -o scan_and_get.exe ./cmd/scan-and-get
.\scan_and_get.exe --cidr 10.152.161.0/24 --settings settings.json --csv-output results.csv
```

Every Python flag is supported with the same name and default:

```powershell
.\scan_and_get.exe --cidr 10.152.161.0/24 --settings settings.json --dry-run --csv-output discovery.csv
.\scan_and_get.exe --cidr 10.152.161.0/24 --settings settings.json --redfish-only --csv-output redfish_only_results.csv
.\scan_and_get.exe --cidr 10.152.160.0/20 --settings settings.json --workers 64 --max-targets 2500
.\scan_and_get.exe --cidr 10.152.161.101/32 --settings settings.json --scheme http --timeout 2 --debug
```

Cross-compile for another platform from Windows:

```powershell
$env:GOOS = "linux"; $env:GOARCH = "amd64"; go build -o scan-and-get ./cmd/scan-and-get
```

Go port notes:

- Nmap is still required for host discovery; only the Python/`pip` dependencies are removed.
- The XML field lookup implements the ElementTree XPath subset used by this repo: relative paths, `//` descendant steps, `*` wildcards, `..` parent steps, and the predicates `[n]`, `[last()]`, `[@attr]`, `[@attr='value']`, `[tag]`, `[tag='value']`, and `[.='value']`.
- XML namespaces are stripped during parsing, matching the Python behavior.
- Error text in the `--debug` columns (`error`, `redfish_error`, `xml_parse_error`) comes from the Go standard library, so the wording differs from `requests`/ElementTree. Exit codes, discovered hosts, and all field values match.
- Numbers from Redfish JSON keep their original literal form (for example `1.6.0` stays a string, `2` stays `2`).
- Build output (`scan_and_get.exe`) is git-ignored.

### Cross-implementation test harness

[tests/compare-python-go.ps1](tests/compare-python-go.ps1) runs the same CLI cases through both implementations with identical arguments and fails if exit codes or CSV output diverge. It covers argument parsing, settings validation, Nmap failure and safety paths, discovery, the `--max-targets` cap, and every output mode (`--debug`, `--no-redfish`, `--redfish-only`).

```powershell
pwsh tests/compare-python-go.ps1
```

Add `-Live` to also start [tests/mock_bmc_server.py](tests/mock_bmc_server.py) on `127.0.0.1:80` and compare real extracted XML and Redfish values rather than connection failures:

```powershell
pwsh tests/compare-python-go.ps1 -Live
```

Harness notes:

- All discovery cases target `127.0.0.1` (plus `192.0.2.1` for the no-hosts path); override with `-Cidr` only for a range you are authorized to scan.
- The harness builds the binary first; pass `-SkipBuild` to test an existing `scan_and_get.exe`.
- Fixtures and CSV output go to a temp directory that is deleted unless `-KeepArtifacts` is passed.
- Cases that surface library error text compare CSV headers only; all other cases compare every row.
- `-Live` needs `127.0.0.1:80` to be free.

### Settings format

`xml_fields` must contain objects with:

- `name`: display label in output
- `xpath`: ElementTree XPath to locate the value
- `xpaths` (optional): ordered fallback XPath list; first matching value is used
- `mode` (optional): `first` (default) or `all` for repeated elements
- `separator` (optional): join string used when `mode` is `all`
- `exclude_values` (optional): values to suppress (for example `N/A`, `Unknown`)

Example field output per host:

- `DeviceName: plc-west-1`
- `SerialNumber: ABC12345`
- `FirmwareVersion: 2.4.1`

If a field is not found, output shows `<missing>`. If a value is empty, output shows `<empty>`.

For repeated XML nodes (for example multiple NIC entries), use `"mode": "all"`.

Optional Redfish enrichment is configured under `redfish.fields`.

Each `redfish.fields` item supports:

- `name`: output CSV column name
- `request_path` or `path`: Redfish endpoint path to request on each host
- `request_paths` or `paths` (optional): ordered fallback paths
- `json_pointer` or `pointer`: JSON pointer to extract value
- `json_pointers` or `pointers` (optional): ordered fallback pointers
- `mode` (optional): `first` (default) or `all`
- `separator` (optional): join string used when `mode` is `all`
- `exclude_values` (optional): values to suppress

Example Redfish fields include `SerialNumber`, `Managers`, `Model`, and `HostName`.

### Add more Redfish paths and fields

Use this workflow when you want additional CSV columns from unauthenticated Redfish responses.

1. Find the Redfish endpoint path that contains the data (for example `/redfish/v1/Systems/1`).
2. Find the JSON key path in that payload (for example `/BiosVersion`).
3. Add a new object in `redfish.fields` with a unique `name`.
4. Re-run the script; the new `name` becomes a new CSV column.

Add one new field from an existing endpoint:

```json
{
	"name": "BiosVersion",
	"request_paths": [
		"/redfish/v1/Systems/1",
		"/redfish/v1/Systems/System.Embedded.1"
	],
	"json_pointers": [
		"/BiosVersion"
	]
}
```

Add one field with multiple endpoint fallbacks and multiple pointer fallbacks:

```json
{
	"name": "PowerState",
	"request_paths": [
		"/redfish/v1/Systems/1",
		"/redfish/v1/Systems/System.Embedded.1",
		"/redfish/v1/Chassis/1"
	],
	"json_pointers": [
		"/PowerState",
		"/Status/State"
	]
}
```

Collect all values from an array field into one CSV column:

```json
{
	"name": "IPv4Addresses",
	"request_paths": [
		"/redfish/v1/Managers/1/EthernetInterfaces/1"
	],
	"json_pointers": [
		"/IPv4Addresses"
	],
	"mode": "all",
	"separator": " | "
}
```

Tips:

- `request_paths` and `json_pointers` are evaluated in order; first valid value wins when `mode` is `first`.
- You can also use singular keys `request_path` and `json_pointer` for simple mappings.
- Keep `name` values unique; duplicate names will create ambiguous columns.
- If your target returns different Redfish object IDs, add all known path variants in `request_paths`.
- For values you want to ignore (for example `N/A`), use `exclude_values`.

Notes:

- The script requests each unique configured Redfish path once per host and reuses the JSON payload across fields.
- JSON pointers must use slash-separated segments (for example `/SerialNumber` or `/Managers/@odata.id`).
- Set `redfish.enabled` to `false` to disable Redfish enrichment without removing config.
- If your environment returns HTTP 401 for some Redfish paths, keep those mappings in `redfish.disabled_fields_http_401` so they stay documented but inactive.
- To re-enable a previously disabled mapping, move it from `redfish.disabled_fields_http_401` back into `redfish.fields` after validating unauthenticated access (or after adding authentication support in a future script update).

Redfish settings sections used in this repository:

- `redfish.fields`: active curated mappings used at runtime for CSV output. See [How discovered unauth fields were found](README.md#how-discovered-unauth-fields-were-found).
- `redfish.all_discovered_unauth_fields_reference`: reference inventory of all JSON pointers discovered from unauthenticated crawling (currently rooted at `/redfish/v1`); this block is documentation and is not read by the script. See [How discovered unauth fields were found](README.md#how-discovered-unauth-fields-were-found).
- `redfish.disabled_fields_http_401`: known mappings that returned unauthorized responses in testing; this block is also documentation and is not read by the script. See [How discovered unauth fields were found](README.md#how-discovered-unauth-fields-were-found).

### How discovered unauth fields were found

The discovered unauth fields were found by unauthenticated Redfish endpoint inspection, then captured as a reference list.

What happened in this repository:

1. We queried Redfish without credentials (starting at `/redfish/v1`) and observed which JSON keys/pointers were returned.
2. We recorded those discovered pointers in the `all_discovered_unauth_fields_reference` block in `settings.example.json` and `settings.json`.
3. That reference block is documentation only, not active extraction logic. Runtime extraction reads `redfish.fields` (plus `xml_fields`) for output.
4. During execution, the script requests each configured `redfish.fields` request path, resolves configured JSON pointers, and writes values to CSV.

So, "discovered unauth fields" means fields previously observed to be accessible without authentication, while only the curated subset in `redfish.fields` is emitted as output columns.

Related files:

- [settings.example.json](settings.example.json)
- [settings.json](settings.json)
- [scan_and_get.py](scan_and_get.py)
- [cmd/scan-and-get](cmd/scan-and-get)
- [README.md](README.md)

### Notes

- HTTPS requests are executed with certificate verification disabled to support self-signed certs.
- XML namespaces are stripped before field lookup, making simple XPaths like `.//SerialNumber` work across namespace variations.
- CSV output always includes `ip`; when `--debug` is enabled it also includes `url`, `error`, `xml_parse_error`, and `redfish_error`.
- CSV output includes one column per configured `xml_fields.name` plus one column per configured `redfish.fields.name`.
- `--redfish-only` skips requests to `request.path` (default `/xmldata?item=All`) and writes only `ip` plus configured `redfish.fields.name` columns.
- When Nmap output contains port results, the script only targets hosts that show an open port in grepable output. This prevents `-Pn` scans from blindly hitting every IP in a large CIDR.
- When `-Pn` is present in the configured Nmap arguments, the script refuses to trust grepable `Status: Up` lines unless `Ports:` output is also present. This stops unsafe fallbacks caused by mangled shell quoting.
- The default safety limit is `2048` HTTP targets. Raise it only when your Nmap arguments are already selective.
- `--dry-run` writes only discovered targets (`ip`, `url`) to CSV and skips all HTTP requests.
- `--progress-every` controls how often completion progress is printed during the HTTP phase.
