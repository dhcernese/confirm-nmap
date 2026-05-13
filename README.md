# confirm-nmap
just to compare with SG nmap

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

Override selected settings from CLI (JSON remains the base config):

```powershell
python scan_and_get.py --cidr 10.152.161.0/24 --settings settings.json --path "/xmldata?item=All" --nmap-args "-sn"
```

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

### Notes

- HTTPS requests are executed with certificate verification disabled to support self-signed certs.
- XML namespaces are stripped before field lookup, making simple XPaths like `.//SerialNumber` work across namespace variations.
- CSV output always includes `ip`; when `--debug` is enabled it also includes `url`, `error`, `xml_parse_error`, and `redfish_error`.
- CSV output includes one column per configured `xml_fields.name` plus one column per configured `redfish.fields.name`.
- When Nmap output contains port results, the script only targets hosts that show an open port in grepable output. This prevents `-Pn` scans from blindly hitting every IP in a large CIDR.
- When `-Pn` is present in the configured Nmap arguments, the script refuses to trust grepable `Status: Up` lines unless `Ports:` output is also present. This stops unsafe fallbacks caused by mangled shell quoting.
- The default safety limit is `2048` HTTP targets. Raise it only when your Nmap arguments are already selective.
- `--dry-run` writes only discovered targets (`ip`, `url`) to CSV and skips all HTTP requests.
- `--progress-every` controls how often completion progress is printed during the HTTP phase.
