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

### Notes

- HTTPS requests are executed with certificate verification disabled to support self-signed certs.
- XML namespaces are stripped before field lookup, making simple XPaths like `.//SerialNumber` work across namespace variations.
- CSV output includes base columns (`ip`, `url`, `request_ok`, `http_status`, `error`, `xml_parse_error`) plus one column per configured `xml_fields.name`.
- When Nmap output contains port results, the script only targets hosts that show an open port in grepable output. This prevents `-Pn` scans from blindly hitting every IP in a large CIDR.
- When `-Pn` is present in the configured Nmap arguments, the script refuses to trust grepable `Status: Up` lines unless `Ports:` output is also present. This stops unsafe fallbacks caused by mangled shell quoting.
- The default safety limit is `2048` HTTP targets. Raise it only when your Nmap arguments are already selective.
- `--dry-run` writes only discovered targets (`ip`, `url`) to CSV and skips all HTTP requests.
- `--progress-every` controls how often completion progress is printed during the HTTP phase.
*** Add File: d:\GitHub\AI\confirm-nmap\nmap-ilo443.args.txt
--unprivileged -Pn -n -p 443 --open --host-timeout 2s
