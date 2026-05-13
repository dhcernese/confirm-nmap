#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, List
import xml.etree.ElementTree as ET

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning


UP_HOST_PATTERN = re.compile(r"^Host:\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\b.*Status:\s+Up\s*$")
OPEN_PORT_PATTERN = re.compile(r"\b\d+/open/")


@dataclass
class HttpResult:
    ip: str
    url: str
    ok: bool
    status_code: int | None = None
    error: str | None = None
    body_text: str | None = None
    parsed_fields: dict[str, str] | None = None
    parse_error: str | None = None
    redfish_fields: dict[str, str] | None = None
    redfish_error: str | None = None


def resolve_relative_to_settings(settings_path: str, candidate_path: str) -> str:
    if os.path.isabs(candidate_path):
        return candidate_path
    return os.path.join(os.path.dirname(os.path.abspath(settings_path)), candidate_path)


def parse_nmap_args(nmap_args: str) -> list[str]:
    return shlex.split(nmap_args.strip(), posix=False)


def load_nmap_args_from_file(file_path: str) -> str:
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            content = fh.read().strip()
    except OSError as exc:
        raise RuntimeError(f"could not read Nmap args file '{file_path}': {exc}") from exc

    if not content:
        raise RuntimeError(f"Nmap args file '{file_path}' is empty")

    return content


def resolve_nmap_args(
    cli_nmap_args: str | None,
    cli_nmap_args_file: str | None,
    nmap_settings: dict[str, Any],
    settings_path: str,
) -> tuple[str, list[str]]:
    if cli_nmap_args:
        return cli_nmap_args, parse_nmap_args(cli_nmap_args)

    args_file = cli_nmap_args_file
    if not args_file:
        configured_args_file = nmap_settings.get("args_file")
        if isinstance(configured_args_file, str) and configured_args_file:
            args_file = resolve_relative_to_settings(settings_path, configured_args_file)

    if args_file:
        nmap_args = load_nmap_args_from_file(args_file)
        return nmap_args, parse_nmap_args(nmap_args)

    configured_args = nmap_settings.get("args", "-sn")
    if not isinstance(configured_args, str) or not configured_args.strip():
        raise RuntimeError("nmap.args must be a non-empty string when nmap.args_file is not set")

    return configured_args, parse_nmap_args(configured_args)


def find_nmap(explicit_path: str | None) -> str:
    if explicit_path:
        return explicit_path

    path_hit = shutil.which("nmap")
    if path_hit:
        return path_hit

    common_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    for candidate in common_paths:
        if os.path.isfile(candidate):
            return candidate

    raise FileNotFoundError(
        "nmap executable not found. Install Nmap for Windows or pass --nmap-path."
    )


def discover_up_hosts(
    nmap_exe: str,
    cidr: str,
    nmap_args: str,
    nmap_arg_tokens: list[str],
    require_open_port_output: bool,
) -> List[str]:
    cmd = [nmap_exe, *nmap_arg_tokens, cidr, "-oG", "-"]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if completed.returncode != 0:
        raise RuntimeError(
            f"nmap failed with exit code {completed.returncode}:\n{completed.stderr.strip()}"
        )

    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    has_port_output = any(line.startswith("Host:") and "Ports:" in line for line in lines)

    if require_open_port_output and not has_port_output:
        raise RuntimeError(
            "unsafe Nmap discovery output: '-Pn' was requested, but grepable output contains no 'Ports:' lines. "
            "Refusing to trust 'Status: Up' entries because the scan arguments may have been mangled or Nmap did not emit port results."
        )

    hosts: List[str] = []
    seen_hosts: set[str] = set()
    for stripped_line in lines:
        if require_open_port_output:
            if stripped_line.startswith("Host:") and "Ports:" in stripped_line and OPEN_PORT_PATTERN.search(stripped_line):
                host_match = re.match(r"^Host:\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\b", stripped_line)
                if host_match:
                    host_ip = host_match.group("ip")
                    if host_ip not in seen_hosts:
                        seen_hosts.add(host_ip)
                        hosts.append(host_ip)
            continue

        match = UP_HOST_PATTERN.match(stripped_line)
        if match and "Ports:" not in stripped_line and not has_port_output:
            host_ip = match.group("ip")
            if host_ip not in seen_hosts:
                seen_hosts.add(host_ip)
                hosts.append(host_ip)
            continue

        if stripped_line.startswith("Host:") and "Ports:" in stripped_line and OPEN_PORT_PATTERN.search(stripped_line):
            host_match = re.match(r"^Host:\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\b", stripped_line)
            if host_match:
                host_ip = host_match.group("ip")
                if host_ip not in seen_hosts:
                    seen_hosts.add(host_ip)
                    hosts.append(host_ip)

    return hosts


def fallback_host_from_single_cidr(cidr: str) -> str | None:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None

    if network.version != 4:
        return None

    if network.prefixlen != 32:
        return None

    return str(network.network_address)


def load_settings(settings_path: str) -> dict[str, Any]:
    try:
        with open(settings_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise RuntimeError(f"could not read settings file '{settings_path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in settings file '{settings_path}': {exc}") from exc

    if not isinstance(data, dict):
        raise RuntimeError("settings root must be a JSON object")

    xml_fields = data.get("xml_fields")
    if not isinstance(xml_fields, list) or not xml_fields:
        raise RuntimeError("settings must define a non-empty 'xml_fields' array")

    for idx, item in enumerate(xml_fields):
        if not isinstance(item, dict):
            raise RuntimeError(f"xml_fields[{idx}] must be an object with 'name' and 'xpath'")
        if not isinstance(item.get("name"), str) or not item.get("name"):
            raise RuntimeError(f"xml_fields[{idx}].name must be a non-empty string")
        has_xpath = isinstance(item.get("xpath"), str) and bool(item.get("xpath"))
        xpaths = item.get("xpaths")
        has_xpaths = isinstance(xpaths, list) and len(xpaths) > 0 and all(
            isinstance(path, str) and bool(path) for path in xpaths
        )
        if not has_xpath and not has_xpaths:
            raise RuntimeError(
                f"xml_fields[{idx}] must define either non-empty 'xpath' or non-empty 'xpaths'"
            )
        mode = item.get("mode", "first")
        if mode not in ("first", "all"):
            raise RuntimeError(f"xml_fields[{idx}].mode must be 'first' or 'all'")
        separator = item.get("separator", " | ")
        if not isinstance(separator, str):
            raise RuntimeError(f"xml_fields[{idx}].separator must be a string")
        exclude_values = item.get("exclude_values", [])
        if not isinstance(exclude_values, list) or not all(
            isinstance(value, str) for value in exclude_values
        ):
            raise RuntimeError(f"xml_fields[{idx}].exclude_values must be an array of strings")

    nmap_settings = data.get("nmap", {})
    if nmap_settings and not isinstance(nmap_settings, dict):
        raise RuntimeError("settings.nmap must be an object")
    if isinstance(nmap_settings, dict):
        if "args" in nmap_settings and (
            not isinstance(nmap_settings["args"], str) or not nmap_settings["args"].strip()
        ):
            raise RuntimeError("nmap.args must be a non-empty string")
        if "args_file" in nmap_settings and (
            not isinstance(nmap_settings["args_file"], str) or not nmap_settings["args_file"].strip()
        ):
            raise RuntimeError("nmap.args_file must be a non-empty string")

    redfish_settings = data.get("redfish")
    if redfish_settings is not None:
        if not isinstance(redfish_settings, dict):
            raise RuntimeError("settings.redfish must be an object")

        if "enabled" in redfish_settings and not isinstance(redfish_settings["enabled"], bool):
            raise RuntimeError("redfish.enabled must be a boolean")

        if "timeout" in redfish_settings and not isinstance(redfish_settings["timeout"], (int, float)):
            raise RuntimeError("redfish.timeout must be a number")

        redfish_fields = redfish_settings.get("fields", [])
        if not isinstance(redfish_fields, list):
            raise RuntimeError("redfish.fields must be an array")

        for idx, item in enumerate(redfish_fields):
            if not isinstance(item, dict):
                raise RuntimeError(f"redfish.fields[{idx}] must be an object")

            if not isinstance(item.get("name"), str) or not item.get("name"):
                raise RuntimeError(f"redfish.fields[{idx}].name must be a non-empty string")

            path_candidates = []
            for key in ("path", "request_path"):
                if isinstance(item.get(key), str) and item.get(key):
                    path_candidates.append(item[key])
            for key in ("paths", "request_paths"):
                value = item.get(key)
                if isinstance(value, list):
                    path_candidates.extend([p for p in value if isinstance(p, str) and p])
            if not path_candidates:
                raise RuntimeError(
                    f"redfish.fields[{idx}] must define at least one non-empty path using path/request_path or paths/request_paths"
                )

            pointer_candidates = []
            for key in ("json_pointer", "pointer"):
                if isinstance(item.get(key), str) and item.get(key):
                    pointer_candidates.append(item[key])
            for key in ("json_pointers", "pointers"):
                value = item.get(key)
                if isinstance(value, list):
                    pointer_candidates.extend([p for p in value if isinstance(p, str) and p])
            if not pointer_candidates:
                raise RuntimeError(
                    f"redfish.fields[{idx}] must define at least one non-empty JSON pointer using json_pointer/pointer or json_pointers/pointers"
                )

            mode = item.get("mode", "first")
            if mode not in ("first", "all"):
                raise RuntimeError(f"redfish.fields[{idx}].mode must be 'first' or 'all'")

            separator = item.get("separator", " | ")
            if not isinstance(separator, str):
                raise RuntimeError(f"redfish.fields[{idx}].separator must be a string")

            exclude_values = item.get("exclude_values", [])
            if not isinstance(exclude_values, list) or not all(
                isinstance(value, str) for value in exclude_values
            ):
                raise RuntimeError(f"redfish.fields[{idx}].exclude_values must be an array of strings")

    return data


def strip_namespaces(root: ET.Element) -> None:
    for elem in root.iter():
        if "}" in elem.tag:
            elem.tag = elem.tag.split("}", 1)[1]


def normalize_value(value: str) -> str:
    return value.strip()


def is_filtered_value(value: str, exclude_values: list[str]) -> bool:
    return value in exclude_values


def get_candidate_xpaths(spec: dict[str, Any]) -> list[str]:
    if isinstance(spec.get("xpaths"), list) and spec["xpaths"]:
        return spec["xpaths"]
    return [spec["xpath"]]


def get_candidate_redfish_paths(spec: dict[str, Any]) -> list[str]:
    for key in ("request_paths", "paths"):
        if isinstance(spec.get(key), list) and spec[key]:
            return spec[key]
    for key in ("request_path", "path"):
        if isinstance(spec.get(key), str) and spec[key]:
            return [spec[key]]
    return []


def get_candidate_redfish_pointers(spec: dict[str, Any]) -> list[str]:
    for key in ("json_pointers", "pointers"):
        if isinstance(spec.get(key), list) and spec[key]:
            return spec[key]
    for key in ("json_pointer", "pointer"):
        if isinstance(spec.get(key), str) and spec[key]:
            return [spec[key]]
    return []


def decode_json_pointer_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def resolve_json_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    if pointer == "":
        return True, document

    if not pointer.startswith("/"):
        return False, None

    current = document
    for raw_token in pointer.split("/")[1:]:
        token = decode_json_pointer_token(raw_token)
        if isinstance(current, list):
            if not token.isdigit():
                return False, None
            index = int(token)
            if index < 0 or index >= len(current):
                return False, None
            current = current[index]
            continue

        if isinstance(current, dict):
            if token not in current:
                return False, None
            current = current[token]
            continue

        return False, None

    return True, current


def normalize_json_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    return json.dumps(value)


def flatten_json_values(value: Any) -> list[str]:
    if isinstance(value, list):
        flattened: list[str] = []
        for item in value:
            flattened.extend(flatten_json_values(item))
        return flattened

    return [normalize_json_value(value)]


def extract_redfish_fields(
    payload_by_path: dict[str, Any],
    field_specs: list[dict[str, Any]],
) -> dict[str, str]:
    extracted: dict[str, str] = {}

    for spec in field_specs:
        field_name = spec["name"]
        mode = spec.get("mode", "first")
        separator = spec.get("separator", " | ")
        exclude_values = spec.get("exclude_values", [])
        paths = get_candidate_redfish_paths(spec)
        pointers = get_candidate_redfish_pointers(spec)

        if mode == "all":
            collected: list[str] = []
            for path in paths:
                payload = payload_by_path.get(path)
                if payload is None:
                    continue
                for pointer in pointers:
                    found, raw_value = resolve_json_pointer(payload, pointer)
                    if not found:
                        continue
                    for value in flatten_json_values(raw_value):
                        if value and not is_filtered_value(value, exclude_values):
                            collected.append(value)

            extracted[field_name] = separator.join(collected) if collected else "<missing>"
            continue

        found = False
        for path in paths:
            payload = payload_by_path.get(path)
            if payload is None:
                continue
            for pointer in pointers:
                resolved, raw_value = resolve_json_pointer(payload, pointer)
                if not resolved:
                    continue
                values = [
                    value
                    for value in flatten_json_values(raw_value)
                    if value and not is_filtered_value(value, exclude_values)
                ]
                if not values:
                    continue
                extracted[field_name] = values[0]
                found = True
                break
            if found:
                break

        if not found:
            extracted[field_name] = "<missing>"

    return extracted


def fetch_redfish_fields_for_host(
    ip: str,
    scheme: str,
    timeout: float,
    field_specs: list[dict[str, Any]],
) -> tuple[dict[str, str], str | None]:
    if not field_specs:
        return {}, None

    if scheme == "https":
        urllib3.disable_warnings(category=InsecureRequestWarning)

    unique_paths: list[str] = []
    seen_paths: set[str] = set()
    for spec in field_specs:
        for path in get_candidate_redfish_paths(spec):
            normalized_path = path if path.startswith("/") else f"/{path}"
            if normalized_path not in seen_paths:
                seen_paths.add(normalized_path)
                unique_paths.append(normalized_path)

    payload_by_path: dict[str, Any] = {}
    request_errors: list[str] = []

    for normalized_path in unique_paths:
        url = f"{scheme}://{ip}{normalized_path}"
        try:
            resp = requests.get(url, timeout=timeout, verify=False if scheme == "https" else True)
        except requests.RequestException as exc:
            request_errors.append(f"{normalized_path}: {exc}")
            continue

        if not resp.ok:
            request_errors.append(f"{normalized_path}: HTTP {resp.status_code}")

        try:
            payload_by_path[normalized_path] = resp.json()
        except ValueError:
            request_errors.append(f"{normalized_path}: response was not JSON")

    extracted = extract_redfish_fields(payload_by_path=payload_by_path, field_specs=field_specs)
    error_text = "; ".join(request_errors) if request_errors else None
    return extracted, error_text


def parse_xml_fields(xml_text: str, field_specs: list[dict[str, Any]]) -> tuple[dict[str, str], str | None]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return {}, f"xml parse error: {exc}"

    strip_namespaces(root)
    extracted: dict[str, str] = {}
    for spec in field_specs:
        field_name = spec["name"]
        mode = spec.get("mode", "first")
        separator = spec.get("separator", " | ")
        exclude_values = spec.get("exclude_values", [])
        xpaths = get_candidate_xpaths(spec)

        if mode == "all":
            collected: list[str] = []
            for xpath in xpaths:
                nodes = root.findall(xpath)
                values = [normalize_value((node.text or "")) for node in nodes]
                filtered = [v for v in values if v and not is_filtered_value(v, exclude_values)]
                collected.extend(filtered)

            if not collected:
                extracted[field_name] = "<missing>"
                continue

            extracted[field_name] = separator.join(collected)
            continue

        found = False
        for xpath in xpaths:
            node = root.find(xpath)
            if node is None:
                continue

            value = normalize_value((node.text or ""))
            if not value or is_filtered_value(value, exclude_values):
                continue

            extracted[field_name] = value
            found = True
            break

        if not found:
            extracted[field_name] = "<missing>"

    return extracted, None


def fetch_endpoint(
    hosts: List[str],
    scheme: str,
    path: str,
    timeout: float,
    xml_fields: list[dict[str, str]],
    redfish_fields: list[dict[str, Any]],
    redfish_timeout: float,
    workers: int,
    progress_every: int,
) -> List[HttpResult]:
    if scheme == "https":
        urllib3.disable_warnings(category=InsecureRequestWarning)

    def fetch_one(ip: str) -> HttpResult:
        normalized_path = path if path.startswith("/") else f"/{path}"
        url = f"{scheme}://{ip}{normalized_path}"
        try:
            resp = requests.get(url, timeout=timeout, verify=False if scheme == "https" else True)
            parsed_fields, parse_error = parse_xml_fields(resp.text, xml_fields)
            redfish_values, redfish_error = fetch_redfish_fields_for_host(
                ip=ip,
                scheme=scheme,
                timeout=redfish_timeout,
                field_specs=redfish_fields,
            )
            return HttpResult(
                ip=ip,
                url=url,
                ok=True,
                status_code=resp.status_code,
                body_text=resp.text,
                parsed_fields=parsed_fields,
                parse_error=parse_error,
                redfish_fields=redfish_values,
                redfish_error=redfish_error,
            )
        except requests.RequestException as exc:
            print(f"[error] {ip} -> {url} ({exc})")
            redfish_values, redfish_error = fetch_redfish_fields_for_host(
                ip=ip,
                scheme=scheme,
                timeout=redfish_timeout,
                field_specs=redfish_fields,
            )
            return HttpResult(
                ip=ip,
                url=url,
                ok=False,
                error=str(exc),
                redfish_fields=redfish_values,
                redfish_error=redfish_error,
            )

    results_by_ip: dict[str, HttpResult] = {}
    total_hosts = len(hosts)
    completed_count = 0

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_to_ip = {executor.submit(fetch_one, ip): ip for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            results_by_ip[ip] = future.result()
            completed_count += 1
            if progress_every > 0 and (completed_count % progress_every == 0 or completed_count == total_hosts):
                print(f"[progress] completed HTTP requests for {completed_count}/{total_hosts} hosts")

    return [results_by_ip[ip] for ip in hosts]


def write_csv_results(
    results: List[HttpResult],
    field_specs: list[dict[str, Any]],
    redfish_field_specs: list[dict[str, Any]],
    csv_path: str,
    debug: bool = False,
) -> None:
    field_names = [spec["name"] for spec in field_specs]
    redfish_field_names = [spec["name"] for spec in redfish_field_specs]
    headers = ["ip"]
    if debug:
        headers.extend(["url", "error", "xml_parse_error", "redfish_error"])
    headers.extend(field_names)
    headers.extend(redfish_field_names)

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        writer.writeheader()

        for result in results:
            row = {"ip": result.ip}
            if debug:
                row.update({
                    "url": result.url,
                    "error": result.error or "",
                    "xml_parse_error": result.parse_error or "",
                    "redfish_error": result.redfish_error or "",
                })
            for field_name in field_names:
                value = ""
                if result.parsed_fields:
                    value = result.parsed_fields.get(field_name, "")
                row[field_name] = value
            for field_name in redfish_field_names:
                value = ""
                if result.redfish_fields:
                    value = result.redfish_fields.get(field_name, "")
                row[field_name] = value

            writer.writerow(row)


def write_discovery_csv(hosts: List[str], scheme: str, path: str, csv_path: str) -> None:
    normalized_path = path if path.startswith("/") else f"/{path}"
    headers = ["ip", "url"]

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        writer.writeheader()
        for ip in hosts:
            writer.writerow({"ip": ip, "url": f"{scheme}://{ip}{normalized_path}"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Nmap against a CIDR and perform unauthenticated GET requests on discovered hosts."
    )
    parser.add_argument("--cidr", required=True, help="Target CIDR (example: 10.152.161.0/24)")
    parser.add_argument(
        "--path",
        default=None,
        help="Path/query for GET request. Overrides settings JSON if provided.",
    )
    parser.add_argument(
        "--scheme",
        choices=["http", "https"],
        default=None,
        help="Protocol for GET requests. Overrides settings JSON if provided.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="HTTP timeout in seconds. Overrides settings JSON if provided.",
    )
    parser.add_argument(
        "--nmap-path",
        default=None,
        help="Optional full path to nmap executable.",
    )
    parser.add_argument(
        "--nmap-args",
        default=None,
        help="Nmap args for discovery scan. Overrides settings JSON if provided.",
    )
    parser.add_argument(
        "--nmap-args-file",
        default=None,
        help="Path to a plain-text file containing Nmap args. Overrides settings JSON if provided.",
    )
    parser.add_argument(
        "--settings",
        default="settings.json",
        help="Path to JSON settings file (default: settings.json)",
    )
    parser.add_argument(
        "--csv-output",
        default="scan_results.csv",
        help="Path for CSV output file (default: scan_results.csv)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Concurrent HTTP workers. Overrides settings JSON if provided.",
    )
    parser.add_argument(
        "--max-targets",
        type=int,
        default=None,
        help="Maximum number of hosts to request before aborting. Overrides settings JSON if provided.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Discover targets and write discovery CSV without issuing HTTP requests.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=None,
        help="Print progress after every N completed HTTP requests. Overrides settings JSON if provided.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Include debug columns in CSV output (url, error, xml_parse_error, redfish_error).",
    )
    parser.add_argument(
        "--no-redfish",
        action="store_true",
        help="Skip unauthenticated Redfish enrichment queries.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        settings = load_settings(args.settings)
    except RuntimeError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    request_settings = settings.get("request", {}) if isinstance(settings.get("request", {}), dict) else {}
    nmap_settings = settings.get("nmap", {}) if isinstance(settings.get("nmap", {}), dict) else {}
    execution_settings = settings.get("execution", {}) if isinstance(settings.get("execution", {}), dict) else {}
    redfish_settings = settings.get("redfish", {}) if isinstance(settings.get("redfish", {}), dict) else {}

    scheme = args.scheme or request_settings.get("scheme", "https")
    path = args.path or request_settings.get("path", "/xmldata?item=All")
    timeout = args.timeout if args.timeout is not None else float(request_settings.get("timeout", 5.0))
    try:
        nmap_args, nmap_arg_tokens = resolve_nmap_args(
            cli_nmap_args=args.nmap_args,
            cli_nmap_args_file=args.nmap_args_file,
            nmap_settings=nmap_settings,
            settings_path=args.settings,
        )
    except RuntimeError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    workers = args.workers if args.workers is not None else int(execution_settings.get("workers", 32))
    max_targets = (
        args.max_targets if args.max_targets is not None else int(execution_settings.get("max_targets", 2048))
    )
    progress_every = (
        args.progress_every if args.progress_every is not None else int(execution_settings.get("progress_every", 50))
    )
    xml_fields = settings["xml_fields"]
    redfish_enabled = bool(redfish_settings.get("enabled", True)) and not args.no_redfish
    redfish_fields = redfish_settings.get("fields", []) if redfish_enabled else []
    redfish_timeout = float(redfish_settings.get("timeout", timeout))

    try:
        require_open_port_output = "-Pn" in nmap_arg_tokens
        nmap_exe = find_nmap(args.nmap_path)
        hosts = discover_up_hosts(
            nmap_exe=nmap_exe,
            cidr=args.cidr,
            nmap_args=nmap_args,
            nmap_arg_tokens=nmap_arg_tokens,
            require_open_port_output=require_open_port_output,
        )
    except FileNotFoundError as exc:
        fallback_host = fallback_host_from_single_cidr(args.cidr)
        if fallback_host:
            print(f"[warn] {exc}")
            print(f"[warn] Falling back to direct host request for {fallback_host} from /32 CIDR.")
            hosts = [fallback_host]
        else:
            print(f"[error] {exc}", file=sys.stderr)
            return 1
    except RuntimeError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    if not hosts:
        print("No hosts reported as Up by nmap.")
        return 0

    print(f"Discovered {len(hosts)} up host(s): {', '.join(hosts)}")

    if args.dry_run:
        write_discovery_csv(hosts=hosts, scheme=scheme, path=path, csv_path=args.csv_output)
        print(f"\nDry run complete. Discovery CSV written: {args.csv_output}")
        return 0

    if len(hosts) > max_targets:
        print(
            f"[error] refusing to issue HTTP requests to {len(hosts)} hosts; max_targets is {max_targets}.",
            file=sys.stderr,
        )
        print(
            "[error] tighten Nmap discovery so only real responders are returned, or raise --max-targets intentionally.",
            file=sys.stderr,
        )
        return 1

    results = fetch_endpoint(
        hosts=hosts,
        scheme=scheme,
        path=path,
        timeout=timeout,
        xml_fields=xml_fields,
        redfish_fields=redfish_fields,
        redfish_timeout=redfish_timeout,
        workers=workers,
        progress_every=progress_every,
    )

    print("\nHTTP GET results")
    print("----------------")
    for result in results:
        if result.ok:
            print(f"[ok]    {result.ip} -> {result.url} (status={result.status_code})")
            if result.parse_error:
                print(f"        XML parse: {result.parse_error}")
            elif result.parsed_fields:
                for field_name, field_value in result.parsed_fields.items():
                    print(f"        {field_name}: {field_value}")
            if result.redfish_fields:
                for field_name, field_value in result.redfish_fields.items():
                    print(f"        {field_name}: {field_value}")
            if result.redfish_error:
                print(f"        Redfish: {result.redfish_error}")
        else:
            print(f"[error] {result.ip} -> {result.url} ({result.error})")
            if result.redfish_fields:
                for field_name, field_value in result.redfish_fields.items():
                    print(f"        {field_name}: {field_value}")
            if result.redfish_error:
                print(f"        Redfish: {result.redfish_error}")

    write_csv_results(
        results=results,
        field_specs=xml_fields,
        redfish_field_specs=redfish_fields,
        csv_path=args.csv_output,
        debug=args.debug,
    )
    print(f"\nCSV written: {args.csv_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
