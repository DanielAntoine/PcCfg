from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable

from pccfg.domain.models import InstallApp
from pccfg.services.command_runner import DEFAULT_INSPECT_TIMEOUT_SEC, run_command_with_options


@dataclass(frozen=True)
class SoftwareDetectionSnapshot:
    winget_ids: frozenset[str]
    registry_rows: tuple[dict[str, str], ...]
    executable_names: frozenset[str]
    shortcut_names: frozenset[str]


def compact_single_line(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return " | ".join(lines)


def parse_json_payload(raw_output: str) -> list[dict[str, str]]:
    raw = raw_output.strip()
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def detect_wifi_adapter(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    command = (
        "$a = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | "
        "Where-Object { $_.InterfaceDescription -match 'Wi-Fi|Wireless|WLAN' -or $_.Name -match 'Wi-Fi|Wireless|WLAN' }; "
        "if ($a) { $a | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress }"
    )
    rc, output = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", command],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return None, "Unable to query"

    adapters: list[str] = []
    raw = output.strip()
    if raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = raw

        if isinstance(payload, str):
            adapters = [payload.strip()] if payload.strip() else []
        elif isinstance(payload, list):
            adapters = [str(item).strip() for item in payload if str(item).strip()]
    if adapters:
        return True, ", ".join(adapters)
    return False, "No Wi-Fi adapter found"


def detect_wifi_connection(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    rc, output = run_command_with_options(
        ["netsh", "wlan", "show", "interfaces"],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return None, "Unable to query"

    state_match = re.search(r"^\s*State\s*:\s*(.+)$", output, flags=re.IGNORECASE | re.MULTILINE)
    ssid_match = re.search(r"^\s*SSID\s*:\s*(.+)$", output, flags=re.IGNORECASE | re.MULTILINE)
    signal_match = re.search(r"^\s*Signal\s*:\s*(.+)$", output, flags=re.IGNORECASE | re.MULTILINE)

    state_value = state_match.group(1).strip() if state_match else "Unknown"
    connected = state_value.lower() == "connected"
    if connected:
        ssid = ssid_match.group(1).strip() if ssid_match else "Unknown"
        signal = signal_match.group(1).strip() if signal_match else "Unknown"
        return True, f"Connected ({ssid}, {signal})"
    return False, f"{state_value}"


def detect_internet_reachability(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    dns_cmd = "Resolve-DnsName -Name microsoft.com -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty NameHost"
    ping_cmd = "Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet"
    dns_rc, dns_out = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", dns_cmd],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    ping_rc, ping_out = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", ping_cmd],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )

    if dns_rc != 0 and ping_rc != 0:
        return None, "Unable to query"

    dns_ok = bool(compact_single_line(dns_out))
    ping_ok = compact_single_line(ping_out).lower() == "true"
    reachable = dns_ok or ping_ok
    detail = f"DNS={'OK' if dns_ok else 'FAIL'}, Ping={'OK' if ping_ok else 'FAIL'}"
    return reachable, detail


def detect_unused_disks(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    command = (
        "$rows = Get-Disk -ErrorAction SilentlyContinue | ForEach-Object { "
        "$disk = $_; "
        "$parts = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue; "
        "$vols = @(); if ($parts) { $vols = $parts | Get-Volume -ErrorAction SilentlyContinue }; "
        "$used = $false; "
        "if ($vols) { $used = @($vols | Where-Object { $_.DriveLetter -or ($_.Size -gt 0 -and $_.FileSystemType) }).Count -gt 0 }; "
        "[PSCustomObject]@{Number=$disk.Number;FriendlyName=$disk.FriendlyName;Used=$used} "
        "}; $rows | ConvertTo-Json -Compress"
    )
    rc, output = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", command],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return None, "Unable to query"

    rows = parse_json_payload(output)
    if not rows:
        return None, "No disk data"

    unused = [f"Disk {row.get('Number')} ({row.get('FriendlyName', 'Unknown')})" for row in rows if not bool(row.get('Used'))]
    if unused:
        return True, f"Unused: {', '.join(unused)}"
    return True, "No unused disks detected"


def detect_ssh_readiness(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    command = (
        "$cap = Get-WindowsCapability -Online -Name OpenSSH.Server* -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty State; "
        "$svc = Get-Service -Name sshd -ErrorAction SilentlyContinue; "
        "$tcp = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; "
        "[PSCustomObject]@{Installed=($cap -eq 'Installed');Running=($svc -and $svc.Status -eq 'Running');Listening=[bool]$tcp} | ConvertTo-Json -Compress"
    )
    rc, output = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", command],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return None, "Unable to query"

    rows = parse_json_payload(output)
    if not rows:
        return None, "No SSH data"

    row = rows[0]
    installed = bool(row.get("Installed"))
    running = bool(row.get("Running"))
    listening = bool(row.get("Listening"))
    ok = installed and running and listening
    return ok, f"Installed={'OK' if installed else 'FAIL'}, Service={'OK' if running else 'FAIL'}, Port22={'OK' if listening else 'FAIL'}"


def detect_remote_desktop_readiness(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    command = (
        "$deny = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections; "
        "$nla = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication; "
        "$svc = Get-Service -Name TermService -ErrorAction SilentlyContinue; "
        "$fw = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True' | Select-Object -First 1; "
        "[PSCustomObject]@{Enabled=($deny -eq 0);NLA=($nla -eq 1);Service=($svc -and $svc.Status -eq 'Running');Firewall=[bool]$fw} | ConvertTo-Json -Compress"
    )
    rc, output = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", command],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return None, "Unable to query"

    rows = parse_json_payload(output)
    if not rows:
        return None, "No RDP data"

    row = rows[0]
    enabled = bool(row.get("Enabled"))
    nla = bool(row.get("NLA"))
    service = bool(row.get("Service"))
    firewall = bool(row.get("Firewall"))
    ok = enabled and nla and service and firewall
    return ok, f"Enabled={'OK' if enabled else 'FAIL'}, NLA={'OK' if nla else 'FAIL'}, Service={'OK' if service else 'FAIL'}, Firewall={'OK' if firewall else 'FAIL'}"


def _match_winget_id_from_output(raw_output: str, winget_id: str) -> bool:
    rows = parse_json_payload(raw_output)
    normalized_id = winget_id.lower()
    for row in rows:
        package_id = str(row.get("Id") or row.get("PackageIdentifier") or "").strip().lower()
        if package_id == normalized_id:
            return True

    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        columns = re.split(r"\s{2,}", stripped)
        if len(columns) < 2:
            continue
        candidate_id = columns[1].strip().lower()
        if candidate_id == normalized_id:
            return True
    return False


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", value.lower())).strip()


def _pattern_matches_text(pattern: str, text: str) -> bool:
    normalized_pattern = _normalize_text(pattern)
    normalized_text = _normalize_text(text)
    if not normalized_pattern or not normalized_text:
        return False
    if normalized_text == normalized_pattern:
        return True
    escaped = re.escape(normalized_pattern)
    return re.search(rf"(?:^|\s){escaped}(?:\s|$)", normalized_text) is not None


def _collect_winget_ids(cancel_requested: Callable[[], bool] | None = None) -> tuple[frozenset[str], bool]:
    rc, output = run_command_with_options(
        ["winget", "list", "--accept-source-agreements", "--output", "json"],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc == 0:
        rows = parse_json_payload(output)
        ids = {
            str(row.get("Id") or row.get("PackageIdentifier") or "").strip().lower()
            for row in rows
            if str(row.get("Id") or row.get("PackageIdentifier") or "").strip()
        }
        return frozenset(ids), bool(rows)

    text_rc, text_out = run_command_with_options(
        ["winget", "list", "--accept-source-agreements"],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if text_rc != 0:
        return frozenset(), False

    ids: set[str] = set()
    for line in text_out.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        if stripped.lower().startswith("name") and "id" in stripped.lower():
            continue
        columns = re.split(r"\s{2,}", stripped)
        if len(columns) < 2:
            continue
        candidate_id = columns[1].strip().lower()
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", candidate_id):
            ids.add(candidate_id)
    return frozenset(ids), bool(ids)


def _collect_registry_rows(cancel_requested: Callable[[], bool] | None = None) -> tuple[tuple[dict[str, str], ...], bool]:
    probe_command = (
        "$paths = @("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        "); "
        "$rows = foreach ($path in $paths) { "
        "Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object @{N='Scope';E={$path}}, DisplayName, Publisher "
        "}; "
        "$rows | ConvertTo-Json -Compress"
    )
    rc, output = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", probe_command],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return (), False
    rows = parse_json_payload(output)
    return tuple(rows), bool(rows)


def _collect_executable_names(cancel_requested: Callable[[], bool] | None = None) -> tuple[frozenset[str], bool]:
    command = (
        "$cmds = Get-Command -CommandType Application -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Name -Unique; "
        "$cmds | ConvertTo-Json -Compress"
    )
    rc, output = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", command],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return frozenset(), False

    names = parse_json_payload(output)
    if names:
        extracted = {
            _normalize_text(str(row.get("Name") or ""))
            for row in names
            if _normalize_text(str(row.get("Name") or ""))
        }
        if extracted:
            return frozenset(extracted), True

    raw = output.strip()
    if not raw:
        return frozenset(), False
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = []
    if isinstance(payload, str):
        return frozenset({_normalize_text(payload)}), True
    if isinstance(payload, list):
        extracted = {_normalize_text(str(item)) for item in payload if _normalize_text(str(item))}
        return frozenset(extracted), bool(extracted)
    return frozenset(), False


def _collect_shortcut_names(cancel_requested: Callable[[], bool] | None = None) -> tuple[frozenset[str], bool]:
    command = (
        "$roots = @($env:ProgramData + '\\Microsoft\\Windows\\Start Menu\\Programs',"
        "$env:APPDATA + '\\Microsoft\\Windows\\Start Menu\\Programs');"
        "$items = foreach ($root in $roots) {"
        "if (Test-Path $root) {Get-ChildItem -Path $root -Filter *.lnk -Recurse -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty BaseName}};"
        "$items | Select-Object -Unique | ConvertTo-Json -Compress"
    )
    rc, output = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", command],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return frozenset(), False

    raw = output.strip()
    if not raw:
        return frozenset(), False
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return frozenset(), False
    if isinstance(payload, str):
        return frozenset({_normalize_text(payload)}), True
    if isinstance(payload, list):
        extracted = {_normalize_text(str(item)) for item in payload if _normalize_text(str(item))}
        return frozenset(extracted), bool(extracted)
    return frozenset(), False


def collect_software_detection_snapshot(
    cancel_requested: Callable[[], bool] | None = None,
) -> tuple[SoftwareDetectionSnapshot | None, str]:
    winget_ids, winget_ok = _collect_winget_ids(cancel_requested)
    registry_rows, registry_ok = _collect_registry_rows(cancel_requested)
    executable_names, executable_ok = _collect_executable_names(cancel_requested)
    shortcut_names, shortcut_ok = _collect_shortcut_names(cancel_requested)

    if not any((winget_ok, registry_ok, executable_ok, shortcut_ok)):
        return None, "Unable to query"

    snapshot = SoftwareDetectionSnapshot(
        winget_ids=winget_ids,
        registry_rows=registry_rows,
        executable_names=executable_names,
        shortcut_names=shortcut_names,
    )
    return snapshot, "OK"


def _detect_from_registry_rows(app: InstallApp, rows: tuple[dict[str, str], ...]) -> tuple[bool, str]:
    display_names = [name.strip() for name in app.detect_display_names if name.strip()]
    if not display_names:
        display_names = [app.label.strip()]
    publishers = [name.strip().lower() for name in app.detect_publishers if name.strip()]

    for row in rows:
        display_name = str(row.get("DisplayName") or "").strip()
        publisher = str(row.get("Publisher") or "").strip()
        scope = str(row.get("Scope") or "registry").strip()

        name_match = any(_pattern_matches_text(pattern, display_name) for pattern in display_names)
        if not name_match:
            continue

        publisher_match = bool(publishers) and any(p in publisher.lower() for p in publishers)
        match_type = "name+publisher" if publisher_match else "name"
        return True, f"Installed (registry {match_type} {scope}: {display_name})"

    return False, "Not installed"


def _detect_from_exec_and_shortcuts(app: InstallApp, snapshot: SoftwareDetectionSnapshot) -> tuple[bool, str]:
    executable_patterns = [_normalize_text(name) for name in app.detect_executables if _normalize_text(name)]
    shortcut_patterns = [_normalize_text(name) for name in app.detect_shortcuts if _normalize_text(name)]

    executable_match = any(pattern in snapshot.executable_names for pattern in executable_patterns)
    shortcut_match = any(pattern in snapshot.shortcut_names for pattern in shortcut_patterns)
    if executable_match and shortcut_match:
        return True, "Installed (path+shortcut)"
    if executable_match:
        return False, "Partial evidence: executable on PATH only"
    if shortcut_match:
        return False, "Partial evidence: Start Menu shortcut only"
    return False, "Not installed"


def _detect_from_registry(app: InstallApp, cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    rows, ok = _collect_registry_rows(cancel_requested)
    if not ok:
        return None, "Unable to query"
    return _detect_from_registry_rows(app, rows)


def detect_software_installation_from_snapshot(
    app: InstallApp,
    snapshot: SoftwareDetectionSnapshot,
) -> tuple[bool | None, str]:
    if app.winget_id.strip().lower() in snapshot.winget_ids:
        return True, "Installed (winget snapshot)"

    registry_ok, registry_detail = _detect_from_registry_rows(app, snapshot.registry_rows)
    if registry_ok:
        return True, registry_detail

    evidence_ok, evidence_detail = _detect_from_exec_and_shortcuts(app, snapshot)
    return evidence_ok, evidence_detail


def detect_software_installation(app: InstallApp, cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    snapshot, detail = collect_software_detection_snapshot(cancel_requested)
    if snapshot is None:
        return None, detail
    return detect_software_installation_from_snapshot(app, snapshot)


def detect_screenconnect_installation(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$paths = @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
        "Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -match 'ScreenConnect|ConnectWise Control' } | "
        "Select-Object -First 1 @{N='Scope';E={$_.PSPath}}, DisplayName | ConvertTo-Json -Compress",
    ]
    rc, output = run_command_with_options(
        command,
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return None, "Unable to query"

    rows = parse_json_payload(output)
    if rows:
        row = rows[0]
        scope = str(row.get("Scope") or "registry").strip()
        name = str(row.get("DisplayName") or "ScreenConnect").strip()
        return True, f"Installed ({scope}: {name})"
    return False, "Not installed"
