from __future__ import annotations

import json
import re
from typing import Callable

from pccfg.domain.models import InstallApp
from pccfg.services.command_runner import DEFAULT_INSPECT_TIMEOUT_SEC, run_command_with_options


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


def _detect_from_registry(app: InstallApp, cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    display_names = [name.strip().lower() for name in app.detect_display_names if name.strip()]
    if not display_names:
        display_names = [app.label.strip().lower()]

    publishers = [name.strip().lower() for name in app.detect_publishers if name.strip()]

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
        return None, "Unable to query"

    rows = parse_json_payload(output)
    if not rows:
        return False, "Not installed"

    for row in rows:
        display_name = str(row.get("DisplayName") or "").strip()
        publisher = str(row.get("Publisher") or "").strip()
        scope = str(row.get("Scope") or "registry").strip()
        normalized_display = display_name.lower()
        normalized_publisher = publisher.lower()

        name_match = any(pattern in normalized_display for pattern in display_names)
        publisher_match = bool(publishers) and any(pattern in normalized_publisher for pattern in publishers)
        if name_match or publisher_match:
            return True, f"Installed (registry {scope}: {display_name})"

    return False, "Not installed"


def detect_software_installation(app: InstallApp, cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    winget_command = [
        "winget",
        "list",
        "--id",
        app.winget_id,
        "--exact",
        "--accept-source-agreements",
        "--output",
        "json",
    ]
    winget_rc, winget_output = run_command_with_options(
        winget_command,
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )

    if winget_rc == 0 and _match_winget_id_from_output(winget_output, app.winget_id):
        return True, "Installed (winget)"

    if winget_rc not in {0, 1}:
        text_rc, text_output = run_command_with_options(
            ["winget", "list", "--id", app.winget_id, "--exact", "--accept-source-agreements"],
            timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
            cancel_requested=cancel_requested,
        )
        if text_rc == 0 and _match_winget_id_from_output(text_output, app.winget_id):
            return True, "Installed (winget)"
        if text_rc not in {0, 1}:
            registry_ok, registry_detail = _detect_from_registry(app, cancel_requested)
            if registry_ok is None:
                return None, "Unable to query"
            return registry_ok, registry_detail

    registry_ok, registry_detail = _detect_from_registry(app, cancel_requested)
    if registry_ok is None:
        return None, "Unable to query"
    return registry_ok, registry_detail


def detect_screenconnect_installation(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        "$paths = @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
        "Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -match 'ScreenConnect|ConnectWise Control' } | "
        "Select-Object -First 1 -ExpandProperty DisplayName",
    ]
    rc, output = run_command_with_options(
        command,
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return None, "Unable to query"

    detected = compact_single_line(output)
    if detected:
        return True, detected
    return False, "Not installed"
