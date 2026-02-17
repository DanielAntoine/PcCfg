# PcCfg

## Idea
PcCfg is a lightweight desktop utility concept for quickly preparing a Windows PC with a repeatable setup profile.

The goal is to provide two simple workflows:
- **Inspect mode** to collect and review current system settings safely.
- **Apply mode** to execute a selected set of common performance and usability tweaks (power, startup, notifications, visual effects, and more).

The app now requests Administrator privileges when launched on Windows.

This helps make fresh-machine setup faster, more consistent, and easier to audit.

## Requirements
- Python 3.10+
- PyQt5
- Windows 10/11 (for full Inspect + Apply functionality)

All dependencies are expected to already be installed in your environment, so no setup/install section is required.

## Run
From the project folder:

```bash
python dxm_pc_setup_gui.py
```

On Windows, the app relaunches itself with Administrator privileges when needed.

## Windows non-interactive install commands (recommended)
If you want installs to run without prompts (`Y/N`, path questions, etc.), use these command patterns.

### 1) Preferred: `winget`
Use `--silent` plus agreement flags to avoid interaction.

```powershell
winget install --id <Publisher.AppId> --exact --silent --accept-package-agreements --accept-source-agreements
```

Example:

```powershell
winget install --id Google.Chrome --exact --silent --accept-package-agreements --accept-source-agreements
```

### 2) Chocolatey

```powershell
choco install <package-name> -y --no-progress
```

Example:

```powershell
choco install git -y --no-progress
```

### 3) Scoop

```powershell
scoop install <package-name>
```

Scoop installs are typically non-interactive by default.

### 4) MSI installers
For raw MSI files, use the Windows installer service directly:

```powershell
msiexec /i "C:\path\installer.msi" /qn /norestart
```

### 5) EXE installers
Most EXE installers support one of these silent switches:

```powershell
# Common patterns (vendor-dependent)
installer.exe /S
installer.exe /silent
installer.exe /verysilent /norestart
```

### 6) PowerShell package providers (if used)

```powershell
Install-Package <name> -Force -Confirm:$false
```

## Practical guidance
- Prefer `winget` first on modern Windows 10/11.
- Use `--exact` with `winget` to avoid ambiguous package matches.
- Keep installers idempotent in scripts (check whether software is already installed before re-running).
- Avoid `yes`-style piping on Windows; silent flags are safer and more predictable.

## DONE
- [x] Redesign the full checklist/table layout spacing so columns align cleanly, content does not drift to the right, and row/task spacing is consistently sized across the UI.
- [x] Constrain long checklist text to wrap to a maximum of 2 lines; use the second line only when needed so single-line content does not reserve extra blank row height.
- [x] Replace plain checklist status text with status chips (`PASS`, `FAIL`, `PENDING`, `RUNNING`) and apply consistent color semantics per status across the UI.
- [x] Generate the hostname automatically using `{ClientNamePascal}-{Role2LUpper}-{numbering00}` and remove manual computer-name input.
- [x] Detect whether a Wi-Fi adapter is present during Inspect, and update the matching checklist item automatically when detection passes.
- [x] Detect whether Wi-Fi is connected during Inspect (connected/disconnected + SSID/signal when available), and update the matching checklist item automatically when detection passes.
- [x] Detect internet reachability during Inspect (for example via DNS/ping test), and update the matching checklist item automatically when detection passes.
- [x] For each Inspect detection result, sync checklist state so passing checks can auto-check their mapped checklist tasks while failed/unknown checks remain visible for manual follow-up.
- [x] Add a client profile config section:
  - Save profile as `{InputName}-{yymmdd}.json`.
  - Include a default profile.
  - Support marking checklist items as `Not Applicable` (right-click), and treat them as skipped.
  - Apply profile changes only after save + reload.
- [x] Enforce computer name/hostname format with all 3 required elements:
  - `ClientName`, `Role`, and `numbering00`.
  - Pattern remains `{ClientNamePascal}-{Role2LUpper}-{numbering00}`.
  - Block **Apply** if any required element is missing.
  - No manual override of generated name.
- [x] Add SSH setup in app:
  - Install/enable OpenSSH Server only if missing.
  - Set service startup type to `Automatic`.
  - Ensure Windows Firewall SSH rule is enabled.
  - Add Inspect validation for installed + running + listening (port 22).
- [x] Add Parsec support:
  - Add Parsec download/install option.
  - Use `winget` silent install.
  - Apply checklist status item.
- [x] Disk usage detection automation:
  - Detect disks that are not used for anything (no meaningful mounted/active volume usage), rather than only checking drive-letter assignment.
- [x] Allow Run when hostname is missing, but block only "Rename computer" until hostname format requirements are met.
- [x] Add Remote Desktop setup to Apply options + checklist as one item:
  - Enable RDP service.
  - Allow firewall rule.
  - Enable NLA.
- [x] Add `https://www.nvidia.com/Download/index.aspx` to Manual Install list only.
- [x] Open text report automatically after save; show dialog if opening fails.
- [x] modify the checklist "Software (client-provided)" to "Software" and list all software there individualy. set all to non applicable excepte for Screenconnect, all to "inspect" to validate the apps install
- [x] add winget install -e --id Bitfocus.Companion and winget install -e --id Elgato.StreamDeck
- 
## TODO
- [ ] Add Inspect output (informational only) to log console and report output:
  - CPU (short value)
  - Motherboard (short value)
  - BIOS version (short value)
  - IP (IPv4 + IPv6 across all adapters)
  - Hostname 
- [ ] After Run, show "restart may be needed" popup only for specific actions that can require reboot:
  - Dialog buttons: `Restart now` and `Restart later`.
  - Include which tasks triggered reboot requirement.
- [ ] Move all "info " input needed by the user to a form under " manual install" and remove culumn info from install pc checklist, update checlist when field is fill
- [ ] dont show hostname date filename in checklist