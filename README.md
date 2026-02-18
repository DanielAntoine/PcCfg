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

## Build EXE with icon (Windows)

Use PyInstaller with the included `app.ico` file:

```powershell
pyinstaller --noconfirm --onefile --console --name PcCfg-v0.1.2-ForTestOnly --icon Icon/PCSetup.ico --add-data "style;style" --add-data "profiles;profiles" dxm_pc_setup_gui.py
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
- [x] Generate the hostname automatically using `{ClientNamePascal}-{Role4LUpper}-{numbering00}` and remove manual computer-name input.
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
  - Pattern remains `{ClientNamePascal}-{Role4LUpper}-{numbering00}`.
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
- [x] dont show hostname date filename in checklist
- [x] Add Inspect output (informational only) to log console and report output ,CPU (short value) ,Motherboard (short value), BIOS version (short value), IP (IPv4 + IPv6 across all adapters)
- [x] After Run, show "restart may be needed" add a Dialog buttons: `Restart now` and `Restart later`.
- [x] Move all "info " input needed by the user to a form under " manual install" and remove culumn info from install pc checklist, update checlist when field is fill
- [x] Move "Evidence / Photos" to the last checklist section.
- [x] Remove "Validation: Device Manager = 0 unknown devices" from Setup information.
- [x] Show Setup information inputs under each label (stacked vertically).
- [x] Improve Google Chrome inspect detection with fallback checks when `winget list` cannot be queried.
- [x] "installed card" can select multiple from a dropdown, now includes 12 preset options and supports manual multi-entry
- [x] Inventory ID set as net applicable by default
- [x] Numbering00 set to none by default
- [x] start whit no "Apply option" check by default
## TODO
- [ ] Decide macOS support target (MVP vs feature-parity), minimum macOS version, and supported CPU architectures (universal2).
- [ ] Inventory all Windows-only execution paths and tag each one as: `portable`, `macOS equivalent`, or `Windows-only`.
- [ ] Introduce a platform abstraction layer so UI/domain code calls one service contract instead of direct PowerShell/registry commands.
- [ ] Implement a macOS platform adapter with read-only inspect probes first, then safe apply actions.
- [ ] Add capability flags so unsupported actions are disabled/hidden on macOS with clear user messaging.
- [ ] Add cross-platform tests for platform adapters and checklist mapping behavior.
- [ ] Add macOS packaging workflow (`.app`/DMG) plus signing/notarization notes.
- [ ] Validate on real macOS hardware and produce a support matrix in docs.

## macOS version plan (maintainable, phase-by-phase)

The recommended path is to keep one codebase and split operating-system logic into adapter modules. This avoids duplicating UI code and keeps Windows behavior stable while macOS support grows.

### Phase 0 — Scope and architecture baseline
**Goal:** lock requirements before code movement.

**Deliverables**
- Define supported macOS versions and architecture target(s).
- Define MVP feature set for macOS (Inspect-only vs partial Apply).
- Agree on commands/providers: Homebrew, `scutil`, `sw_vers`, `networksetup`, `pmset`, `defaults`.

**File-level changes**
- `README.md`
  - Add support matrix draft and macOS MVP scope.
- `docs/software-detection-task-plan.md`
  - Add a platform notes section to separate Windows and macOS evidence sources.

---

### Phase 1 — Create platform service abstraction (no behavior change)
**Goal:** isolate OS-specific code behind interfaces.

**Deliverables**
- Add a `PlatformService` contract for:
  - software discovery/install
  - system probes (hostname/network/os/version)
  - apply operations (power/notifications/remote access/etc.)
  - capability reporting for UI.
- Keep current Windows behavior as default implementation.

**File-level changes**
- `pccfg/services/platform/base.py` *(new)*
  - Define abstract methods + capability model.
- `pccfg/services/platform/windows.py` *(new)*
  - Wrap existing Windows commands and logic.
- `pccfg/services/platform/factory.py` *(new)*
  - Runtime selection by `sys.platform`.
- `pccfg/services/__init__.py`
  - Export platform service helpers.
- `dxm_pc_setup_gui.py`
  - Replace direct OS command calls with platform service calls.

---

### Phase 2 — Refactor Windows paths into the adapter
**Goal:** make Windows implementation explicit and testable before adding macOS behavior.

**Deliverables**
- Move direct PowerShell/registry/winget access into `WindowsPlatformService`.
- Keep UI and domain logic mostly unchanged except for injected service calls.

**File-level changes**
- `pccfg/services/winget.py`
  - Convert to helper utilities consumed by windows adapter.
- `pccfg/services/system_probes.py`
  - Move/bridge functions into windows adapter probe methods.
- `pccfg/domain/apply_catalog.py`
  - Split command definitions into platform-aware action descriptors.
- `dxm_pc_setup_gui.py`
  - Consume descriptors/capabilities from platform service instead of hardcoded Windows assumptions.
- `tests/test_winget.py`, `tests/test_system_probes.py`
  - Update tests to use adapter API surface.

---

### Phase 3 — Add macOS inspect support (read-only first)
**Goal:** ship a safe, useful macOS MVP quickly.

**Deliverables**
- Implement macOS inspect probes and software detection.
- Populate checklist evidence from macOS commands.
- Mark unsupported apply actions as unavailable.

**File-level changes**
- `pccfg/services/platform/macos.py` *(new)*
  - Implement hostname, OS, network, disk, and software detection probes.
- `pccfg/domain/checklist.py`
  - Add platform-aware checklist mapping and fallback labels.
- `pccfg/domain/models.py`
  - Extend evidence model with source tags suitable for macOS probes.
- `profiles/default-profile.json`
  - Add platform metadata and defaults for unsupported tasks.
- `dxm_pc_setup_gui.py`
  - Disable or hide unsupported apply toggles based on capabilities.

---

### Phase 4 — Add selected macOS apply actions
**Goal:** incrementally support low-risk macOS apply operations.

**Deliverables**
- Implement idempotent apply handlers for selected tasks.
- Add rollback/safety notes for destructive or policy-sensitive actions.

**File-level changes**
- `pccfg/domain/apply_catalog.py`
  - Add macOS action descriptors and command builders.
- `pccfg/services/platform/macos.py`
  - Implement apply methods with guardrails and clear failures.
- `dxm_pc_setup_gui.py`
  - Show macOS action availability + reason when blocked.

Suggested first macOS apply targets:
- computer name/hostname
- energy settings that are safe in desktop contexts
- software installs through Homebrew

---

### Phase 5 — Packaging, distribution, and QA hardening
**Goal:** make macOS distribution practical for users.

**Deliverables**
- Build `.app` artifact and optional DMG.
- Document signing + notarization workflow.
- Expand automated tests and smoke test scripts.

**File-level changes**
- `README.md`
  - Add macOS run/build/package instructions.
- `.github/workflows/` *(new or update existing CI workflows)*
  - Add macOS CI job for lint/test/package smoke checks.
- `tests/`
  - Add adapter contract tests and platform-specific fixtures.

---

### Phase 6 — Feature parity review and stabilization
**Goal:** decide parity boundaries and finalize support policy.

**Deliverables**
- Publish support matrix: Windows-only vs macOS-supported tasks.
- Add known limitations section.
- Finalize release checklist for both platforms.

**File-level changes**
- `README.md`
  - Add support matrix + limitation table.
- `docs/software-detection-task-plan.md`
  - Document final detection confidence rules per platform.

## Suggested implementation order (quick wins)
1. Phase 1 + Phase 2 (abstraction + Windows extraction).
2. Phase 3 (macOS Inspect-only MVP).
3. Phase 5 packaging baseline (internal builds).
4. Phase 4 selected apply actions.
5. Phase 6 parity/stabilization.
