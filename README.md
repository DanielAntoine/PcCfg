# PcCfg

PcCfg is a PyQt5 desktop utility for preparing Windows workstations with a repeatable checklist-driven workflow. It combines **Inspect** checks (safe validation/reporting) with **Run** actions (optional configuration tasks) so technicians can standardize fresh-machine setup.

## Highlights

- Checklist-first UI with status chips: `PASS`, `FAIL`, `PENDING`, `RUNNING`, and `NA`.
- Two main workflows:
  - **Inspect**: gathers system and software readiness signals without applying changes.
  - **Run**: executes selected setup/apply tasks.
- Automatic hostname generation using:
  - `{ClientNamePascal}-{Role4LUpper}-{numbering00}`
- Profile support:
  - Load/save checklist state from JSON profiles in `profiles/`.
  - Default profile: `profiles/default-profile.json`.
- Built-in readiness probes for common setup requirements, including:
  - Wi-Fi adapter presence and connection state
  - Internet reachability
  - Remote Desktop readiness
  - SSH readiness
  - Selected software installation checks
- Windows elevation support:
  - On Windows, the app can relaunch itself as Administrator when needed.

## Requirements

- Python 3.10+
- PyQt5
- Windows 10/11 for full inspect/apply behavior

> Note: Many inspect/apply commands rely on Windows tools (`powershell`, `reg`, `netsh`, `winget`, etc.). Running on non-Windows platforms is mainly useful for development and static checks.

## Run the app

From the repository root:

```bash
python dxm_pc_setup_gui.py
```

## Build a Windows EXE (PyInstaller)


Example command from the repo root:

```powershell
pyinstaller --noconfirm --onefile --windowed --name PcCfg --icon Icon/PCSetup.ico --add-data "style;style" --add-data "profiles;profiles" --add-data "Icon;Icon" dxm_pc_setup_gui.py
```

## Repository structure

- `dxm_pc_setup_gui.py` - main PyQt application entrypoint and UI/controller logic
- `pccfg/domain/` - checklist models/catalogs and hostname/apply domain logic
- `pccfg/services/` - command execution, persistence, probe detection, checklist synchronization
- `profiles/` - default and user profile JSON files
- `style/` - Qt stylesheet (`app.qss`)
- `Icon/` - application icon assets

## Practical notes

- For unattended package installs in task commands, prefer silent flags:
  - `winget install --silent --accept-package-agreements --accept-source-agreements`
  - `choco install -y --no-progress`
- Keep install commands idempotent where possible (check if already installed before running again).
- Use **Inspect** first, then run only the apply tasks needed for that machine.
