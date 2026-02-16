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
