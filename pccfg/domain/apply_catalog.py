from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ApplyTaskDefinition:
    key: str
    label: str
    commands: tuple[tuple[str, ...], ...]


APPLY_TASK_DEFINITIONS: tuple[ApplyTaskDefinition, ...] = (
    ApplyTaskDefinition("power_plan", "Set power plan to High performance", (("powercfg", "/setactive", "SCHEME_MIN"),)),
    ApplyTaskDefinition(
        "power_timeouts",
        "Configure timeouts (Sleep/Hibernate/Disk=Never, Monitor=30m)",
        (
            ("powercfg", "/hibernate", "off"),
            ("powercfg", "/change", "standby-timeout-ac", "0"),
            ("powercfg", "/change", "standby-timeout-dc", "0"),
            ("powercfg", "/change", "hibernate-timeout-ac", "0"),
            ("powercfg", "/change", "hibernate-timeout-dc", "0"),
            ("powercfg", "/change", "disk-timeout-ac", "0"),
            ("powercfg", "/change", "disk-timeout-dc", "0"),
            ("powercfg", "/change", "monitor-timeout-ac", "30"),
            ("powercfg", "/change", "monitor-timeout-dc", "30"),
        ),
    ),
    ApplyTaskDefinition(
        "usb_suspend",
        "Disable USB selective suspend (AC/DC)",
        (
            ("powercfg", "/setacvalueindex", "SCHEME_MIN", "2a737441-1930-4402-8d77-b2bebba308a3", "48e6b7a6-50f5-4782-a5d4-53bb8f07e226", "0"),
            ("powercfg", "/setdcvalueindex", "SCHEME_MIN", "2a737441-1930-4402-8d77-b2bebba308a3", "48e6b7a6-50f5-4782-a5d4-53bb8f07e226", "0"),
            ("powercfg", "/setactive", "SCHEME_MIN"),
        ),
    ),
    ApplyTaskDefinition(
        "fast_startup",
        "Disable Fast Startup",
        (("reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power", "/v", "HiberbootEnabled", "/t", "REG_DWORD", "/d", "0", "/f"),),
    ),
    ApplyTaskDefinition(
        "game_dvr",
        "Disable Game Bar / Game DVR",
        (
            ("reg", "add", "HKCU\\System\\GameConfigStore", "/v", "GameDVR_Enabled", "/t", "REG_DWORD", "/d", "0", "/f"),
            ("reg", "add", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR", "/v", "AppCaptureEnabled", "/t", "REG_DWORD", "/d", "0", "/f"),
            ("reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR", "/v", "AllowGameDVR", "/t", "REG_DWORD", "/d", "0", "/f"),
        ),
    ),
    ApplyTaskDefinition(
        "visual_effects",
        "Set visual effects (best performance, keep thumbnails)",
        (
            ("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects", "/v", "VisualFXSetting", "/t", "REG_DWORD", "/d", "2", "/f"),
            ("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "/v", "IconsOnly", "/t", "REG_DWORD", "/d", "0", "/f"),
        ),
    ),
    ApplyTaskDefinition(
        "notifications",
        "Disable Windows notifications (current user)",
        (
            ("reg", "add", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications", "/v", "ToastEnabled", "/t", "REG_DWORD", "/d", "0", "/f"),
            ("reg", "add", "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer", "/v", "DisableNotificationCenter", "/t", "REG_DWORD", "/d", "1", "/f"),
        ),
    ),
)
