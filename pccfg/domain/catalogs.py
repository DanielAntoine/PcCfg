from __future__ import annotations

from .models import InstallApp, ManualInstallApp

INSTALL_APPS: tuple[InstallApp, ...] = (
    InstallApp(
        "chrome",
        "Google Chrome",
        "Google.Chrome",
        "Utilities for creators",
        "software_google_chrome",
        detect_display_names=("Google Chrome",),
        detect_publishers=("Google LLC",),
        detect_executables=("chrome.exe",),
        detect_shortcuts=("Google Chrome",),
    ),
    InstallApp("shotcut", "Shotcut", "Meltytech.Shotcut", "Core video editing / post", "software_shotcut"),
    InstallApp("kdenlive", "Kdenlive", "KDE.Kdenlive", "Core video editing / post", "software_kdenlive"),
    InstallApp("handbrake", "HandBrake", "HandBrake.HandBrake", "Core video editing / post", "software_handbrake"),
    InstallApp("avidemux", "Avidemux", "Avidemux.Avidemux", "Core video editing / post", "software_avidemux"),
    InstallApp(
        "obs",
        "OBS Studio",
        "OBSProject.OBSStudio",
        "Capture / streaming / recording",
        "software_obs_studio",
        detect_executables=("obs64.exe", "obs32.exe"),
        detect_shortcuts=("OBS Studio",),
    ),
    InstallApp("sharex", "ShareX", "ShareX.ShareX", "Capture / streaming / recording", "software_sharex"),
    InstallApp("audacity", "Audacity", "Audacity.Audacity", "Audio for video", "software_audacity"),
    InstallApp("reaper", "REAPER", "Cockos.REAPER", "Audio for video", "software_reaper"),
    InstallApp(
        "vlc",
        "VLC media player",
        "VideoLAN.VLC",
        "Codecs / media tools",
        "software_vlc_media_player",
        detect_executables=("vlc.exe",),
        detect_shortcuts=("VLC media player",),
    ),
    InstallApp(
        "ffmpeg",
        "FFmpeg",
        "Gyan.FFmpeg",
        "Codecs / media tools",
        "software_ffmpeg",
        detect_executables=("ffmpeg.exe",),
    ),
    InstallApp("mediainfo", "MediaInfo", "MediaArea.MediaInfo.GUI", "Codecs / media tools", "software_mediainfo"),
    InstallApp("mkvtoolnix", "MKVToolNix", "MoritzBunkus.MKVToolNix", "Codecs / media tools", "software_mkvtoolnix"),
    InstallApp("blender", "Blender", "BlenderFoundation.Blender", "Motion graphics / VFX / 3D", "software_blender"),
    InstallApp("natron", "Natron", "Natron.Natron", "Motion graphics / VFX / 3D", "software_natron"),
    InstallApp(
        "notepadpp",
        "Notepad++",
        "Notepad++.Notepad++",
        "Utilities for creators",
        "software_notepadpp",
        detect_display_names=("Notepad++",),
        detect_executables=("notepad++.exe",),
        detect_shortcuts=("Notepad++",),
    ),
    InstallApp(
        "seven_zip",
        "7-Zip",
        "7zip.7zip",
        "Utilities for creators",
        "software_7_zip",
        detect_display_names=("7-Zip",),
        detect_executables=("7z.exe", "7zfm.exe"),
        detect_shortcuts=("7-Zip",),
    ),
    InstallApp("everything", "Everything", "voidtools.Everything", "Utilities for creators", "software_everything"),
    InstallApp("crystaldiskinfo", "CrystalDiskInfo", "CrystalDewWorld.CrystalDiskInfo", "Utilities for creators", "software_crystaldiskinfo"),
    InstallApp("hwinfo", "HWInfo", "REALiX.HWiNFO", "Utilities for creators", "software_hwinfo"),
    InstallApp("anydesk", "AnyDesk", "AnyDeskSoftwareGmbH.AnyDesk", "Remote support", "software_anydesk"),
    InstallApp(
        "teamviewer",
        "TeamViewer",
        "TeamViewer.TeamViewer",
        "Remote support",
        "software_teamviewer",
        detect_display_names=("TeamViewer",),
    ),
    InstallApp(
        "parsec",
        "Parsec",
        "Parsec.Parsec",
        "Remote support",
        "software_parsec",
        detect_executables=("parsec.exe",),
        detect_shortcuts=("Parsec",),
    ),
    InstallApp(
        "companion",
        "Bitfocus Companion",
        "Bitfocus.Companion",
        "Control surfaces",
        "software_companion",
        detect_executables=("companion.exe",),
        detect_shortcuts=("Companion", "Bitfocus Companion"),
    ),
    InstallApp(
        "streamdeck",
        "Elgato Stream Deck",
        "Elgato.StreamDeck",
        "Control surfaces",
        "software_stream_deck",
        detect_executables=("StreamDeck.exe",),
        detect_shortcuts=("Stream Deck", "Elgato Stream Deck"),
    ),
)

SOFTWARE_INSPECT_APPS: tuple[InstallApp, ...] = tuple(
    app for app in INSTALL_APPS if app.inspect_item_id
)

MANUAL_INSTALL_APPS: tuple[ManualInstallApp, ...] = (
    ManualInstallApp("davinci_resolve", "DaVinci Resolve", "Video editing / color grading", "https://www.blackmagicdesign.com/products/davinciresolve"),
    ManualInstallApp("creative_cloud", "Adobe Creative Cloud", "Creative suite management", "https://www.adobe.com/creativecloud/desktop-app.html"),
    ManualInstallApp("blackmagic_desktop_video", "Blackmagic Desktop Video", "Capture cards / I/O", "https://www.blackmagicdesign.com/support/family/capture-and-playback"),
    ManualInstallApp("vmix", "vMix", "Live production / switching", "https://www.vmix.com/software/download.aspx"),
    ManualInstallApp("nvidia_drivers", "NVIDIA Drivers", "GPU drivers", "https://www.nvidia.com/Download/index.aspx"),
    ManualInstallApp("screenconnect", "ScreenConnect", "Remote support", "https://screenconnect.connectwise.com/download"),
)


def validate_install_app_catalog() -> None:
    seen_keys: set[str] = set()
    seen_inspect_ids: set[str] = set()
    for app in INSTALL_APPS:
        if app.key in seen_keys:
            raise ValueError(f"Duplicate install app key: {app.key}")
        seen_keys.add(app.key)

        if not app.inspect_item_id:
            continue
        if app.inspect_item_id in seen_inspect_ids:
            raise ValueError(f"Duplicate inspect item id: {app.inspect_item_id}")
        seen_inspect_ids.add(app.inspect_item_id)
