from __future__ import annotations

from .models import InstallApp, ManualInstallApp

INSTALL_APPS: tuple[InstallApp, ...] = (
    InstallApp("chrome", "Google Chrome", "Google.Chrome", "Utilities for creators"),
    InstallApp("shotcut", "Shotcut", "Meltytech.Shotcut", "Core video editing / post"),
    InstallApp("kdenlive", "Kdenlive", "KDE.Kdenlive", "Core video editing / post"),
    InstallApp("handbrake", "HandBrake", "HandBrake.HandBrake", "Core video editing / post"),
    InstallApp("avidemux", "Avidemux", "Avidemux.Avidemux", "Core video editing / post"),
    InstallApp("obs", "OBS Studio", "OBSProject.OBSStudio", "Capture / streaming / recording"),
    InstallApp("sharex", "ShareX", "ShareX.ShareX", "Capture / streaming / recording"),
    InstallApp("audacity", "Audacity", "Audacity.Audacity", "Audio for video"),
    InstallApp("reaper", "REAPER", "Cockos.REAPER", "Audio for video"),
    InstallApp("vlc", "VLC media player", "VideoLAN.VLC", "Codecs / media tools"),
    InstallApp("ffmpeg", "FFmpeg", "Gyan.FFmpeg", "Codecs / media tools"),
    InstallApp("mediainfo", "MediaInfo", "MediaArea.MediaInfo.GUI", "Codecs / media tools"),
    InstallApp("mkvtoolnix", "MKVToolNix", "MoritzBunkus.MKVToolNix", "Codecs / media tools"),
    InstallApp("blender", "Blender", "BlenderFoundation.Blender", "Motion graphics / VFX / 3D"),
    InstallApp("natron", "Natron", "Natron.Natron", "Motion graphics / VFX / 3D"),
    InstallApp("notepadpp", "Notepad++", "Notepad++.Notepad++", "Utilities for creators"),
    InstallApp("seven_zip", "7-Zip", "7zip.7zip", "Utilities for creators"),
    InstallApp("everything", "Everything", "voidtools.Everything", "Utilities for creators"),
    InstallApp("crystaldiskinfo", "CrystalDiskInfo", "CrystalDewWorld.CrystalDiskInfo", "Utilities for creators"),
    InstallApp("hwinfo", "HWInfo", "REALiX.HWiNFO", "Utilities for creators"),
    InstallApp("anydesk", "AnyDesk", "AnyDeskSoftwareGmbH.AnyDesk", "Remote support"),
    InstallApp("teamviewer", "TeamViewer", "TeamViewer.TeamViewer", "Remote support"),
)

MANUAL_INSTALL_APPS: tuple[ManualInstallApp, ...] = (
    ManualInstallApp("davinci_resolve", "DaVinci Resolve", "Video editing / color grading", "https://www.blackmagicdesign.com/products/davinciresolve"),
    ManualInstallApp("blackmagic_desktop_video", "Blackmagic Desktop Video", "Capture cards / I/O", "https://www.blackmagicdesign.com/support/family/capture-and-playback"),
    ManualInstallApp("vmix", "vMix", "Live production / switching", "https://www.vmix.com/software/download.aspx"),
    ManualInstallApp("streamdeck", "Elgato Stream Deck", "Control surfaces", "https://www.elgato.com/downloads"),
    ManualInstallApp("screenconnect", "ScreenConnect", "Remote support", "https://screenconnect.connectwise.com/download"),
)
