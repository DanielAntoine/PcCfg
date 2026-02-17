from __future__ import annotations

from pathlib import Path

from .models import ChecklistField, ChecklistItem, ChecklistSection

CHECKLIST_LOG_FILE = Path(__file__).resolve().parents[2] / "installation_checklist_log.json"
CHECKLIST_PROFILE_DIR = Path(__file__).resolve().parents[2] / "profiles"
DEFAULT_PROFILE_FILE = CHECKLIST_PROFILE_DIR / "default-profile.json"
CHECKLIST_TASK_MAX_LEN = 52
TECHNICIAN_DEFAULT_OPTIONS: tuple[str, ...] = (
    "Ludovic Hamel",
    "Pierre-Luc Paré",
    "Daniel Antoine Lambert",
    "Jerome Pelletier",
    "Dominic Bourget",
    "Eric Nolin",
    "Adam Giraudias",
)

COMPUTER_ROLE_OPTIONS: tuple[str, ...] = (
    "Editor",
    "Colorimetrie",
    "Server",
    "Datawringling",
)


CHECKLIST_FIELDS: tuple[ChecklistField, ...] = (
    ChecklistField("client_name", "Client name", "text"),
    ChecklistField("computer_role", "Computer role", "text"),
    ChecklistField("numbering", "Numbering00 (e.g., 01, 02, 03)", "numbering"),

    ChecklistField("hostname", "Hostname/User: {ClientNamePascal}-{Role4LUpper}-{numbering00}", "text"),
    ChecklistField("inventory_id", "Inventory ID", "text"),
    ChecklistField("technician", "Technicien", "technician"),
    ChecklistField("date", "Date", "date"),
    ChecklistField("installed_cards", "Installed cards: BMD / 10GbE / others", "text"),
    ChecklistField("file_name", "File name: YYYYMMDD_InventoryID_Step_{enumeration000}.jpg", "text"),
    ChecklistField("screenconnect_id", "Record ScreenConnect ID", "text"),
)

FIELDS_BY_ID = {field.field_id: field for field in CHECKLIST_FIELDS}
FIELDS_BY_LABEL = {field.label: field for field in CHECKLIST_FIELDS}
FIELD_IDS_BY_LABEL = {field.label: field.field_id for field in CHECKLIST_FIELDS}
FIELD_LABELS_BY_ID = {field.field_id: field.label for field in CHECKLIST_FIELDS}

SECTIONS: tuple[ChecklistSection, ...] = (
    ChecklistSection(
        "workstation_info",
        "0) Workstation information",
        (
            ChecklistItem("client_name", "Client name"),
            ChecklistItem("computer_role", "Computer role"),
            ChecklistItem("numbering", "Numbering00 (e.g., 01, 02, 03)"),
            ChecklistItem("inventory_id", "Inventory ID"),
            ChecklistItem("technician", "Technicien"),
            ChecklistItem("installed_cards", "Installed cards: BMD / 10GbE / others"),
        ),
    ),
    ChecklistSection(
        "physical_inspection",
        "1) Physical inspection",
        (
            ChecklistItem("open_case", "Open the case + take UNBOX photos"),
            ChecklistItem("verify_components", "Verify components against invoice (RAM/SSD/GPU/cards)"),
            ChecklistItem("check_cables", "Check cables (nothing in fans / nothing loose)"),
        ),
    ),
    ChecklistSection("initial_boot", "2) Initial boot", (
        ChecklistItem("start_pc", "Start the PC"),
        ChecklistItem("fans_spin", "Check that all fans spin (CPU/GPU/case)"),
    )),
    ChecklistSection(
        "bios_uefi",
        "3) BIOS / UEFI",
        (
            ChecklistItem("update_bios", "Update BIOS (version before/after)"),
            ChecklistItem("enable_4g", "Enable 4G Decoding"),
            ChecklistItem("enable_rebar", "Enable Resizable BAR support (ReBAR)"),
            ChecklistItem("uefi_mode", "Boot in UEFI mode (CSM OFF)"),
            ChecklistItem("enable_xmp", "Enable XMP / EXPO"),
            ChecklistItem("save_reboot", "Save settings / reboot"),
        ),
    ),
    ChecklistSection(
        "windows_update_drivers",
        "4) Windows Update + Drivers",
        (

            ChecklistItem("rename_pc", "Rename the PC ({ClientNamePascal}-{Role4LUpper}-{numbering00})"),
            ChecklistItem("windows_update", 'Run Windows Update until "Up to date"'),
            ChecklistItem("install_chipset", "Install chipset drivers"),
            ChecklistItem("install_network", "Install network drivers (LAN/10GbE/Wi-Fi)"),
            ChecklistItem("install_gpu", "Install GPU drivers (NVIDIA/AMD)"),
            ChecklistItem("install_audio", "Install audio drivers"),
            ChecklistItem("install_bmd", "Install Blackmagic Desktop Video (if card is present)"),
            ChecklistItem("install_other", "Install other card drivers (USB/RAID/etc)"),
            ChecklistItem("devmgr_validation", "Validation: Device Manager = 0 unknown devices"),
        ),
    ),
    ChecklistSection("gpu_nvidia", "5) GPU NVIDIA", (
        ChecklistItem("nvidia_perf", "NVIDIA Control Panel > Power management mode > Prefer maximum performance"),
    )),
    ChecklistSection("cleanup", "6) Cleanup (manual)", (
        ChecklistItem("remove_bloat", "Remove bloatware"),
        ChecklistItem("startup_apps", "Check startup apps (Task Manager > Startup)"),
    )),
    ChecklistSection("power_sleep", "7) Power / Sleep / Fast Startup", (
        ChecklistItem("power_perf", "Power plan: Performance (High performance)"),
        ChecklistItem("sleep_never", "Sleep: Never (AC)"),
        ChecklistItem("hibernate_off", "Hibernate: Off"),
        ChecklistItem("disk_sleep", "Disk sleep: Never"),
        ChecklistItem("monitor_timeout", "Monitor timeout: 30 min"),
        ChecklistItem("disable_fast_startup", "Disable Fast Startup"),
    )),
    ChecklistSection("game_bar", "8) Game Bar / Game DVR", (
        ChecklistItem("disable_game_bar", "Disable Game Bar / Game DVR"),
    )),
    ChecklistSection("performance_options", "9) Performance options", (
        ChecklistItem("best_perf", "Enable Best performance + keep thumbnails"),
    )),
    ChecklistSection("notifications", "10) Notifications", (
        ChecklistItem("disable_notifications", "Disable Windows notifications (current user)"),
    )),
    ChecklistSection("disks", "11) Disks", (ChecklistItem("disks_visible", "Ensure all disks are visible"),)),
    ChecklistSection(
        "network_support",
        "12) Network & support",
        (
            ChecklistItem("test_usb", "Test USB ports"),
            ChecklistItem("test_wifi", "Test Wi-Fi"),
            ChecklistItem("validate_ssh", "Validate SSH (installed + running + listening:22)"),
            ChecklistItem("enable_rdp", "Enable Remote Desktop (service + firewall + NLA)"),
            ChecklistItem("record_scid", "Record ScreenConnect ID"),
            ChecklistItem("vault_passwords", "Passwords and keys stored in Vault"),
            ChecklistItem("test_remote", "Test remote connection"),
        ),
    ),
    ChecklistSection(
        "software",
        "13) Software",
        (
            ChecklistItem("software_google_chrome", "Google Chrome"),
            ChecklistItem("software_shotcut", "Shotcut"),
            ChecklistItem("software_kdenlive", "Kdenlive"),
            ChecklistItem("software_handbrake", "HandBrake"),
            ChecklistItem("software_avidemux", "Avidemux"),
            ChecklistItem("software_obs_studio", "OBS Studio"),
            ChecklistItem("software_sharex", "ShareX"),
            ChecklistItem("software_audacity", "Audacity"),
            ChecklistItem("software_reaper", "REAPER"),
            ChecklistItem("software_vlc_media_player", "VLC media player"),
            ChecklistItem("software_ffmpeg", "FFmpeg"),
            ChecklistItem("software_mediainfo", "MediaInfo"),
            ChecklistItem("software_mkvtoolnix", "MKVToolNix"),
            ChecklistItem("software_blender", "Blender"),
            ChecklistItem("software_natron", "Natron"),
            ChecklistItem("software_notepadpp", "Notepad++"),
            ChecklistItem("software_7_zip", "7-Zip"),
            ChecklistItem("software_everything", "Everything"),
            ChecklistItem("software_crystaldiskinfo", "CrystalDiskInfo"),
            ChecklistItem("software_hwinfo", "HWInfo"),
            ChecklistItem("software_anydesk", "AnyDesk"),
            ChecklistItem("software_teamviewer", "TeamViewer"),
            ChecklistItem("software_parsec", "Parsec"),
            ChecklistItem("software_companion", "Bitfocus Companion"),
            ChecklistItem("software_stream_deck", "Elgato Stream Deck"),
            ChecklistItem("software_screenconnect", "ScreenConnect"),
        ),
    ),
    ChecklistSection("capture_validation", "14) Capture card validation", (
        ChecklistItem("test_io_media_express", "Test I/O via Blackmagic Media Express"),
        ChecklistItem("test_vmix", "Test in vMix (if required)"),
        ChecklistItem("test_streamdeck", "Test StreamDeck in vMix (if required)"),
    )),
    ChecklistSection("repack", "15) Repack / InstaPak", (
        ChecklistItem("pack_before", "Photo PACK_BEFORE_001"),
        ChecklistItem("insert_instapak", "Insert InstaPak, close case, wait for foam expansion"),
        ChecklistItem("pack_after", "Photo PACK_AFTER_001"),
        ChecklistItem("remove_verify", "Remove InstaPak to verify the client can remove it"),
        ChecklistItem("reinsert_final", "Reinsert InstaPak + close + final packaging"),
    )),
    ChecklistSection(
        "evidence_photos",
        "16) Evidence / Photos",
        (
            ChecklistItem("attach_photos", "Attach photos to the client inventory record or the ticket"),
        ),
    ),
)

ITEM_LABELS_BY_ID = {item.item_id: item.label for section in SECTIONS for item in section.items}
ITEM_IDS_BY_LABEL = {item.label: item.item_id for section in SECTIONS for item in section.items}
