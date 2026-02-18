import unittest

from pccfg.domain.models import InstallApp
from pccfg.services.system_probes import (
    SoftwareDetectionSnapshot,
    _pattern_matches_text,
    detect_software_installation_from_snapshot,
)


class PatternMatchingTests(unittest.TestCase):
    def test_word_boundary_match(self) -> None:
        self.assertTrue(_pattern_matches_text("Google Chrome", "Google Chrome"))
        self.assertTrue(_pattern_matches_text("OBS Studio", "OBS Studio 30.0"))

    def test_prevents_substring_false_positive(self) -> None:
        self.assertFalse(_pattern_matches_text("OBS", "Blobster Utility"))


class SnapshotDetectionTests(unittest.TestCase):
    def test_winget_exact_match(self) -> None:
        app = InstallApp("chrome", "Google Chrome", "Google.Chrome", "cat", "software_google_chrome")
        snapshot = SoftwareDetectionSnapshot(
            winget_ids=frozenset({"google.chrome"}),
            registry_rows=(),
            executable_names=frozenset(),
            shortcut_names=frozenset(),
        )
        ok, detail = detect_software_installation_from_snapshot(app, snapshot)
        self.assertTrue(ok)
        self.assertIn("winget snapshot", detail)

    def test_registry_name_required_not_publisher_only(self) -> None:
        app = InstallApp(
            "chrome",
            "Google Chrome",
            "Google.Chrome",
            "cat",
            "software_google_chrome",
            detect_display_names=("Google Chrome",),
            detect_publishers=("Google LLC",),
        )
        snapshot = SoftwareDetectionSnapshot(
            winget_ids=frozenset(),
            registry_rows=(
                {
                    "DisplayName": "Google Drive",
                    "Publisher": "Google LLC",
                    "Scope": "HKLM",
                },
            ),
            executable_names=frozenset(),
            shortcut_names=frozenset(),
        )
        ok, detail = detect_software_installation_from_snapshot(app, snapshot)
        self.assertFalse(ok)
        self.assertEqual("Not installed", detail)

    def test_path_and_shortcut_combined_match(self) -> None:
        app = InstallApp(
            "streamdeck",
            "Elgato Stream Deck",
            "Elgato.StreamDeck",
            "cat",
            "software_stream_deck",
            detect_executables=("StreamDeck.exe",),
            detect_shortcuts=("Stream Deck",),
        )
        snapshot = SoftwareDetectionSnapshot(
            winget_ids=frozenset(),
            registry_rows=(),
            executable_names=frozenset({"streamdeck exe"}),
            shortcut_names=frozenset({"stream deck"}),
        )
        ok, detail = detect_software_installation_from_snapshot(app, snapshot)
        self.assertTrue(ok)
        self.assertIn("path+shortcut", detail)


if __name__ == "__main__":
    unittest.main()
