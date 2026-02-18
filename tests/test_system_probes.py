import unittest
from unittest.mock import patch

import sys
import types

if "PyQt5" not in sys.modules:
    pyqt5 = types.ModuleType("PyQt5")
    qtcore = types.ModuleType("QtCore")

    class _DummyQThread:
        @staticmethod
        def msleep(_ms: int) -> None:
            return None

    qtcore.QThread = _DummyQThread
    pyqt5.QtCore = qtcore
    sys.modules["PyQt5"] = pyqt5
    sys.modules["PyQt5.QtCore"] = qtcore


from pccfg.domain.models import InstallApp
from pccfg.services.system_probes import (
    SoftwareDetectionSnapshot,
    _collect_winget_ids,
    _collect_executable_names,
    _extract_winget_package_rows,
    _collect_shortcut_names,
    _shortcut_cache,
    _shortcut_cache_lock,
    _pattern_matches_text,
    collect_software_detection_snapshot,
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
            appx_names=frozenset(),
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
            appx_names=frozenset(),
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

    def test_path_and_shortcut_evidence_does_not_mark_installed(self) -> None:
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
            appx_names=frozenset(),
            registry_rows=(),
            executable_names=frozenset({"streamdeck exe"}),
            shortcut_names=frozenset({"stream deck"}),
        )
        ok, detail = detect_software_installation_from_snapshot(app, snapshot)
        self.assertFalse(ok)
        self.assertEqual("Not installed", detail)

    def test_appx_match_from_winget_id(self) -> None:
        app = InstallApp("terminal", "Windows Terminal", "Microsoft.WindowsTerminal", "cat", "software_terminal")
        snapshot = SoftwareDetectionSnapshot(
            winget_ids=frozenset(),
            appx_names=frozenset({"microsoft windowsterminal"}),
            registry_rows=(),
            executable_names=frozenset(),
            shortcut_names=frozenset(),
        )
        ok, detail = detect_software_installation_from_snapshot(app, snapshot)
        self.assertTrue(ok)
        self.assertIn("appx snapshot", detail)


class SnapshotCollectionTests(unittest.TestCase):
    @patch("pccfg.services.system_probes._collect_shortcut_names", return_value=(frozenset({"shortcut"}), True))
    @patch("pccfg.services.system_probes._collect_executable_names", return_value=(frozenset({"app exe"}), True))
    @patch("pccfg.services.system_probes._collect_registry_rows", return_value=(({"DisplayName": "A"},), True))
    @patch("pccfg.services.system_probes._collect_appx_names", return_value=(frozenset({"microsoft app"}), True))
    @patch("pccfg.services.system_probes._collect_winget_ids", return_value=(frozenset({"a.b"}), True))
    def test_collect_snapshot_keeps_ok_semantics(
        self,
        _winget: object,
        _appx: object,
        _registry: object,
        _execs: object,
        _shortcuts: object,
    ) -> None:
        snapshot, detail = collect_software_detection_snapshot()
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual("OK", detail)
        self.assertIn("a.b", snapshot.winget_ids)
        self.assertIn("microsoft app", snapshot.appx_names)


class WingetParsingTests(unittest.TestCase):
    def test_extract_rows_from_sources_payload(self) -> None:
        rows = _extract_winget_package_rows(
            '{"Sources":[{"Packages":[{"PackageIdentifier":"Git.Git"},{"PackageIdentifier":"Google.Chrome"}]}]}'
        )
        self.assertEqual(2, len(rows))
        self.assertEqual("Git.Git", rows[0]["PackageIdentifier"])

    @patch(
        "pccfg.services.system_probes.run_command_with_options",
        return_value=(
            0,
            '{"Sources":[{"Packages":[{"PackageIdentifier":"Git.Git"},{"PackageIdentifier":"Google.Chrome"}]}]}',
        ),
    )
    def test_collect_winget_ids_parses_nested_json(self, _run: object) -> None:
        winget_ids, ok = _collect_winget_ids()
        self.assertTrue(ok)
        self.assertIn("git.git", winget_ids)
        self.assertIn("google.chrome", winget_ids)


class ProbeBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        with _shortcut_cache_lock:
            _shortcut_cache["roots"] = ()
            _shortcut_cache["timestamp"] = 0.0
            _shortcut_cache["names"] = frozenset()

    @patch("pccfg.services.system_probes.run_command_with_options", return_value=(0, '["ffmpeg.exe", "git.exe"]'))
    def test_collect_executable_names_normalizes_json_list(self, _run: object) -> None:
        names, ok = _collect_executable_names()
        self.assertTrue(ok)
        self.assertIn("ffmpeg exe", names)
        self.assertIn("git exe", names)

    def test_collect_shortcut_names_uses_cache(self) -> None:
        with patch(
            "pccfg.services.system_probes.run_command_with_options",
            return_value=(0, '["Google Chrome", "OBS Studio"]'),
        ) as mock_run:
            first_names, first_ok = _collect_shortcut_names()
            second_names, second_ok = _collect_shortcut_names()

        self.assertTrue(first_ok)
        self.assertTrue(second_ok)
        self.assertEqual(first_names, second_names)
        self.assertEqual(1, mock_run.call_count)


if __name__ == "__main__":
    unittest.main()
