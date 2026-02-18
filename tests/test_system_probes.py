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
    _extract_winget_package_rows,
    collect_software_detection_snapshot,
    detect_software_installation_from_snapshot,
)


class SnapshotDetectionTests(unittest.TestCase):
    def test_winget_exact_match(self) -> None:
        app = InstallApp("chrome", "Google Chrome", "Google.Chrome", "cat", "software_google_chrome")
        snapshot = SoftwareDetectionSnapshot(winget_ids=frozenset({"google.chrome"}))
        ok, detail = detect_software_installation_from_snapshot(app, snapshot)
        self.assertTrue(ok)
        self.assertIn("winget snapshot", detail)

    def test_only_winget_is_used(self) -> None:
        app = InstallApp("terminal", "Windows Terminal", "Microsoft.WindowsTerminal", "cat", "software_terminal")
        snapshot = SoftwareDetectionSnapshot(winget_ids=frozenset())
        ok, detail = detect_software_installation_from_snapshot(app, snapshot)
        self.assertFalse(ok)
        self.assertEqual("Not installed", detail)


class SnapshotCollectionTests(unittest.TestCase):
    @patch("pccfg.services.system_probes._collect_winget_ids", return_value=(frozenset({"a.b"}), True))
    def test_collect_snapshot_keeps_ok_semantics(self, _winget: object) -> None:
        snapshot, detail = collect_software_detection_snapshot()
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual("OK", detail)
        self.assertIn("a.b", snapshot.winget_ids)

    @patch("pccfg.services.system_probes._collect_winget_ids", return_value=(frozenset(), False))
    def test_collect_snapshot_returns_unable_to_query_when_winget_fails(self, _winget: object) -> None:
        snapshot, detail = collect_software_detection_snapshot()
        self.assertIsNone(snapshot)
        self.assertEqual("Unable to query", detail)


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


if __name__ == "__main__":
    unittest.main()
