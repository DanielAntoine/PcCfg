import unittest

from pccfg.services.winget import is_noop_install_success


class WingetNoopInstallTests(unittest.TestCase):
    def test_detects_already_installed_no_upgrade_message(self) -> None:
        output = "\n".join(
            (
                "Found an existing package already installed. Trying to upgrade the installed package...",
                "No available upgrade found.",
                "No newer package versions are available from the configured sources.",
            )
        )
        self.assertTrue(is_noop_install_success(output))

    def test_returns_false_when_markers_missing(self) -> None:
        output = "No package found matching input criteria."
        self.assertFalse(is_noop_install_success(output))


if __name__ == "__main__":
    unittest.main()
