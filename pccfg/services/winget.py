from __future__ import annotations


_ALREADY_INSTALLED_MARKERS = (
    "Found an existing package already installed.",
    "No available upgrade found.",
    "No newer package versions are available from the configured sources.",
)


def is_noop_install_success(output: str) -> bool:
    """Return True when winget reports the package is already installed/up-to-date."""
    normalized = output.lower()
    return all(marker.lower() in normalized for marker in _ALREADY_INSTALLED_MARKERS)
