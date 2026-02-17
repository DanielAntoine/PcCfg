from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class ApplyTask:
    key: str
    label: str
    action: Callable[[], list[list[str]]]


@dataclass
class InstallApp:
    key: str
    label: str
    winget_id: str
    category: str
    inspect_item_id: str | None = None
    detect_display_names: tuple[str, ...] = ()
    detect_publishers: tuple[str, ...] = ()


@dataclass
class ManualInstallApp:
    key: str
    label: str
    category: str
    website_url: str


@dataclass
class ExecutionStep:
    label: str
    commands: list[list[str]]


@dataclass(frozen=True)
class ChecklistField:
    field_id: str
    label: str
    field_type: str


@dataclass(frozen=True)
class ChecklistItem:
    item_id: str
    label: str


@dataclass(frozen=True)
class ChecklistSection:
    section_id: str
    label: str
    items: tuple[ChecklistItem, ...]
