from __future__ import annotations

import json
from pathlib import Path

from pccfg.domain.checklist import FIELD_IDS_BY_LABEL, ITEM_IDS_BY_LABEL


def save_checklist_state(
    path: Path,
    checklist_values_by_item_id: dict[str, str],
    info_values_by_field_id: dict[str, str],
) -> None:
    payload = {
        "items": checklist_values_by_item_id,
        "info": info_values_by_field_id,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_checklist_state(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    if not path.exists():
        return {}, {}

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw_items = raw.get("items", {})
    raw_info = raw.get("info", {})

    item_state: dict[str, str] = {}
    for key, value in raw_items.items():
        item_id = ITEM_IDS_BY_LABEL.get(key, key)
        if isinstance(value, str):
            normalized = value.upper()
            if normalized in {"CHECKED", "UNCHECKED", "NA"}:
                item_state[item_id] = normalized
                continue
        item_state[item_id] = "CHECKED" if bool(value) else "UNCHECKED"

    info_state: dict[str, str] = {}
    for key, value in raw_info.items():
        field_id = FIELD_IDS_BY_LABEL.get(key, key)
        info_state[field_id] = str(value)

    return item_state, info_state
