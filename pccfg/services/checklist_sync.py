from __future__ import annotations


def sync_item_state_from_info_value(current_state: str | None, value: str) -> tuple[str, str, str]:
    if current_state == "NA":
        return "NA", "NA", "Not applicable"
    if value.strip():
        return "CHECKED", "PASS", "Filled from setup information"
    return "UNCHECKED", "PENDING", "Waiting for setup information"


def sync_inspect_status(
    current_state: str | None,
    task_id: str,
    status: str,
    should_check: bool,
) -> tuple[str | None, bool]:
    is_software_item = task_id.startswith("software_")
    if current_state == "NA" and not (is_software_item and should_check and status == "PASS"):
        return None, False

    next_state = current_state
    if current_state == "NA":
        next_state = "UNCHECKED"

    if should_check and status == "PASS":
        return "CHECKED", True
    if status in {"FAIL", "PENDING"}:
        return "UNCHECKED", False
    return next_state, False
