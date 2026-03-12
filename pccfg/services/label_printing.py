from __future__ import annotations

from dataclasses import dataclass

from pccfg.services.barcode_code128 import has_invalid_code128b_chars
from pccfg.services.barcode_code39 import has_invalid_code39_chars

LABEL_SIZE_OPTIONS: dict[str, tuple[float, float]] = {
    "Brother 62mm x 40mm (large)": (62.0, 40.0),
    "Brother 62mm x 29mm (compact)": (62.0, 29.0),
    "Brother 29mm x 90mm (address)": (29.0, 90.0),
    "Custom size…": (0.0, 0.0),
}

PRINT_PROFILE_OPTIONS: dict[str, str] = {
    "Scanner only (Code128)": "code128",
    "Scanner + phone (Code128 + QR)": "code128_qr",
    "Legacy (Code39)": "code39",
}


@dataclass(frozen=True)
class LabelLayoutPlan:
    title_height_ratio: float
    barcode_height_ratio: float
    qr_size_ratio: float
    note_height_ratio: float


def validate_label_values(sku: str, inventory_id: str, profile_key: str) -> str | None:
    if not sku or not inventory_id:
        return "SKU and Inventory ID are required before printing a label."

    if profile_key == "code39":
        if has_invalid_code39_chars(sku) or has_invalid_code39_chars(inventory_id):
            return "SKU/Inventory ID contain unsupported Code39 characters. Allowed: A-Z, 0-9, space, - . $ / + %"

    if profile_key in {"code128", "code128_qr"}:
        if has_invalid_code128b_chars(sku) or has_invalid_code128b_chars(inventory_id):
            return "SKU/Inventory ID contain unsupported Code128-B characters. Allowed: printable ASCII (32-126)."

    return None


def build_layout_plan(width_mm: float, height_mm: float, include_qr: bool) -> LabelLayoutPlan:
    shortest_side = min(width_mm, height_mm)
    if shortest_side < 15:
        raise ValueError("Label is too small to render readable text and barcodes.")

    if include_qr:
        return LabelLayoutPlan(
            title_height_ratio=0.10,
            barcode_height_ratio=0.22,
            qr_size_ratio=0.20,
            note_height_ratio=0.06,
        )

    return LabelLayoutPlan(
        title_height_ratio=0.12,
        barcode_height_ratio=0.28,
        qr_size_ratio=0.0,
        note_height_ratio=0.08,
    )
