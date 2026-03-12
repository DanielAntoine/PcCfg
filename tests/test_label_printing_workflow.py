from pccfg.services.barcode_code128 import encode_code128b_indices, has_invalid_code128b_chars, normalize_code128b_value
from pccfg.services.label_printing import build_layout_plan, validate_label_values


def test_code128_normalize_and_invalid_flags() -> None:
    assert normalize_code128b_value(" SKU-01 ") == "SKU-01"
    assert has_invalid_code128b_chars("SKU-é") is True
    assert has_invalid_code128b_chars("SKU-01") is False


def test_code128_indices_include_start_checksum_stop() -> None:
    indices = encode_code128b_indices("AB")
    assert indices[0] == 104
    assert indices[-1] == 106
    assert len(indices) == 5


def test_validate_values_for_profiles() -> None:
    assert validate_label_values("", "X", "code128") is not None
    assert validate_label_values("SKU", "INV", "code128") is None
    assert validate_label_values("SKU-é", "INV", "code128") is not None
    assert validate_label_values("SKU-01", "INV 1", "code39") is None


def test_layout_plan_rejects_too_small_labels() -> None:
    try:
        build_layout_plan(10.0, 12.0, include_qr=True)
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for too-small labels")


def test_layout_plan_profiles() -> None:
    with_qr = build_layout_plan(62.0, 40.0, include_qr=True)
    without_qr = build_layout_plan(62.0, 40.0, include_qr=False)
    assert with_qr.qr_size_ratio > 0
    assert without_qr.qr_size_ratio == 0
