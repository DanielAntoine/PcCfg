from pccfg.services.barcode_code39 import has_invalid_code39_chars, normalize_code39_value


def test_normalize_code39_keeps_supported_characters() -> None:
    assert normalize_code39_value("ab-12./+$% 7") == "AB-12./+$% 7"


def test_normalize_code39_drops_unsupported_characters() -> None:
    assert normalize_code39_value("sku_é@123") == "SKU123"


def test_has_invalid_code39_chars_detects_invalid_input() -> None:
    assert has_invalid_code39_chars("sku_123") is True
    assert has_invalid_code39_chars("SKU-123") is False
