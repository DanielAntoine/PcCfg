from __future__ import annotations

# Code 128 module patterns for symbols 0..106
# Each string uses module widths (1-4) alternating bar/space, except stop (106) has 7 modules.
CODE128_PATTERNS: tuple[str, ...] = (
    "212222", "222122", "222221", "121223", "121322", "131222", "122213", "122312", "132212", "221213",
    "221312", "231212", "112232", "122132", "122231", "113222", "123122", "123221", "223211", "221132",
    "221231", "213212", "223112", "312131", "311222", "321122", "321221", "312212", "322112", "322211",
    "212123", "212321", "232121", "111323", "131123", "131321", "112313", "132113", "132311", "211313",
    "231113", "231311", "112133", "112331", "132131", "113123", "113321", "133121", "313121", "211331",
    "231131", "213113", "213311", "213131", "311123", "311321", "331121", "312113", "312311", "332111",
    "314111", "221411", "431111", "111224", "111422", "121124", "121421", "141122", "141221", "112214",
    "112412", "122114", "122411", "142112", "142211", "241211", "221114", "413111", "241112", "134111",
    "111242", "121142", "121241", "114212", "124112", "124211", "411212", "421112", "421211", "212141",
    "214121", "412121", "111143", "111341", "131141", "114113", "114311", "411113", "411311", "113141",
    "114131", "311141", "411131", "211412", "211214", "211232", "2331112",
)

START_B = 104
STOP = 106
CODESET_B_MIN = 32
CODESET_B_MAX = 126


def normalize_code128b_value(value: str) -> str:
    """Normalize to printable ASCII supported by Code128 code set B."""
    return "".join(ch for ch in value.strip() if CODESET_B_MIN <= ord(ch) <= CODESET_B_MAX)


def has_invalid_code128b_chars(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    return any(not (CODESET_B_MIN <= ord(ch) <= CODESET_B_MAX) for ch in stripped)


def encode_code128b_indices(value: str) -> list[int]:
    """Encode value into Code128 symbol indices using code set B."""
    normalized = normalize_code128b_value(value)
    if not normalized:
        return []

    data_indices = [ord(ch) - 32 for ch in normalized]
    checksum = START_B
    for idx, code in enumerate(data_indices, start=1):
        checksum += code * idx
    checksum %= 103
    return [START_B, *data_indices, checksum, STOP]
