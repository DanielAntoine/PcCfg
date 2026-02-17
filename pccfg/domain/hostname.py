from __future__ import annotations

import re


def to_alnum(value: str) -> str:
    return "".join(char for char in value if char.isalnum())


def normalize_numbering_value(value: str) -> str:
    alnum_value = to_alnum(value)
    if alnum_value.isdigit():
        numeric_value = int(alnum_value)
        if 1 <= numeric_value <= 99:
            return f"{numeric_value:02d}"
    return alnum_value


def to_pascal_case_alnum(value: str) -> str:
    words = re.split(r"[^A-Za-z0-9]+", value)
    return "".join(to_alnum(word).capitalize() for word in words if word)


def build_hostname_value(client_name: str, computer_role: str, numbering: str) -> str:
    normalized_client_name = to_pascal_case_alnum(client_name)
    client_hostname = (normalized_client_name[:6]).ljust(6, "X")
    role_value = to_alnum(computer_role).upper()
    numbering_value = normalize_numbering_value(numbering)
    if not normalized_client_name or len(role_value) < 4 or not re.fullmatch(r"\d{2}", numbering_value):
        return ""
    return f"{client_hostname}-{role_value[:4]}-{numbering_value}"


def hostname_requirements_met(client_name: str, computer_role: str, numbering: str) -> bool:
    return bool(build_hostname_value(client_name, computer_role, numbering))
