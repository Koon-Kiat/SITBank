from __future__ import annotations


_CREDENTIAL_SCHEMES = ("postgres://", "postgresql://", "redis://")
_WEBHOOK_SCHEME = "https://"
_WEBHOOK_HOSTS = frozenset({"discord.com", "discordapp.com"})
_WEBHOOK_PATH_PREFIXES = ("webhooks/", "services/")
_ASCII_LOWER_TRANSLATION = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
)


def contains_sensitive_url(text: str) -> bool:
    """Return whether text contains a credential-bearing or webhook URL."""
    return contains_credential_url(text) or contains_webhook_url(text)


def contains_credential_url(text: str) -> bool:
    """Detect supported credential URLs with a deterministic linear scan."""
    folded = text.translate(_ASCII_LOWER_TRANSLATION)
    for scheme in _CREDENTIAL_SCHEMES:
        cursor = 0
        while True:
            scheme_index = folded.find(scheme, cursor)
            if scheme_index < 0:
                break
            cursor = scheme_index + 1
            if scheme_index and _is_word_character(text[scheme_index - 1]):
                continue
            if _authority_contains_password(text, scheme_index + len(scheme)):
                return True
    return False


def contains_webhook_url(text: str) -> bool:
    """Detect supported webhook URLs without regex backtracking."""
    folded = text.translate(_ASCII_LOWER_TRANSLATION)
    cursor = 0
    while True:
        scheme_index = folded.find(_WEBHOOK_SCHEME, cursor)
        if scheme_index < 0:
            return False
        cursor = scheme_index + 1
        authority_start = scheme_index + len(_WEBHOOK_SCHEME)
        path_start = _path_start(text, authority_start)
        if path_start < 0:
            continue
        host = folded[authority_start : path_start - 1]
        if _is_webhook_host(host) and _has_webhook_path(text, folded, path_start):
            return True


def _authority_contains_password(text: str, authority_start: int) -> bool:
    has_userinfo_separator = False
    for char in text[authority_start:]:
        if char.isspace() or char == "/":
            return False
        if char == "@":
            return has_userinfo_separator
        if char == ":":
            has_userinfo_separator = True
    return False


def _path_start(text: str, authority_start: int) -> int:
    for index in range(authority_start, len(text)):
        char = text[index]
        if char.isspace():
            return -1
        if char == "/":
            return index + 1
    return -1


def _is_webhook_host(host: str) -> bool:
    return "hooks" in host or host in _WEBHOOK_HOSTS


def _has_webhook_path(text: str, folded: str, path_start: int) -> bool:
    if folded.startswith("api/", path_start):
        path_start += len("api/")
    for prefix in _WEBHOOK_PATH_PREFIXES:
        if folded.startswith(prefix, path_start):
            secret_start = path_start + len(prefix)
            return secret_start < len(text) and not text[secret_start].isspace()
    return False


def _is_word_character(char: str) -> bool:
    return char == "_" or char.isalnum()
