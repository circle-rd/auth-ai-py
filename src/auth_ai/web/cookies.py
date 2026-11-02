from __future__ import annotations

import re
from typing import Final

from ..errors import ERR

# Token characters only: the values handled here are base64url ids and compact JWEs.
_COOKIE_VALUE: Final = re.compile(r"[A-Za-z0-9._~-]+")
_COOKIE_NAME: Final = re.compile(r"[A-Za-z0-9_-]+")
_HOST_PREFIX: Final = "__Host-"


def cookie_name(base: str, secure: bool) -> str:  # noqa: FBT001
    """Name of a cookie of the SDK.

    `__Host-` pins the cookie to this host and needs `Secure`, so it only applies
    over https.
    """
    return f"{_HOST_PREFIX}{base}" if secure else base


def parse_cookies(header: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not header:
        return cookies
    for part in header.split(";"):
        name, separator, value = part.partition("=")
        if not separator:
            continue
        # The first occurrence wins, as it is the one scoped most specifically.
        cookies.setdefault(name.strip(), value.strip())
    return cookies


def serialize_cookie(name: str, value: str, *, max_age_seconds: float, secure: bool) -> str:
    """`max_age_seconds` of 0 expires the cookie at once; `secure` adds `Secure`."""
    if not _COOKIE_NAME.fullmatch(name.removeprefix(_HOST_PREFIX)):
        raise ERR.CFG_001("Invalid cookie name")
    if value != "" and not _COOKIE_VALUE.fullmatch(value):
        raise ERR.CFG_001("Invalid cookie value")
    attributes = [
        f"{name}={value}",
        "Path=/",
        "HttpOnly",
        # Lax still sends the cookie on the top-level GET that returns from the provider.
        "SameSite=Lax",
        f"Max-Age={max(0, int(max_age_seconds))}",
    ]
    if secure:
        attributes.append("Secure")
    return "; ".join(attributes)


def clear_cookie(name: str, *, secure: bool) -> str:
    return serialize_cookie(name, "", max_age_seconds=0, secure=secure)
