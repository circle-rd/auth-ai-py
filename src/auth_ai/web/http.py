from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from ..errors import ERR, AuthAiError
from ..messages import WebRequest, WebResponse, json_response

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from ..errors import AuthAiErrorCode

STATUS_BY_CODE: Final[dict[AuthAiErrorCode, int]] = {
    "REQ_001": 400,
    "SES_001": 401,
    "SES_002": 400,
    "SES_004": 403,
    "SES_005": 403,
    "TOK_001": 401,
    "TOK_002": 401,
    "TOK_003": 401,
    "TOK_004": 403,
    "OIDC_002": 400,
    "OIDC_001": 502,
    "OIDC_003": 502,
    "OIDC_004": 501,
    "API_001": 502,
    "API_002": 502,
    "GW_001": 402,
    "GW_002": 429,
    "GW_003": 403,
    "GW_004": 503,
    "GW_005": 502,
}

# Control characters and backslashes make browsers read a "path" as another host.
_UNSAFE_REDIRECT: Final = re.compile(r"[\\\x00-\x1f\x7f]")
_PLACEHOLDER_HOST: Final = "placeholder.invalid"


def error_response(
    err: BaseException,
    on_error: Callable[[BaseException], None] | None,
    headers: Iterable[tuple[str, str]] = (),
) -> WebResponse:
    """Serialises a failure as the same `{ error: { code, message } }` envelope auth-service uses.

    Only the code and a generic message go out: the detailed message and the
    details stay in the error, for the application's logs. Any other failure is
    reported to `on_error` and answered generically.
    """
    if isinstance(err, AuthAiError):
        status = STATUS_BY_CODE.get(err.code, 500)
        # Server-side failures (provider or API down, unexpected answer) need a log line.
        if status >= 500 and on_error is not None:
            on_error(err)
        return json_response({"error": err.to_public_json()}, status, headers)
    if on_error is not None:
        on_error(err)
    return json_response({"error": ERR.SRV_001().to_public_json()}, 500, headers)


def safe_redirect_path(candidate: str | None, fallback: str) -> str:
    """A redirect target taken from a request, reduced to a same-origin path.

    An absolute URL, a protocol-relative one (`//host`) or anything odd falls back
    to `fallback`, so a login link cannot bounce users to another site.
    """
    if not candidate or not candidate.startswith("/") or candidate.startswith("//"):
        return fallback
    if _UNSAFE_REDIRECT.search(candidate):
        return fallback
    probe = urlsplit(f"https://{_PLACEHOLDER_HOST}{candidate}")
    if probe.hostname != _PLACEHOLDER_HOST or probe.port is not None:
        return fallback
    return candidate


def is_cross_site(request: WebRequest, expected_origin: str) -> bool:
    """Whether a browser sent this state-changing request from another site.

    Requests without `Origin` and `Sec-Fetch-Site` (non-browser clients) carry no
    ambient cookie to abuse and pass.
    """
    origin = request.header("origin")
    if origin is not None:
        return origin != expected_origin
    site = request.header("sec-fetch-site")
    return site is not None and site not in ("same-origin", "none")
