from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from .errors import ERR, AuthAiError

if TYPE_CHECKING:
    from collections.abc import Mapping


def _error_fields(body: object) -> tuple[str | None, str | None]:
    """The `type` and `message` of an OpenAI-style error body, when well formed."""
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return None, None
    kind, message = error.get("type"), error.get("message")
    return (
        kind if isinstance(kind, str) else None,
        message if isinstance(message, str) else None,
    )


def to_gateway_error(
    status: int, body: object, headers: Mapping[str, str] | None = None
) -> AuthAiError:
    """Maps a failed gateway answer to the SDK registry.

    Branch on the status first: LiteLLM serialises the final body itself, so only
    the status is a contract. The message is the gateway's own and carries no
    credential.
    """
    kind, message = _error_fields(body)
    details: dict[str, str | int | float] = {"status": status}
    if kind:
        details["type"] = kind

    if status == httpx.codes.TOO_MANY_REQUESTS and headers is not None:
        try:
            retry_after = float(headers.get("retry-after", ""))
        except ValueError:
            retry_after = -1
        if retry_after >= 0 and retry_after != float("inf"):
            details["retryAfterSeconds"] = retry_after

    match status:
        case httpx.codes.PAYMENT_REQUIRED:
            return ERR.GW_001(message, details=details)
        case httpx.codes.TOO_MANY_REQUESTS:
            return ERR.GW_002(message, details=details)
        case httpx.codes.UNAUTHORIZED | httpx.codes.FORBIDDEN:
            return ERR.GW_003(message, details=details)
        case httpx.codes.SERVICE_UNAVAILABLE:
            return ERR.GW_004(message, details=details)
        case _:
            return ERR.GW_005(message or f"The gateway answered {status}", details=details)


def is_insufficient_credit(err: object) -> bool:
    """True for the error of a call refused because the wallet is empty."""
    return isinstance(err, AuthAiError) and err.code == "GW_001"


def is_insufficient_credit_status(err: object) -> bool:
    """Same test for the error of an OpenAI-compatible SDK, which exposes the HTTP
    status as `status_code` (the `openai` package) or `status`.

    The gateway answers 402 when the balance is zero or negative.
    """
    return httpx.codes.PAYMENT_REQUIRED in {
        getattr(err, "status_code", None),
        getattr(err, "status", None),
    }
