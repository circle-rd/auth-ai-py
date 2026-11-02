from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Literal

type AuthAiErrorDetails = Mapping[str, str | int | float | bool | None]

type AuthAiErrorCode = Literal[
    "CFG_001",
    "OIDC_001",
    "OIDC_002",
    "OIDC_003",
    "OIDC_004",
    "TOK_001",
    "TOK_002",
    "TOK_003",
    "TOK_004",
    "API_001",
    "API_002",
    "GW_001",
    "GW_002",
    "GW_003",
    "GW_004",
    "GW_005",
    "SES_001",
    "SES_002",
    "SES_003",
    "SES_004",
    "SES_005",
    "REQ_001",
    "SRV_001",
]

DEFAULT_MESSAGES: Final[Mapping[AuthAiErrorCode, str]] = {
    "CFG_001": "Invalid SDK configuration",
    "OIDC_001": "Identity provider discovery failed",
    "OIDC_002": "Invalid authorization response",
    "OIDC_003": "Token request failed",
    "OIDC_004": "The identity provider does not support this operation",
    "TOK_001": "Token verification failed",
    "TOK_002": "No usable grant for this user: sign in again",
    "TOK_003": "Missing or malformed bearer credentials",
    "TOK_004": "Insufficient scope",
    "API_001": "auth-service rejected the request",
    "API_002": "Unexpected response from auth-service",
    "GW_001": "Insufficient credit: the wallet cannot pay for this call",
    "GW_002": "The gateway rate limit was reached",
    "GW_003": "The gateway refused the credentials or the resource",
    "GW_004": "The gateway is temporarily unavailable",
    "GW_005": "Unexpected response from the gateway",
    "SES_001": "Not signed in",
    "SES_002": "The sign-in attempt is missing, expired or was tampered with",
    "SES_003": "Sign-in could not be completed",
    "SES_004": "Cross-origin request refused",
    "SES_005": "Sign-in failed",
    "REQ_001": "Invalid request",
    "SRV_001": "Internal error",
}


def is_auth_ai_error_code(value: object) -> bool:
    return isinstance(value, str) and value in DEFAULT_MESSAGES


class AuthAiError(Exception):
    """Every failure raised by the SDK.

    `details` must never carry tokens, secrets or other credentials: it is meant
    to be logged and serialised.
    """

    code: AuthAiErrorCode
    message: str
    details: AuthAiErrorDetails | None

    def __init__(
        self,
        code: AuthAiErrorCode,
        message: str,
        *,
        details: AuthAiErrorDetails | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details
        if cause is not None:
            self.__cause__ = cause

    def to_public_json(self) -> dict[str, str]:
        """What may reach an end user: the code and the registry's generic message.

        `message` and `details` carry what a developer needs (a provider's
        description, a scope name) and belong in logs, not in responses.
        """
        return {"code": self.code, "message": DEFAULT_MESSAGES[self.code]}

    def to_json(self) -> dict[str, object]:
        body: dict[str, object] = {"code": self.code, "message": self.message}
        if self.details:
            body["details"] = dict(self.details)
        return body


class ErrorFactory:
    """Builds the error of one code. A callable object, not a function, so that
    the registry's attributes are not bound as methods."""

    __slots__ = ("_code",)

    def __init__(self, code: AuthAiErrorCode) -> None:
        self._code = code

    def __call__(
        self,
        message: str | None = None,
        *,
        details: AuthAiErrorDetails | None = None,
        cause: BaseException | None = None,
    ) -> AuthAiError:
        return AuthAiError(
            self._code,
            DEFAULT_MESSAGES[self._code] if message is None else message,
            details=details,
            cause=cause,
        )


# ── Registry ──
# Domain prefixes mirror auth-service: CFG_ configuration, OIDC_ protocol exchanges
# with the identity provider, TOK_ token and grant handling, API_ calls to the
# auth-service REST API, GW_ calls to the LiteLLM gateway, SES_ browser sessions,
# REQ_ invalid requests to the SDK's own routes, SRV_ unexpected failures of the
# SDK's own HTTP handlers.
class _ErrorRegistry:
    CFG_001: Final = ErrorFactory("CFG_001")
    OIDC_001: Final = ErrorFactory("OIDC_001")
    OIDC_002: Final = ErrorFactory("OIDC_002")
    OIDC_003: Final = ErrorFactory("OIDC_003")
    OIDC_004: Final = ErrorFactory("OIDC_004")
    TOK_001: Final = ErrorFactory("TOK_001")
    TOK_002: Final = ErrorFactory("TOK_002")
    TOK_003: Final = ErrorFactory("TOK_003")
    TOK_004: Final = ErrorFactory("TOK_004")
    API_001: Final = ErrorFactory("API_001")
    API_002: Final = ErrorFactory("API_002")
    GW_001: Final = ErrorFactory("GW_001")
    GW_002: Final = ErrorFactory("GW_002")
    GW_003: Final = ErrorFactory("GW_003")
    GW_004: Final = ErrorFactory("GW_004")
    GW_005: Final = ErrorFactory("GW_005")
    SES_001: Final = ErrorFactory("SES_001")
    SES_002: Final = ErrorFactory("SES_002")
    SES_003: Final = ErrorFactory("SES_003")
    SES_004: Final = ErrorFactory("SES_004")
    SES_005: Final = ErrorFactory("SES_005")
    REQ_001: Final = ErrorFactory("REQ_001")
    SRV_001: Final = ErrorFactory("SRV_001")


ERR: Final = _ErrorRegistry()
