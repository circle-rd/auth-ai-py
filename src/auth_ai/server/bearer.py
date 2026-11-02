from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final, Protocol
from urllib.parse import urlsplit

from pydantic import ValidationError

from ..claims import AccessTokenClaims
from ..errors import ERR

_BEARER_PATTERN: Final = re.compile(r"Bearer +([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE)


def extract_bearer_token(authorization: str | None) -> str:
    """Extracts the token of an `Authorization: Bearer <token>` header."""
    match = _BEARER_PATTERN.fullmatch(authorization) if authorization else None
    if match is None:
        raise ERR.TOK_003()
    return match.group(1)


@dataclass(frozen=True, slots=True)
class VerifiedAccessToken:
    #: The end user, or None for a `client_credentials` token (machine call).
    user_id: str | None
    #: The OAuth client (application slug) the token was issued to.
    client_id: str
    scopes: tuple[str, ...]
    audiences: tuple[str, ...]
    claims: AccessTokenClaims


class JwtVerifying(Protocol):
    """What the verifiers need of an `AuthClient`."""

    async def verify_jwt(
        self, token: str, *, audience: str, typ: str | None = None
    ) -> dict[str, Any]: ...


class BearerVerifier:
    """Verifies JWT access tokens minted for this API (`aud` contains `audience`).

    Opaque tokens are refused: they carry no audience this API could trust.
    """

    def __init__(self, auth: JwtVerifying, *, audience: str) -> None:
        parts = urlsplit(audience)
        if not parts.scheme or not parts.hostname:
            raise ERR.CFG_001("audience must be the URL of this API")
        self._auth = auth
        self._audience = audience

    async def verify(self, token: str) -> VerifiedAccessToken:
        """Verifies a raw JWT access token."""
        if len(token.split(".")) != 3:
            raise ERR.TOK_001("Only JWT access tokens are accepted")
        payload = await self._auth.verify_jwt(token, audience=self._audience)
        try:
            claims = AccessTokenClaims.model_validate(payload)
        except ValidationError as err:
            raise ERR.TOK_001("The access token is not bound to a client", cause=err) from err
        audiences = (claims.aud,) if isinstance(claims.aud, str) else tuple(claims.aud)
        return VerifiedAccessToken(
            # For client_credentials tokens `sub` is the client id itself.
            user_id=None if claims.sub == claims.azp else claims.sub,
            client_id=claims.azp,
            scopes=tuple(claims.scope.split(" ")) if claims.scope else (),
            audiences=audiences,
            claims=claims,
        )

    async def verify_header(self, authorization: str | None) -> VerifiedAccessToken:
        """Verifies the token of an `Authorization` header."""
        return await self.verify(extract_bearer_token(authorization))


def require_scopes(token: VerifiedAccessToken, *required: str) -> None:
    """Raises TOK_004 unless the token carries every listed scope."""
    missing = [scope for scope in required if scope not in token.scopes]
    if missing:
        raise ERR.TOK_004(
            f"Missing required scope: {' '.join(missing)}",
            details={"missing": " ".join(missing)},
        )
