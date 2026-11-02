from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from .errors import ERR

if TYPE_CHECKING:
    from .claims import IdTokenClaims

type Prompt = Literal["login", "consent", "select_account", "create", "none"]
type TokenTypeHint = Literal["access_token", "refresh_token"]


@dataclass(frozen=True, slots=True)
class TokenSet:
    # Secrets stay out of `repr` so that logging a token set leaks nothing.
    access_token: str = field(repr=False)
    token_type: str
    #: Unix seconds.
    expires_at: int
    scope: str | None = None
    #: Absent when the provider issued none (no `offline_access`, or no rotation).
    refresh_token: str | None = field(default=None, repr=False)
    id_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class LoginHandshake:
    """Secrets of one sign-in attempt.

    The caller persists them (typically in a short-lived sealed cookie) between
    the redirect and the callback.
    """

    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LoginRequest:
    url: str
    handshake: LoginHandshake


@dataclass(frozen=True, slots=True)
class LoginResult:
    tokens: TokenSet
    claims: IdTokenClaims
    #: The provider session, only present when end-session or back-channel
    #: logout is enabled for the application.
    session_id: str | None

    @property
    def id_token(self) -> str:
        if self.tokens.id_token is None:
            raise ERR.OIDC_002("The token response carries no ID token")
        return self.tokens.id_token
