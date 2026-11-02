from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol
from urllib.parse import parse_qs

from ..errors import ERR
from ..messages import NO_STORE, WebRequest, WebResponse, json_response

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ..config import AuthClientConfig

LOGOUT_EVENT: Final = "http://schemas.openid.net/event/backchannel-logout"
LOGOUT_TOKEN_TYP: Final = "logout+jwt"
# auth-service issues 120 s tokens; anything far beyond is not one of its.
MAX_LOGOUT_TOKEN_LIFETIME_SECONDS: Final = 600
MAX_BODY_BYTES: Final = 16_384


class ReplayStore(Protocol):
    """Remembers the `jti` of accepted logout tokens until they expire.

    Share it across replicas (e.g. a Redis `SET NX PX`): a per-process store only
    stops replays that hit the same instance.
    """

    async def claim(self, jti: str, expires_at: float) -> bool:
        """Returns True the first time a `jti` is claimed, False on a replay."""
        ...


class MemoryReplayStore:
    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    async def claim(self, jti: str, expires_at: float) -> bool:
        now = time.time()
        self._seen = {j: exp for j, exp in self._seen.items() if exp > now}
        if jti in self._seen:
            return False
        self._seen[jti] = expires_at
        return True


@dataclass(frozen=True, slots=True)
class LogoutTokenClaims:
    sid: str
    sub: str
    jti: str
    iat: float
    exp: float


class LogoutAuth(Protocol):
    @property
    def config(self) -> AuthClientConfig: ...

    async def verify_jwt(
        self, token: str, *, audience: str, typ: str | None = None
    ) -> dict[str, Any]: ...


async def verify_logout_token(
    auth: LogoutAuth, token: str, replay_store: ReplayStore
) -> LogoutTokenClaims:
    """Validates an OIDC Back-Channel Logout token (spec §2.6) and records its `jti`.

    auth-service always names both the session and the user.
    """
    payload = await auth.verify_jwt(token, audience=auth.config.client_id, typ=LOGOUT_TOKEN_TYP)

    events = payload.get("events")
    if not isinstance(events, dict) or LOGOUT_EVENT not in events:
        raise ERR.TOK_001("The logout token lacks the back-channel logout event")
    if "nonce" in payload:
        raise ERR.TOK_001("A logout token must not carry a nonce")
    jti, sid, sub = payload.get("jti"), payload.get("sid"), payload.get("sub")
    if not isinstance(jti, str) or not jti or not isinstance(sid, str) or not sid:
        raise ERR.TOK_001("The logout token lacks jti or sid")
    iat, exp = payload.get("iat"), payload.get("exp")
    if (
        not isinstance(sub, str)
        or not isinstance(iat, int | float)
        or isinstance(iat, bool)
        or not isinstance(exp, int | float)
        or isinstance(exp, bool)
    ):
        raise ERR.TOK_001("The logout token lacks sub, iat or exp")
    if (
        iat > time.time() + auth.config.clock_tolerance_seconds
        or exp - iat > MAX_LOGOUT_TOKEN_LIFETIME_SECONDS
    ):
        raise ERR.TOK_001("The logout token has an implausible lifetime")
    if not await replay_store.claim(jti, exp):
        raise ERR.TOK_001("The logout token was already used")
    return LogoutTokenClaims(sid=sid, sub=sub, jti=jti, iat=iat, exp=exp)


@dataclass(frozen=True, slots=True)
class BackchannelLogoutEvent:
    #: End every local session whose stored `sid` equals this one.
    sid: str
    #: For per-user state, when you keep any.
    sub: str


type LogoutCallback = Callable[[BackchannelLogoutEvent], Awaitable[None] | None]
type ErrorCallback = Callable[[BaseException], None]


def _error(status: int, error: str) -> WebResponse:
    return json_response({"error": error}, status)


class BackchannelLogoutHandler:
    """Handler of the application's back-channel logout endpoint.

    It is called without cookies or credentials: mount it outside any session or
    CSRF protection. `on_error` receives every rejected token and failed
    callback: the response carries no detail.
    """

    def __init__(
        self,
        *,
        auth: LogoutAuth,
        on_logout: LogoutCallback,
        replay_store: ReplayStore | None = None,
        on_error: ErrorCallback | None = None,
    ) -> None:
        self._auth = auth
        self._on_logout = on_logout
        self._replay_store = replay_store or MemoryReplayStore()
        self._on_error = on_error

    async def __call__(self, request: WebRequest) -> WebResponse:
        if request.method != "POST":
            return WebResponse(405, (("cache-control", NO_STORE), ("allow", "POST")))

        content_type = (request.header("content-type") or "").lower()
        if not content_type.startswith("application/x-www-form-urlencoded"):
            return _error(400, "invalid_request")
        declared = request.header("content-length") or "0"
        if (declared.isdigit() and int(declared) > MAX_BODY_BYTES) or len(
            request.body
        ) > MAX_BODY_BYTES:
            return _error(400, "invalid_request")
        values = parse_qs(request.body.decode(errors="replace")).get("logout_token")
        if not values or not values[0]:
            return _error(400, "invalid_request")

        try:
            claims = await verify_logout_token(self._auth, values[0], self._replay_store)
        except Exception as err:  # noqa: BLE001
            self._report(err)
            return _error(400, "invalid_request")

        try:
            result = self._on_logout(BackchannelLogoutEvent(sid=claims.sid, sub=claims.sub))
            if result is not None:
                await result
        except Exception as err:  # noqa: BLE001
            self._report(err)
            return _error(500, "server_error")
        return WebResponse(204, (("cache-control", NO_STORE),))

    def _report(self, err: BaseException) -> None:
        if self._on_error is not None:
            self._on_error(err)
