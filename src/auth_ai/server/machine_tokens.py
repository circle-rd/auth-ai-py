from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Final, Protocol

from ..errors import ERR, AuthAiError

if TYPE_CHECKING:
    from ..types import TokenSet

# A cached token is renewed this long before it expires.
EXPIRY_SKEW_SECONDS: Final = 30


class ClientCredentialsAuth(Protocol):
    async def client_credentials(
        self, *, scope: str | None = None, resource: str | None = None
    ) -> TokenSet: ...


class MachineTokenProvider:
    """`client_credentials` tokens of the application, one per scope set.

    They are cached until shortly before they expire, and concurrent callers share
    one request to the token endpoint.
    """

    def __init__(self, auth: ClientCredentialsAuth) -> None:
        self._auth = auth
        self._cache: dict[str, tuple[str, int]] = {}
        self._inflight: dict[str, asyncio.Task[str]] = {}

    async def get_token(self, scope: str) -> str:
        cached = self._cache.get(scope)
        if cached and cached[1] - EXPIRY_SKEW_SECONDS > time.time():
            return cached[0]
        task = self._inflight.get(scope)
        if task is None:
            task = asyncio.create_task(self._mint(scope))
            self._inflight[scope] = task
            task.add_done_callback(lambda done: self._settle(scope, done))
        # Shielded: one caller giving up must not cancel the request the others await.
        return await asyncio.shield(task)

    def invalidate(self, scope: str) -> None:
        """Drops a token the API refused, e.g. after a secret rotation."""
        self._cache.pop(scope, None)

    def _settle(self, scope: str, done: asyncio.Task[str]) -> None:
        self._inflight.pop(scope, None)
        if not done.cancelled():
            # Marks the failure as retrieved when every waiter has already left.
            done.exception()

    async def _mint(self, scope: str) -> str:
        try:
            tokens = await self._auth.client_credentials(scope=scope)
        except AuthAiError as err:
            # The scope goes in `details` (for logs); the message stays generic.
            if err.details is not None and err.details.get("oauthError") == "invalid_scope":
                raise ERR.TOK_004(details={"scope": scope}, cause=err) from err
            raise
        self._cache[scope] = (tokens.access_token, tokens.expires_at)
        return tokens.access_token
