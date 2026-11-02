from __future__ import annotations

import asyncio
import time
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Protocol

from .errors import ERR, AuthAiError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from .types import TokenSet, TokenTypeHint

DEFAULT_EXPIRY_SKEW_SECONDS: Final = 30


class GrantStore(Protocol):
    """Persists the single refresh-token chain of a user.

    The provider rotates it on every use, so a store must hold exactly one value
    per grant. Encrypt it at rest: it is a long-lived credential.
    """

    async def get(self, grant_id: str) -> str | None: ...

    async def set(self, grant_id: str, refresh_token: str) -> None: ...

    async def delete(self, grant_id: str) -> None: ...


class GrantLock(Protocol):
    """Serialises the refreshes of one grant.

    The default lock only covers a single process: replicas need a distributed
    lock (or a row lock in the store).
    """

    def hold(self, grant_id: str) -> AbstractAsyncContextManager[None]: ...


class GrantAuth(Protocol):
    async def refresh(self, refresh_token: str, *, resource: str | None = None) -> TokenSet: ...

    async def revoke(self, token: str, hint: TokenTypeHint | None = None) -> None: ...


@dataclass(frozen=True, slots=True)
class AccessToken:
    access_token: str = field(repr=False)
    #: Unix seconds.
    expires_at: int


class MemoryGrantStore:
    """Keeps grants in the process: for tests and single-process prototypes."""

    def __init__(self) -> None:
        self._grants: dict[str, str] = {}

    async def get(self, grant_id: str) -> str | None:
        return self._grants.get(grant_id)

    async def set(self, grant_id: str, refresh_token: str) -> None:
        self._grants[grant_id] = refresh_token

    async def delete(self, grant_id: str) -> None:
        self._grants.pop(grant_id, None)


@dataclass(slots=True)
class _LockEntry:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    # Holders and waiters: an idle lock is dropped so the map does not grow.
    users: int = 0


class InProcessGrantLock:
    def __init__(self) -> None:
        self._entries: dict[str, _LockEntry] = {}

    @asynccontextmanager
    async def hold(self, grant_id: str) -> AsyncIterator[None]:
        entry = self._entries.setdefault(grant_id, _LockEntry())
        entry.users += 1
        try:
            async with entry.lock:
                yield
        finally:
            entry.users -= 1
            if entry.users == 0:
                del self._entries[grant_id]


def _cache_key(grant_id: str, resource: str | None) -> str:
    return f"{grant_id}\0{resource or ''}"


def is_invalid_grant(err: BaseException) -> bool:
    return (
        isinstance(err, AuthAiError)
        and err.details is not None
        and err.details.get("oauthError") == "invalid_grant"
    )


class GrantManager:
    """The only place that refreshes tokens.

    Access tokens are minted per resource (RFC 8707) from the stored refresh
    token and cached in memory until shortly before they expire; they are never
    persisted.
    """

    def __init__(
        self,
        *,
        auth: GrantAuth,
        store: GrantStore,
        lock: GrantLock | None = None,
        expiry_skew_seconds: int = DEFAULT_EXPIRY_SKEW_SECONDS,
    ) -> None:
        self._auth = auth
        self._store = store
        self._lock: GrantLock = lock or InProcessGrantLock()
        self._skew = expiry_skew_seconds
        self._cache: dict[str, AccessToken] = {}

    async def save(self, grant_id: str, refresh_token: str) -> None:
        """Stores the refresh token obtained at sign-in, replacing any older chain."""
        async with self._lock.hold(grant_id):
            await self._store.set(grant_id, refresh_token)
            self._forget(grant_id)

    async def has(self, grant_id: str) -> bool:
        return await self._store.get(grant_id) is not None

    async def get_access_token(self, grant_id: str, *, resource: str | None = None) -> AccessToken:
        """An access token for one audience, narrowed to `resource` (RFC 8707).

        Raises TOK_002 when the user has no grant or the provider rejected it: the
        grant is then dropped and only a new sign-in restores it.
        """
        key = _cache_key(grant_id, resource)
        if (cached := self._cached(key)) is not None:
            return cached

        async with self._lock.hold(grant_id):
            # Another caller may have refreshed while this one waited for the lock.
            if (refreshed := self._cached(key)) is not None:
                return refreshed
            tokens = await self._rotate(grant_id, resource)
            token = AccessToken(tokens.access_token, tokens.expires_at)
            self._cache[key] = token
            return token

    async def refresh_tokens(self, grant_id: str) -> TokenSet:
        """Refreshes without narrowing to a resource and returns the whole token set.

        The ID token is included: this is the way to renew the claims of a session.
        The rotated refresh token is stored. Failures are those of `get_access_token`.
        """
        async with self._lock.hold(grant_id):
            return await self._rotate(grant_id, None)

    def invalidate(self, grant_id: str, resource: str | None = None) -> None:
        """Drops a cached access token the API refused, so the next call mints a fresh one."""
        self._cache.pop(_cache_key(grant_id, resource), None)

    async def revoke(self, grant_id: str) -> None:
        """Revokes the refresh token at the provider, then forgets the grant."""
        async with self._lock.hold(grant_id):
            refresh_token = await self._store.get(grant_id)
            try:
                if refresh_token is not None:
                    await self._auth.revoke(refresh_token, "refresh_token")
            finally:
                # An unreachable provider must not keep the user signed in locally.
                await self._store.delete(grant_id)
                self._forget(grant_id)

    async def _rotate(self, grant_id: str, resource: str | None) -> TokenSet:
        """One refresh under the grant lock the caller already holds."""
        refresh_token = await self._store.get(grant_id)
        if refresh_token is None:
            raise ERR.TOK_002()
        try:
            tokens = await self._auth.refresh(refresh_token, resource=resource)
        except AuthAiError as err:
            if is_invalid_grant(err):
                await self._store.delete(grant_id)
                self._forget(grant_id)
                raise ERR.TOK_002(cause=err) from err
            raise
        # Providers may omit the refresh token when they do not rotate it.
        await self._store.set(grant_id, tokens.refresh_token or refresh_token)
        return tokens

    def _cached(self, key: str) -> AccessToken | None:
        token = self._cache.get(key)
        if token is None:
            return None
        if token.expires_at - self._skew > time.time():
            return token
        del self._cache[key]
        return None

    def _forget(self, grant_id: str) -> None:
        prefix = f"{grant_id}\0"
        for key in [key for key in self._cache if key.startswith(prefix)]:
            del self._cache[key]
