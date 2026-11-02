from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..claims import IdTokenClaims


@dataclass(frozen=True, slots=True)
class Session:
    """A signed-in browser session, as kept by the application's backend."""

    #: SHA-256 of the cookie value: a leaked store cannot be replayed as cookies.
    id: str
    #: The provider's subject: also the key of the user's grant.
    user_id: str
    #: The provider session, which a back-channel logout names.
    session_id: str | None
    claims: IdTokenClaims
    #: Hint for the provider's logout endpoint.
    id_token: str
    #: Unix seconds.
    created_at: int
    #: Absolute end of the session, in unix seconds.
    expires_at: int
    #: When the claims are next renewed from the provider, in unix seconds.
    renew_at: int


class SessionStore(Protocol):
    """Where sessions live.

    Implement it on the database of the application; it must survive restarts and
    be shared by every replica. Records are keyed by `Session.id`, and
    `session_id` and `user_id` must be indexed.
    """

    async def create(self, session: Session) -> None: ...

    async def get(self, session_key: str) -> Session | None:
        """Returns None for an unknown or expired session."""
        ...

    async def update(self, session: Session) -> None: ...

    async def delete(self, session_key: str) -> None: ...

    async def delete_by_provider_session(self, session_id: str) -> Sequence[Session]:
        """Removes every session of a provider session and returns what was removed."""
        ...

    async def count_by_user(self, user_id: str) -> int: ...


class MemorySessionStore:
    """Keeps sessions in the process: for tests and single-process prototypes."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    async def create(self, session: Session) -> None:
        self._sessions[session.id] = session

    async def get(self, session_key: str) -> Session | None:
        session = self._sessions.get(session_key)
        if session is not None and session.expires_at <= time.time():
            del self._sessions[session_key]
            return None
        return session

    async def update(self, session: Session) -> None:
        if session.id in self._sessions:
            self._sessions[session.id] = replace(session)

    async def delete(self, session_key: str) -> None:
        self._sessions.pop(session_key, None)

    async def delete_by_provider_session(self, session_id: str) -> Sequence[Session]:
        removed = [s for s in self._sessions.values() if s.session_id == session_id]
        for session in removed:
            del self._sessions[session.id]
        return removed

    async def count_by_user(self, user_id: str) -> int:
        now = time.time()
        return sum(
            1
            for session in self._sessions.values()
            if session.user_id == user_id and session.expires_at > now
        )
