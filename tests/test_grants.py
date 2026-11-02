from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from auth_ai import ERR, AuthAiError, GrantManager, InProcessGrantLock, MemoryGrantStore, TokenSet
from auth_ai import grants as grants_module
from auth_ai.types import TokenTypeHint

NOW = 1_793_433_600
DEFAULT_ACCESS = "access"
DEFAULT_ROTATED = "rotated"


@dataclass
class Clock:
    now: float = NOW


@dataclass
class FakeAuth:
    """Scripted provider: each call pops the next outcome, or `default` when none is left."""

    default: TokenSet | None = None
    outcomes: list[TokenSet | AuthAiError] = field(default_factory=list)
    refresh_calls: list[tuple[str, str | None]] = field(default_factory=list)
    revoke_calls: list[tuple[str, TokenTypeHint | None]] = field(default_factory=list)
    revoke_error: AuthAiError | None = None
    echo_resource: bool = False

    async def refresh(self, refresh_token: str, *, resource: str | None = None) -> TokenSet:
        self.refresh_calls.append((refresh_token, resource))
        # Yield so that concurrent callers get a chance to pile up behind the lock.
        await asyncio.sleep(0)
        if self.echo_resource:
            return token_set(access_token=resource or "default")
        outcome = self.outcomes.pop(0) if self.outcomes else self.default
        if outcome is None:
            raise AssertionError("unexpected refresh call")
        if isinstance(outcome, AuthAiError):
            raise outcome
        return outcome

    async def revoke(self, token: str, hint: TokenTypeHint | None = None) -> None:
        self.revoke_calls.append((token, hint))
        if self.revoke_error is not None:
            raise self.revoke_error


def token_set(
    access_token: str = DEFAULT_ACCESS,
    refresh_token: str | None = DEFAULT_ROTATED,
    id_token: str | None = None,
) -> TokenSet:
    return TokenSet(
        access_token=access_token,
        token_type="Bearer",
        expires_at=NOW + 3600,
        refresh_token=refresh_token,
        id_token=id_token,
    )


def oauth_error(code: str) -> AuthAiError:
    return ERR.OIDC_003("rejected", details={"oauthError": code})


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    clock = Clock()
    monkeypatch.setattr(grants_module, "time", SimpleNamespace(time=lambda: clock.now))
    return clock


@pytest.fixture
def fake_auth() -> FakeAuth:
    return FakeAuth()


@pytest.fixture
def store() -> MemoryGrantStore:
    return MemoryGrantStore()


@pytest.fixture
def manager(fake_auth: FakeAuth, store: MemoryGrantStore, clock: Clock) -> GrantManager:
    return GrantManager(auth=fake_auth, store=store)


class TestGetAccessToken:
    async def test_refreshes_for_one_resource_and_persists_the_rotated_token(
        self, fake_auth: FakeAuth, store: MemoryGrantStore, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.default = token_set(access_token="llm-token")

        token = await manager.get_access_token("u1", resource="https://llm.test")

        assert token.access_token == "llm-token"
        assert token.expires_at == NOW + 3600
        assert fake_auth.refresh_calls == [("refresh-0", "https://llm.test")]
        assert await store.get("u1") == "rotated"

    async def test_keeps_the_stored_token_when_the_provider_does_not_rotate(
        self, fake_auth: FakeAuth, store: MemoryGrantStore, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.default = token_set(refresh_token=None)

        await manager.get_access_token("u1")

        assert await store.get("u1") == "refresh-0"

    async def test_caches_per_resource_until_shortly_before_expiry(
        self, fake_auth: FakeAuth, manager: GrantManager, clock: Clock
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.echo_resource = True

        await manager.get_access_token("u1", resource="a")
        await manager.get_access_token("u1", resource="a")
        assert len(fake_auth.refresh_calls) == 1

        other = await manager.get_access_token("u1", resource="b")
        assert other.access_token == "b"
        assert len(fake_auth.refresh_calls) == 2

        clock.now = NOW + 3600 - 29
        await manager.get_access_token("u1", resource="a")
        assert len(fake_auth.refresh_calls) == 3

    async def test_serves_from_cache_up_to_the_expiry_skew(
        self, fake_auth: FakeAuth, manager: GrantManager, clock: Clock
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.default = token_set()

        await manager.get_access_token("u1")
        clock.now = NOW + 3600 - 31
        await manager.get_access_token("u1")

        assert len(fake_auth.refresh_calls) == 1

    async def test_honours_a_custom_expiry_skew(
        self, fake_auth: FakeAuth, store: MemoryGrantStore, clock: Clock
    ) -> None:
        manager = GrantManager(auth=fake_auth, store=store, expiry_skew_seconds=600)
        await manager.save("u1", "refresh-0")
        fake_auth.default = token_set()

        await manager.get_access_token("u1")
        clock.now = NOW + 3600 - 599
        await manager.get_access_token("u1")

        assert len(fake_auth.refresh_calls) == 2

    async def test_serialises_concurrent_callers_into_a_single_refresh(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.default = token_set()

        tokens = await asyncio.gather(
            manager.get_access_token("u1"),
            manager.get_access_token("u1"),
            manager.get_access_token("u1"),
        )

        assert len(fake_auth.refresh_calls) == 1
        assert len({token.access_token for token in tokens}) == 1

    async def test_chains_rotations_so_each_refresh_presents_the_latest_token(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.outcomes = [
            token_set(refresh_token="refresh-1"),
            token_set(refresh_token="refresh-2"),
        ]

        await asyncio.gather(
            manager.get_access_token("u1", resource="a"),
            manager.get_access_token("u1", resource="b"),
        )

        assert [token for token, _ in fake_auth.refresh_calls] == ["refresh-0", "refresh-1"]

    async def test_requires_a_sign_in_when_no_grant_exists(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await manager.get_access_token("ghost")

        assert raised.value.code == "TOK_002"
        assert fake_auth.refresh_calls == []

    async def test_drops_the_grant_when_the_provider_rejects_it(
        self, fake_auth: FakeAuth, store: MemoryGrantStore, manager: GrantManager
    ) -> None:
        await manager.save("u1", "stale")
        rejection = oauth_error("invalid_grant")
        fake_auth.outcomes = [rejection]

        with pytest.raises(AuthAiError) as raised:
            await manager.get_access_token("u1")

        assert raised.value.code == "TOK_002"
        assert raised.value.__cause__ is rejection
        assert await manager.has("u1") is False
        assert await store.get("u1") is None

    async def test_forgets_cached_tokens_when_the_provider_rejects_the_grant(
        self, fake_auth: FakeAuth, manager: GrantManager, clock: Clock
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.default = token_set()
        await manager.get_access_token("u1", resource="a")
        clock.now = NOW + 3600
        fake_auth.outcomes = [oauth_error("invalid_grant")]
        with pytest.raises(AuthAiError):
            await manager.get_access_token("u1", resource="b")

        with pytest.raises(AuthAiError) as raised:
            await manager.get_access_token("u1", resource="a")

        assert raised.value.code == "TOK_002"

    async def test_keeps_the_grant_on_a_non_grant_oauth_error(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.outcomes = [oauth_error("server_error")]

        with pytest.raises(AuthAiError) as raised:
            await manager.get_access_token("u1")

        assert raised.value.code == "OIDC_003"
        assert await manager.has("u1") is True

    async def test_keeps_the_grant_on_a_transient_failure(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.outcomes = [ERR.OIDC_003(), token_set()]

        with pytest.raises(AuthAiError) as raised:
            await manager.get_access_token("u1")
        assert raised.value.code == "OIDC_003"
        assert await manager.has("u1") is True

        token = await manager.get_access_token("u1")
        assert token.access_token == "access"


class TestRefreshTokens:
    async def test_returns_the_whole_token_set_and_stores_the_rotation(
        self, fake_auth: FakeAuth, store: MemoryGrantStore, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.default = token_set(id_token="id-token")

        tokens = await manager.refresh_tokens("u1")

        assert tokens.id_token == "id-token"
        assert fake_auth.refresh_calls == [("refresh-0", None)]
        assert await store.get("u1") == "rotated"

    async def test_requires_a_sign_in_when_no_grant_exists(self, manager: GrantManager) -> None:
        with pytest.raises(AuthAiError) as raised:
            await manager.refresh_tokens("ghost")

        assert raised.value.code == "TOK_002"

    async def test_drops_the_grant_when_the_provider_rejects_it(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.save("u1", "stale")
        fake_auth.outcomes = [oauth_error("invalid_grant")]

        with pytest.raises(AuthAiError) as raised:
            await manager.refresh_tokens("u1")

        assert raised.value.code == "TOK_002"
        assert await manager.has("u1") is False


class TestInvalidate:
    async def test_forces_the_next_call_to_mint_a_fresh_token_for_that_resource_only(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.default = token_set()
        await manager.get_access_token("u1", resource="a")
        await manager.get_access_token("u1", resource="b")
        assert len(fake_auth.refresh_calls) == 2

        manager.invalidate("u1", "a")
        await manager.get_access_token("u1", resource="a")
        await manager.get_access_token("u1", resource="b")

        assert len(fake_auth.refresh_calls) == 3


class TestSaveAndRevoke:
    async def test_forgets_cached_tokens_when_a_new_sign_in_replaces_the_grant(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.default = token_set()
        await manager.get_access_token("u1")

        await manager.save("u1", "refresh-new")
        await manager.get_access_token("u1")

        assert fake_auth.refresh_calls == [("refresh-0", None), ("refresh-new", None)]

    async def test_revokes_at_the_provider_and_forgets_the_grant(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")

        await manager.revoke("u1")

        assert fake_auth.revoke_calls == [("refresh-0", "refresh_token")]
        assert await manager.has("u1") is False

    async def test_forgets_cached_access_tokens_on_revoke(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.default = token_set()
        await manager.get_access_token("u1")

        await manager.revoke("u1")

        with pytest.raises(AuthAiError) as raised:
            await manager.get_access_token("u1")
        assert raised.value.code == "TOK_002"

    async def test_forgets_the_grant_even_when_the_provider_is_unreachable(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.save("u1", "refresh-0")
        fake_auth.revoke_error = ERR.OIDC_003()

        with pytest.raises(AuthAiError) as raised:
            await manager.revoke("u1")

        assert raised.value.code == "OIDC_003"
        assert await manager.has("u1") is False

    async def test_does_nothing_at_the_provider_for_an_unknown_grant(
        self, fake_auth: FakeAuth, manager: GrantManager
    ) -> None:
        await manager.revoke("ghost")

        assert fake_auth.revoke_calls == []


class TestMemoryGrantStore:
    async def test_holds_one_value_per_grant(self, store: MemoryGrantStore) -> None:
        assert await store.get("u1") is None

        await store.set("u1", "refresh-0")
        await store.set("u1", "refresh-1")
        assert await store.get("u1") == "refresh-1"

        await store.delete("u1")
        await store.delete("u1")
        assert await store.get("u1") is None


class TestInProcessGrantLock:
    async def test_runs_tasks_of_one_grant_in_order_and_tasks_of_others_in_parallel(self) -> None:
        lock = InProcessGrantLock()
        order: list[str] = []
        gate = asyncio.Event()

        async def first() -> None:
            async with lock.hold("a"):
                order.append("a1:start")
                await gate.wait()
                order.append("a1:end")

        async def second() -> None:
            async with lock.hold("a"):
                order.append("a2")

        async def other() -> None:
            async with lock.hold("b"):
                order.append("b")

        first_task = asyncio.create_task(first())
        await asyncio.sleep(0)
        second_task = asyncio.create_task(second())
        await asyncio.create_task(other())

        assert order == ["a1:start", "b"]
        gate.set()
        await asyncio.gather(first_task, second_task)
        assert order == ["a1:start", "b", "a1:end", "a2"]

    async def test_is_not_blocked_by_a_failing_task(self) -> None:
        lock = InProcessGrantLock()

        with pytest.raises(RuntimeError, match="boom"):
            async with lock.hold("a"):
                raise RuntimeError("boom")

        async with lock.hold("a"):
            acquired = True
        assert acquired

    async def test_a_cancelled_waiter_does_not_block_the_next_one(self) -> None:
        lock = InProcessGrantLock()
        gate = asyncio.Event()

        async def holder() -> None:
            async with lock.hold("a"):
                await gate.wait()

        async def waiter() -> None:
            async with lock.hold("a"):
                raise AssertionError("must not acquire")

        holder_task = asyncio.create_task(holder())
        await asyncio.sleep(0)
        waiter_task = asyncio.create_task(waiter())
        await asyncio.sleep(0)
        waiter_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter_task

        gate.set()
        await holder_task
        async with lock.hold("a"):
            acquired = True
        assert acquired
