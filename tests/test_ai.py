from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable

import httpx
import pytest

from auth_ai import AccessToken, AiClient, AuthAiError, AuthClient, GrantManager, MemoryGrantStore
from tests.support.mock_idp import (
    GATEWAY_URL,
    ISSUER,
    MockIdp,
    RecordedRequest,
    create_test_auth,
    json_response,
    now_seconds,
)

ACCOUNT = {"balance": "5000000", "isUnlimited": False, "canSpend": True, "currency": "eur"}


class Harness:
    def __init__(self, idp: MockIdp) -> None:
        self.idp = idp
        self.resources: list[str] = []
        self.expires_in = 3600
        self.auths: list[AuthClient] = []
        idp.token_handler = self._issue
        self.grants: GrantManager
        self.ai: AiClient
        self.build(GATEWAY_URL)

    def _issue(self, request: RecordedRequest) -> httpx.Response:
        resource = request.form.get("resource", "none")
        self.resources.append(resource)
        return json_response(
            {
                "access_token": f"token-for-{resource}",
                "token_type": "Bearer",
                "expires_in": self.expires_in,
                "refresh_token": f"refresh-{len(self.resources)}",
            }
        )

    def build(self, gateway_url: str | None) -> None:
        overrides = {"gateway_url": gateway_url} if gateway_url else {}
        auth = create_test_auth(self.idp, **overrides)
        self.auths.append(auth)
        self.grants = GrantManager(auth=auth, store=MemoryGrantStore())
        self.ai = AiClient(auth=auth, grants=self.grants)


@pytest.fixture
async def harness(idp: MockIdp) -> AsyncIterator[Harness]:
    harness = Harness(idp)
    yield harness
    for auth in harness.auths:
        await auth.http.aclose()


class TestForUser:
    async def test_reads_the_wallet_with_a_token_narrowed_to_auth_service(
        self, idp: MockIdp, harness: Harness
    ) -> None:
        await harness.grants.save("u1", "refresh-0")
        idp.api_handler = lambda _request: json_response(ACCOUNT)

        account = await harness.ai.for_user("u1").wallet.get_account()

        assert account.balance == 5_000_000
        assert harness.resources == [ISSUER]
        assert idp.requests[-1].url.path == "/api/user/wallet"
        assert idp.requests[-1].headers["authorization"] == f"Bearer token-for-{ISSUER}"

    async def test_calls_the_gateway_with_a_token_narrowed_to_the_gateway_audience(
        self, idp: MockIdp, harness: Harness
    ) -> None:
        await harness.grants.save("u1", "refresh-0")
        idp.gateway_handler = lambda _request: json_response({"data": [{"id": "gpt-4o-mini"}]})

        models = await harness.ai.for_user("u1").gateway.list_models()

        assert models[0].id == "gpt-4o-mini"
        assert harness.resources == [GATEWAY_URL]
        assert idp.gateway_requests[0].headers["authorization"] == f"Bearer token-for-{GATEWAY_URL}"

    async def test_keeps_one_refresh_chain_across_wallet_and_gateway_calls(
        self, idp: MockIdp, harness: Harness
    ) -> None:
        await harness.grants.save("u1", "refresh-0")
        idp.api_handler = lambda _request: json_response({**ACCOUNT, "balance": "1"})
        idp.gateway_handler = lambda _request: json_response({"data": []})
        user = harness.ai.for_user("u1")

        await asyncio.gather(user.wallet.get_account(), user.gateway.list_models())

        presented = [request.form.get("refresh_token") for request in idp.requests_to("/token")]
        assert presented == ["refresh-0", "refresh-1"]

    async def test_reuses_a_gateway_token_until_it_nears_expiry_and_mints_a_new_one_after_a_401(
        self, idp: MockIdp, harness: Harness
    ) -> None:
        await harness.grants.save("u1", "refresh-0")
        status = 200
        idp.gateway_handler = lambda _request: (
            json_response({"data": []}) if status == 200 else httpx.Response(status)
        )
        gateway = harness.ai.for_user("u1").gateway

        await gateway.list_models()
        await gateway.list_models()
        assert len(harness.resources) == 1

        status = 401
        with pytest.raises(AuthAiError):
            await gateway.list_models()
        status = 200
        await gateway.list_models()

        assert len(harness.resources) == 2

    async def test_mints_a_new_token_when_the_cached_one_is_about_to_expire(
        self, idp: MockIdp, harness: Harness
    ) -> None:
        await harness.grants.save("u1", "refresh-0")
        harness.expires_in = 10
        idp.gateway_handler = lambda _request: json_response({"data": []})
        gateway = harness.ai.for_user("u1").gateway

        await gateway.list_models()
        await gateway.list_models()

        assert len(harness.resources) == 2

    async def test_retries_the_wallet_once_with_a_fresh_token_after_a_401(
        self, idp: MockIdp, harness: Harness
    ) -> None:
        await harness.grants.save("u1", "refresh-0")
        idp.api_handler = lambda request: (
            json_response(ACCOUNT)
            if len(harness.resources) > 1
            else json_response({"error": {"code": "AUTH_001", "message": "expired"}}, 401)
        )

        account = await harness.ai.for_user("u1").wallet.get_account()

        assert account.can_spend is True
        assert harness.resources == [ISSUER, ISSUER]

    async def test_requires_a_sign_in_when_the_user_has_no_grant(self, harness: Harness) -> None:
        with pytest.raises(AuthAiError) as caught:
            await harness.ai.for_user("ghost").wallet.get_account()

        assert caught.value.code == "TOK_002"

    async def test_builds_the_gateway_client_once_per_user_object(self, harness: Harness) -> None:
        user = harness.ai.for_user("u1")

        assert user.gateway is user.gateway

    async def test_explains_how_to_enable_the_gateway_when_no_url_is_configured(
        self, harness: Harness
    ) -> None:
        harness.build(None)

        with pytest.raises(AuthAiError) as caught:
            _ = harness.ai.for_user("u1").gateway

        assert caught.value.code == "CFG_001"
        assert "gateway_url" in caught.value.message

    async def test_still_serves_the_wallet_without_a_gateway_url(
        self, idp: MockIdp, harness: Harness
    ) -> None:
        harness.build(None)
        await harness.grants.save("u1", "refresh-0")
        idp.api_handler = lambda _request: json_response(ACCOUNT)

        account = await harness.ai.for_user("u1").wallet.get_account()

        assert account.can_spend is True
        assert harness.resources == [ISSUER]


class FakeGrants:
    def __init__(self) -> None:
        self.requested: list[tuple[str, str | None]] = []
        self.invalidated: list[tuple[str, str | None]] = []

    async def get_access_token(self, grant_id: str, *, resource: str | None = None) -> AccessToken:
        self.requested.append((grant_id, resource))
        return AccessToken(f"fake-{len(self.requested)}", now_seconds() + 3600)

    def invalidate(self, grant_id: str, resource: str | None = None) -> None:
        self.invalidated.append((grant_id, resource))


class TestWithAnyGrantSource:
    @pytest.fixture
    async def build(self, idp: MockIdp) -> AsyncIterator[Callable[[FakeGrants], AiClient]]:
        auth = create_test_auth(idp, gateway_url=GATEWAY_URL)

        def factory(grants: FakeGrants) -> AiClient:
            return AiClient(auth=auth, grants=grants)

        yield factory
        await auth.http.aclose()

    async def test_asks_for_the_audience_of_each_client(
        self, idp: MockIdp, build: Callable[[FakeGrants], AiClient]
    ) -> None:
        grants = FakeGrants()
        idp.api_handler = lambda _request: json_response(ACCOUNT)
        idp.gateway_handler = lambda _request: json_response({"data": []})
        user = build(grants).for_user("u1")

        await user.wallet.get_account()
        await user.gateway.list_models()
        await user.gateway.get_access_token()

        assert grants.requested == [("u1", ISSUER), ("u1", GATEWAY_URL), ("u1", GATEWAY_URL)]
        assert idp.requests[-1].headers["authorization"] == "Bearer fake-1"
        assert idp.gateway_requests[0].headers["authorization"] == "Bearer fake-2"

    async def test_invalidates_the_token_of_the_audience_the_service_refused(
        self, idp: MockIdp, build: Callable[[FakeGrants], AiClient]
    ) -> None:
        grants = FakeGrants()
        idp.gateway_handler = lambda _request: httpx.Response(401)
        user = build(grants).for_user("u1")

        with pytest.raises(AuthAiError):
            await user.gateway.list_models()

        assert grants.invalidated == [("u1", GATEWAY_URL)]
