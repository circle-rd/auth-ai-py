from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable

import httpx2
import pytest

from auth_ai import (
    AuthAiError,
    GatewayAuth,
    GatewayClient,
    is_insufficient_credit,
    is_insufficient_credit_status,
    to_gateway_error,
)
from tests.support.mock_idp import GATEWAY_URL, MockIdp, RecordedRequest, json_response


class CountingTokens:
    def __init__(self) -> None:
        self.minted = 0
        self.invalidations = 0

    async def get_token(self) -> str:
        self.minted += 1
        return f"gw-token-{self.minted}"

    def invalidate(self) -> None:
        self.invalidations += 1


class StatusError(Exception):
    def __init__(self, **attributes: object) -> None:
        super().__init__("x")
        for name, value in attributes.items():
            setattr(self, name, value)


@pytest.fixture
def tokens() -> CountingTokens:
    return CountingTokens()


@pytest.fixture
async def client(idp: MockIdp, tokens: CountingTokens) -> AsyncIterator[GatewayClient]:
    http = idp.http_client()
    yield GatewayClient(gateway_url=GATEWAY_URL, tokens=tokens, http=http, timeout_seconds=5)
    await http.aclose()


async def rejection(call: Awaitable[object]) -> AuthAiError:
    with pytest.raises(AuthAiError) as caught:
        await call
    return caught.value


def sent_authorizations(idp: MockIdp) -> list[str | None]:
    return [request.headers.get("authorization") for request in idp.gateway_requests]


class TestHttpClient:
    async def test_signs_a_request_to_the_gateway_with_a_fresh_token_each_time(
        self, idp: MockIdp, client: GatewayClient
    ) -> None:
        idp.gateway_handler = lambda _request: json_response({"ok": True})

        async with client.create_http_client(transport=httpx2.MockTransport(idp.handle)) as http:
            await http.post(f"{GATEWAY_URL}/v1/chat/completions", json={"model": "m"})
            await http.get(f"{GATEWAY_URL}/v1/models")

        assert sent_authorizations(idp) == ["Bearer gw-token-1", "Bearer gw-token-2"]
        assert idp.gateway_requests[0].json == {"model": "m"}
        assert idp.gateway_requests[0].headers["content-type"] == "application/json"

    async def test_replaces_a_placeholder_key_set_by_an_openai_compatible_sdk(
        self, idp: MockIdp, client: GatewayClient
    ) -> None:
        idp.gateway_handler = lambda _request: json_response({})

        async with client.create_http_client(transport=httpx2.MockTransport(idp.handle)) as http:
            await http.get(
                f"{GATEWAY_URL}/v1/models", headers={"authorization": "Bearer placeholder"}
            )

        assert sent_authorizations(idp) == ["Bearer gw-token-1"]

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.test/v1/models",
            "https://llm.test.evil.test/v1/models",
            "https://llm.test:8443/v1/models",
            "http://llm.test/v1/models",
        ],
    )
    async def test_refuses_any_other_origin_so_the_token_cannot_leak(
        self, idp: MockIdp, client: GatewayClient, tokens: CountingTokens, url: str
    ) -> None:
        async with client.create_http_client(transport=httpx2.MockTransport(idp.handle)) as http:
            with pytest.raises(AuthAiError) as caught:
                await http.get(url)

        assert caught.value.code == "CFG_001"
        assert idp.gateway_requests == []
        assert idp.requests == []
        assert tokens.minted == 0

    async def test_drops_the_cached_token_on_a_401_and_returns_the_response(
        self, idp: MockIdp, client: GatewayClient, tokens: CountingTokens
    ) -> None:
        idp.gateway_handler = lambda _request: httpx2.Response(401)

        async with client.create_http_client(transport=httpx2.MockTransport(idp.handle)) as http:
            response = await http.get(f"{GATEWAY_URL}/v1/models")

        assert response.status_code == 401
        assert tokens.invalidations == 1
        assert len(idp.gateway_requests) == 1

    async def test_keeps_the_token_after_a_success(
        self, idp: MockIdp, client: GatewayClient, tokens: CountingTokens
    ) -> None:
        idp.gateway_handler = lambda _request: json_response({})

        async with client.create_http_client(transport=httpx2.MockTransport(idp.handle)) as http:
            await http.get(f"{GATEWAY_URL}/v1/models")

        assert tokens.invalidations == 0

    async def test_does_not_follow_redirects_to_another_origin(
        self, idp: MockIdp, client: GatewayClient
    ) -> None:
        idp.gateway_handler = lambda _request: httpx2.Response(
            302, headers={"location": "https://evil.test/steal"}
        )

        async with client.create_http_client(transport=httpx2.MockTransport(idp.handle)) as http:
            response = await http.get(f"{GATEWAY_URL}/v1/models")

        assert response.status_code == 302
        assert idp.requests == []

    async def test_uses_the_configured_timeout_unless_overridden(
        self, client: GatewayClient
    ) -> None:
        async with client.create_http_client() as default:
            assert default.timeout == httpx2.Timeout(5)
        async with client.create_http_client(timeout=2) as custom:
            assert custom.timeout == httpx2.Timeout(2)

    async def test_exposes_the_auth_as_an_httpx_auth(self, client: GatewayClient) -> None:
        assert isinstance(client.auth, GatewayAuth)
        assert isinstance(client.auth, httpx2.Auth)


class TestOpenAiCompatibleAccess:
    async def test_exposes_the_base_url_and_a_raw_token(self, client: GatewayClient) -> None:
        assert client.openai_base_url == f"{GATEWAY_URL}/v1"
        assert await client.get_access_token() == "gw-token-1"
        assert await client.get_access_token() == "gw-token-2"


class TestListing:
    async def test_lists_the_models_of_the_plan(self, idp: MockIdp, client: GatewayClient) -> None:
        idp.gateway_handler = lambda _request: json_response(
            {
                "object": "list",
                "data": [
                    {"id": "gpt-4o-mini", "object": "model", "created": 1, "owned_by": "openai"},
                    {"id": "local-llama", "extra": True},
                ],
            }
        )

        models = await client.list_models()

        assert [model.id for model in models] == ["gpt-4o-mini", "local-llama"]
        assert models[0].owned_by == "openai"
        assert models[1].model_extra == {"extra": True}
        request = idp.gateway_requests[0]
        assert str(request.url) == f"{GATEWAY_URL}/v1/models"
        assert request.headers["accept"] == "application/json"
        assert request.headers["authorization"] == "Bearer gw-token-1"

    async def test_lists_agents_and_mcp_servers(self, idp: MockIdp, client: GatewayClient) -> None:
        idp.gateway_handler = lambda request: (
            json_response([{"agent_id": "a1", "agent_name": "Researcher"}])
            if request.url.path == "/v1/agents"
            else json_response(
                [
                    {"server_id": "s1", "server_name": "docs", "description": None},
                    {"server_id": "s2", "alias": "web"},
                ]
            )
        )

        agents = await client.list_agents()
        servers = await client.list_mcp_servers()

        assert agents[0].agent_name == "Researcher"
        assert [server.server_id for server in servers] == ["s1", "s2"]
        assert [request.url.path for request in idp.gateway_requests] == [
            "/v1/agents",
            "/v1/mcp/server",
        ]

    async def test_flags_an_answer_that_is_not_the_documented_shape(
        self, idp: MockIdp, client: GatewayClient
    ) -> None:
        idp.gateway_handler = lambda _request: json_response({"data": [{"name": "no-id"}]})

        assert (await rejection(client.list_models())).code == "GW_005"

    async def test_maps_a_refused_listing_to_a_gateway_error(
        self, idp: MockIdp, client: GatewayClient
    ) -> None:
        idp.gateway_handler = lambda _request: json_response(
            {"error": {"message": "This endpoint is not available to users", "type": "auth_error"}},
            403,
        )

        err = await rejection(client.list_agents())

        assert err.code == "GW_003"
        assert err.message == "This endpoint is not available to users"
        assert err.details == {"status": 403, "type": "auth_error"}

    async def test_reports_an_unreachable_gateway_as_unavailable(
        self, idp: MockIdp, client: GatewayClient
    ) -> None:
        def refuse(request: RecordedRequest) -> httpx2.Response:
            raise httpx2.ConnectError("connection refused")

        idp.gateway_handler = refuse

        err = await rejection(client.list_models())

        assert err.code == "GW_004"
        assert isinstance(err.__cause__, httpx2.ConnectError)


class TestPostJson:
    async def test_posts_json_with_a_fresh_token_and_returns_the_parsed_answer(
        self, idp: MockIdp, client: GatewayClient
    ) -> None:
        idp.gateway_handler = lambda _request: json_response(
            {"choices": [{"message": {"content": "hi"}}]}
        )

        answer = await client.post_json("/v1/chat/completions", {"model": "m", "messages": []})

        assert answer == {"choices": [{"message": {"content": "hi"}}]}
        request = idp.gateway_requests[0]
        assert request.method == "POST"
        assert request.headers["authorization"] == "Bearer gw-token-1"
        assert request.headers["content-type"] == "application/json"
        assert request.json == {"model": "m", "messages": []}

    async def test_maps_an_empty_wallet_to_gw_001(
        self, idp: MockIdp, client: GatewayClient
    ) -> None:
        idp.gateway_handler = lambda _request: json_response(
            {
                "error": {
                    "message": "Insufficient credit. Top up your account to continue.",
                    "type": "insufficient_credit",
                    "code": "402",
                }
            },
            402,
        )

        err = await rejection(client.post_json("/v1/embeddings", {"input": "x"}))

        assert err.code == "GW_001"
        assert err.details == {"status": 402, "type": "insufficient_credit"}
        assert is_insufficient_credit(err)

    async def test_maps_a_refusal_without_a_json_body_by_status(
        self, idp: MockIdp, client: GatewayClient
    ) -> None:
        idp.gateway_handler = lambda _request: httpx2.Response(502, text="<html>bad gateway</html>")

        err = await rejection(client.post_json("/v1/embeddings", {"input": "x"}))

        assert err.code == "GW_005"
        assert err.message == "The gateway answered 502"

    async def test_does_not_retry_a_401_and_drops_the_token(
        self, idp: MockIdp, client: GatewayClient, tokens: CountingTokens
    ) -> None:
        idp.gateway_handler = lambda _request: httpx2.Response(401)

        err = await rejection(client.post_json("/v1/embeddings", {"input": "x"}))

        assert err.code == "GW_003"
        assert tokens.invalidations == 1
        assert len(idp.gateway_requests) == 1


class TestMcpEndpoints:
    def test_builds_the_gateway_and_per_server_urls(self, client: GatewayClient) -> None:
        assert client.mcp_url() == f"{GATEWAY_URL}/mcp"
        assert client.mcp_url("docs-server_1") == f"{GATEWAY_URL}/docs-server_1/mcp"

    @pytest.mark.parametrize("name", ["", "a/b", "..", "a b", "x?y=1", "x#y", "-start"])
    def test_refuses_the_server_name(self, client: GatewayClient, name: str) -> None:
        with pytest.raises(AuthAiError) as caught:
            client.mcp_url(name)

        assert caught.value.code == "CFG_001"


class TestToGatewayError:
    @pytest.mark.parametrize(
        ("status", "code"),
        [
            (402, "GW_001"),
            (429, "GW_002"),
            (401, "GW_003"),
            (403, "GW_003"),
            (503, "GW_004"),
            (500, "GW_005"),
            (404, "GW_005"),
        ],
    )
    def test_maps_the_http_status(self, status: int, code: str) -> None:
        assert to_gateway_error(status, None).code == code

    def test_keeps_the_gateway_message_and_error_type(self) -> None:
        err = to_gateway_error(
            402,
            {
                "error": {
                    "message": "Insufficient credit. Top up your account to continue.",
                    "type": "insufficient_credit",
                    "code": "402",
                }
            },
        )

        assert err.message == "Insufficient credit. Top up your account to continue."
        assert err.details == {"status": 402, "type": "insufficient_credit"}
        assert is_insufficient_credit(err)

    def test_reports_how_long_to_wait_before_retrying_a_rate_limit(self) -> None:
        err = to_gateway_error(429, None, httpx2.Headers({"retry-after": "12"}))

        assert err.details == {"status": 429, "retryAfterSeconds": 12}

    @pytest.mark.parametrize("retry_after", ["soon", "-3", "inf", "nan", ""])
    def test_ignores_a_retry_after_that_is_not_a_usable_delay(self, retry_after: str) -> None:
        err = to_gateway_error(429, None, httpx2.Headers({"retry-after": retry_after}))

        assert err.details == {"status": 429}

    def test_ignores_retry_after_on_other_statuses(self) -> None:
        err = to_gateway_error(503, None, httpx2.Headers({"retry-after": "12"}))

        assert err.details == {"status": 503}

    @pytest.mark.parametrize(
        "body",
        [
            "<html>",
            [],
            {"error": "boom"},
            {"error": {"message": 5, "type": ["x"]}},
        ],
    )
    def test_ignores_a_body_that_is_not_an_openai_style_error(self, body: object) -> None:
        err = to_gateway_error(502, body)

        assert err.message == "The gateway answered 502"
        assert err.details == {"status": 502}

    def test_falls_back_to_a_message_naming_the_status(self) -> None:
        assert to_gateway_error(502, "<html>").message == "The gateway answered 502"

    def test_uses_the_registry_message_for_a_known_status_without_a_gateway_message(self) -> None:
        err = to_gateway_error(402, None)

        assert err.message == "Insufficient credit: the wallet cannot pay for this call"


class TestCreditHelpers:
    def test_recognises_the_status_of_an_openai_compatible_sdk_error(self) -> None:
        assert is_insufficient_credit_status(StatusError(status_code=402))
        assert is_insufficient_credit_status(StatusError(status=402))
        assert not is_insufficient_credit_status(StatusError(status_code=500))
        assert not is_insufficient_credit_status(StatusError(status=500))
        assert not is_insufficient_credit_status(None)
        assert not is_insufficient_credit_status("402")
        assert not is_insufficient_credit_status(Exception("402"))

    def test_recognises_the_gateway_error_only(self) -> None:
        assert is_insufficient_credit(to_gateway_error(402, None))
        assert not is_insufficient_credit(to_gateway_error(429, None))
        assert not is_insufficient_credit(Exception("x"))
        assert not is_insufficient_credit(StatusError(status_code=402))
