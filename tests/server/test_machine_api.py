from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from types import SimpleNamespace

import httpx
import pytest

from auth_ai import AuthAiError, AuthClient
from auth_ai.server import MachineApi
from auth_ai.server import machine_tokens as machine_tokens_module
from tests.support.mock_idp import (
    MockIdp,
    RecordedRequest,
    create_test_auth,
    json_response,
)

SUBSCRIPTION = {
    "plan": {"id": "p1", "name": "Premium"},
    "isActive": True,
    "expiresAt": None,
    "stripeStatus": "active",
    "currentPeriodStart": "2026-10-01T00:00:00.000Z",
    "currentPeriodEnd": "2026-11-01T00:00:00.000Z",
    "cancelAtPeriodEnd": False,
    "canceledAt": None,
}
AGGREGATE = {"key": "docs", "total": "12", "updatedAt": "2026-10-31T08:00:00.000Z"}


@dataclass
class TokenIssuer:
    issued: int = 0

    def __call__(self, _request: RecordedRequest) -> httpx.Response:
        self.issued += 1
        return json_response(
            {"access_token": f"machine-{self.issued}", "token_type": "Bearer", "expires_in": 3600}
        )


@pytest.fixture
def issuer(idp: MockIdp) -> TokenIssuer:
    issuer = TokenIssuer()
    idp.token_handler = issuer
    idp.api_handler = lambda _request: json_response({})
    return issuer


@pytest.fixture
def api(auth: AuthClient, issuer: TokenIssuer) -> MachineApi:
    return MachineApi(auth)


def api_requests(idp: MockIdp) -> list[RecordedRequest]:
    return [request for request in idp.requests if request.url.path.startswith("/api/")]


def last_api_request(idp: MockIdp) -> RecordedRequest:
    requests = api_requests(idp)
    assert requests, "no API request was made"
    return requests[-1]


class TestMachineTokens:
    async def test_mints_one_token_per_scope_and_caches_it(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response({"subscription": None})

        await api.billing.get_subscription("u1")
        await api.billing.get_subscription("u2")

        grants = idp.requests_to("/token")
        assert len(grants) == 1
        assert grants[0].form["grant_type"] == "client_credentials"
        assert grants[0].form["scope"] == "billing:read"
        assert last_api_request(idp).headers["authorization"] == "Bearer machine-1"

    async def test_mints_a_separate_token_for_each_scope(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response({"aggregates": []})

        await api.consumption.list_aggregates("u1")
        await api.consumption.list_aggregates("u1")
        idp.api_handler = lambda _request: json_response({"subscription": None})
        await api.billing.get_subscription("u1")

        scopes = [request.form["scope"] for request in idp.requests_to("/token")]
        assert scopes == ["consumption:read", "billing:read"]

    async def test_shares_one_token_request_between_concurrent_calls(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response({"subscription": None})

        await asyncio.gather(
            api.billing.get_subscription("u1"),
            api.billing.get_subscription("u2"),
            api.billing.get_subscription("u3"),
        )

        assert len(idp.requests_to("/token")) == 1

    async def test_renews_a_token_shortly_before_it_expires(
        self, idp: MockIdp, api: MachineApi, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        idp.api_handler = lambda _request: json_response({"subscription": None})
        await api.billing.get_subscription("u1")

        monkeypatch.setattr(
            machine_tokens_module, "time", SimpleNamespace(time=lambda: time.time() + 3600 - 29)
        )
        await api.billing.get_subscription("u1")

        assert len(idp.requests_to("/token")) == 2
        assert last_api_request(idp).headers["authorization"] == "Bearer machine-2"

    async def test_retries_once_with_a_fresh_token_after_a_401(
        self, idp: MockIdp, api: MachineApi, issuer: TokenIssuer
    ) -> None:
        def handler(request: RecordedRequest) -> httpx.Response:
            if request.headers["authorization"] == "Bearer machine-2":
                return json_response({"subscription": None})
            return json_response({"error": {"code": "AUTH_001", "message": "expired"}}, 401)

        idp.api_handler = handler

        assert await api.billing.get_subscription("u1") is None
        assert len(api_requests(idp)) == 2
        assert issuer.issued == 2

    async def test_gives_up_after_a_second_401(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response(
            {"error": {"code": "AUTH_001", "message": "nope"}}, 401
        )

        with pytest.raises(AuthAiError) as raised:
            await api.billing.get_subscription("u1")

        assert raised.value.code == "API_001"
        assert raised.value.details == {"status": 401, "apiCode": "AUTH_001"}
        assert len(api_requests(idp)) == 2

    async def test_requires_a_confidential_client(self, idp: MockIdp) -> None:
        public_auth = create_test_auth(idp, client_secret=None)
        try:
            with pytest.raises(AuthAiError) as raised:
                MachineApi(public_auth)
        finally:
            await public_auth.http.aclose()

        assert raised.value.code == "CFG_001"


class TestMachineScopeNotGranted:
    async def test_names_the_scope_in_the_details_only_never_in_the_message(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.token_handler = lambda _request: json_response(
            {
                "error": "invalid_scope",
                "error_description": "The following scopes are invalid: billing:read",
            },
            400,
        )

        with pytest.raises(AuthAiError) as raised:
            await api.billing.get_usage("u1")

        err = raised.value
        assert err.code == "TOK_004"
        assert err.message == "Insufficient scope"
        assert err.details == {"scope": "billing:read"}
        assert "billing" not in json.dumps(err.to_public_json())
        assert api_requests(idp) == []

    async def test_lets_other_token_failures_through_unchanged(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.token_handler = lambda _request: json_response({"error": "invalid_client"}, 401)

        with pytest.raises(AuthAiError) as raised:
            await api.billing.get_usage("u1")

        assert raised.value.code == "OIDC_003"


class TestBilling:
    async def test_reads_the_subscription(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response({"subscription": SUBSCRIPTION})

        subscription = await api.billing.get_subscription("user/1")

        assert subscription is not None
        assert subscription.plan.name == "Premium"
        assert subscription.is_active is True
        assert subscription.current_period_end == "2026-11-01T00:00:00.000Z"
        assert last_api_request(idp).url.raw_path == b"/api/app/billing/users/user%2F1/subscription"

    async def test_reads_no_subscription(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response({"subscription": None})

        assert await api.billing.get_subscription("u1") is None

    async def test_reads_the_usage(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response(
            {
                "periodStart": "2026-10-01T00:00:00.000Z",
                "features": [
                    {
                        "featureKey": "tokens",
                        "unit": None,
                        "usageLimit": -1,
                        "used": 5,
                        "remaining": None,
                    }
                ],
            }
        )

        usage = await api.billing.get_usage("u1")

        assert usage.features[0].used == 5
        assert usage.features[0].remaining is None
        assert last_api_request(idp).url.path == "/api/app/billing/users/u1/usage"

    async def test_pages_through_invoices(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response({"items": [], "nextCursor": None})

        page = await api.billing.list_invoices("u1", limit=10, cursor="c1")

        assert page.items == []
        assert page.next_cursor is None
        request = last_api_request(idp)
        assert request.url.path == "/api/app/billing/users/u1/invoices"
        assert request.url.params["limit"] == "10"
        assert request.url.params["cursor"] == "c1"

        await api.billing.list_invoices("u1")
        assert last_api_request(idp).url.query == b""

    async def test_flags_a_response_that_is_not_what_auth_service_documents(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response({"subscription": {"plan": "gold"}})

        with pytest.raises(AuthAiError) as raised:
            await api.billing.get_subscription("u1")

        assert raised.value.code == "API_002"

    async def test_flags_a_response_that_is_not_json(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: httpx.Response(200, text="<html>")

        with pytest.raises(AuthAiError) as raised:
            await api.billing.get_usage("u1")

        assert raised.value.code == "API_002"

    async def test_reports_an_error_without_a_documented_body_by_its_status(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: httpx.Response(502, text="bad gateway")

        with pytest.raises(AuthAiError) as raised:
            await api.billing.get_usage("u1")

        assert raised.value.code == "API_001"
        assert raised.value.details == {"status": 502}


class TestConsumption:
    async def test_reports_usage_for_the_application(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response(
            {"success": True, "aggregate": {"key": "docs", "total": "12"}}
        )

        result = await api.consumption.report("u1", "docs", 2, idempotency_key="req-1")

        assert result.aggregate.key == "docs"
        assert result.aggregate.total == "12"
        assert result.metered is False
        request = last_api_request(idp)
        assert request.method == "POST"
        assert request.url.path == "/api/app/consumption/users/u1"
        assert request.json == {"key": "docs", "value": 2, "idempotencyKey": "req-1"}
        assert request.headers["content-type"] == "application/json"
        assert idp.requests_to("/token")[0].form["scope"] == "consumption:write"

    async def test_omits_the_idempotency_key_when_none_is_given(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"success": True, "aggregate": {"key": "docs", "total": "1"}}
        )

        await api.consumption.report("u1", "docs", 1)

        assert last_api_request(idp).json == {"key": "docs", "value": 1}

    async def test_credits_back_with_a_negative_value(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response(
            {"success": True, "aggregate": {"key": "docs", "total": "9"}}
        )

        await api.consumption.report("u1", "docs", -3.5)

        assert last_api_request(idp).json == {"key": "docs", "value": -3.5}

    async def test_reports_a_metered_key_as_such(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response(
            {"success": True, "metered": True, "aggregate": {"key": "ai", "total": "3"}}
        )

        assert (await api.consumption.report("u1", "ai", 1)).metered is True

    async def test_flags_a_report_the_api_did_not_record(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"success": False, "aggregate": {"key": "docs", "total": "1"}}
        )

        with pytest.raises(AuthAiError) as raised:
            await api.consumption.report("u1", "docs", 1)

        assert raised.value.code == "API_002"

    @pytest.mark.parametrize(
        ("user_id", "key", "value", "idempotency_key"),
        [
            pytest.param("u1", "a-b", 1, None, id="a key with a dash"),
            pytest.param("u1", "a" * 65, 1, None, id="a key over 64 characters"),
            pytest.param("u1", "", 1, None, id="an empty key"),
            pytest.param("u1", "docs", float("inf"), None, id="a non-finite value"),
            pytest.param("u1", "docs", float("nan"), None, id="a NaN value"),
            pytest.param("", "docs", 1, None, id="an empty user"),
            pytest.param("u1", "docs", 1, "", id="an empty idempotency key"),
            pytest.param("u1", "docs", 1, "k" * 201, id="an idempotency key over 200 characters"),
        ],
    )
    async def test_rejects_an_invalid_report_before_any_request(
        self,
        idp: MockIdp,
        api: MachineApi,
        user_id: str,
        key: str,
        value: float,
        idempotency_key: str | None,
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await api.consumption.report(user_id, key, value, idempotency_key=idempotency_key)

        assert raised.value.code == "CFG_001"
        assert idp.requests == []

    async def test_lists_and_reads_running_totals(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda request: (
            json_response({"aggregate": AGGREGATE})
            if request.url.path.endswith("/docs")
            else json_response({"aggregates": [AGGREGATE]})
        )

        aggregates = await api.consumption.list_aggregates("u1")

        assert len(aggregates) == 1
        assert aggregates[0].key == "docs"
        assert aggregates[0].updated_at == "2026-10-31T08:00:00.000Z"
        assert idp.requests_to("/token")[-1].form["scope"] == "consumption:read"
        assert last_api_request(idp).url.path == "/api/app/consumption/users/u1"

        aggregate = await api.consumption.get_aggregate("u1", "docs")

        assert aggregate.total == "12"
        assert last_api_request(idp).url.path == "/api/app/consumption/users/u1/docs"

    async def test_surfaces_an_unknown_key_as_an_api_error(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"error": {"code": "CONS_003", "message": "Consumption record not found"}}, 404
        )

        with pytest.raises(AuthAiError) as raised:
            await api.consumption.get_aggregate("u1", "ghost")

        assert raised.value.code == "API_001"
        assert raised.value.details == {"status": 404, "apiCode": "CONS_003"}
