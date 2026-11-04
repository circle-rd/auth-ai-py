from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx2
import pytest

from auth_ai import MICRO_PER_EUR, AuthAiError, WalletClient, format_euros
from auth_ai.http import JsonHttp
from tests.support.mock_idp import ISSUER, MockIdp, RecordedRequest, json_response

ACCOUNT = {"isUnlimited": False, "canSpend": True, "currency": "eur"}
MODEL = {
    "model": "gpt-4o-mini",
    "amount": "18420",
    "count": 6,
    "promptTokens": 1200,
    "completionTokens": 400,
    "totalTokens": 1600,
}
APPLICATION = {
    "applicationId": "a1",
    "name": "My app",
    "slug": "my-app",
    "amount": "18420",
    "count": 6,
}


class CountingTokens:
    def __init__(self) -> None:
        self.minted = 0
        self.invalidated: list[str] = []

    async def get_token(self, key: str) -> str:
        self.minted += 1
        return f"user-token-{self.minted}"

    def invalidate(self, key: str) -> None:
        self.invalidated.append(key)


@pytest.fixture
def tokens() -> CountingTokens:
    return CountingTokens()


@pytest.fixture
async def wallet(idp: MockIdp, tokens: CountingTokens) -> AsyncIterator[WalletClient]:
    http = idp.http_client()
    json_http = JsonHttp(base_url=ISSUER, http=http, timeout_seconds=5, tokens=tokens)
    yield WalletClient(json_http, ISSUER)
    await http.aclose()


def last_request(idp: MockIdp) -> RecordedRequest:
    return idp.requests[-1]


class TestAccount:
    async def test_reads_the_balance_as_an_int_with_the_user_token(
        self, idp: MockIdp, wallet: WalletClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {**ACCOUNT, "balance": "-9007199254740993", "canSpend": False}
        )

        account = await wallet.get_account()

        assert account.balance == -9007199254740993
        assert isinstance(account.balance, int)
        assert account.is_unlimited is False
        assert account.can_spend is False
        assert account.currency == "eur"
        assert last_request(idp).url.path == "/api/user/wallet"
        assert last_request(idp).headers["authorization"] == "Bearer user-token-1"

    async def test_serialises_the_balance_back_to_a_string(
        self, idp: MockIdp, wallet: WalletClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {**ACCOUNT, "balance": "-9007199254740993"}
        )

        account = await wallet.get_account()

        assert account.to_json() == {
            "balance": "-9007199254740993",
            "isUnlimited": False,
            "canSpend": True,
            "currency": "eur",
        }

    async def test_retries_once_with_a_fresh_token_after_a_401(
        self, idp: MockIdp, wallet: WalletClient, tokens: CountingTokens
    ) -> None:
        idp.api_handler = lambda request: (
            json_response({**ACCOUNT, "balance": "1"})
            if request.headers["authorization"] == "Bearer user-token-2"
            else json_response({"error": {"code": "AUTH_001", "message": "expired"}}, 401)
        )

        account = await wallet.get_account()

        assert account.can_spend is True
        assert tokens.invalidated == ["wallet"]
        assert tokens.minted == 2

    async def test_does_not_retry_a_second_401(
        self, idp: MockIdp, wallet: WalletClient, tokens: CountingTokens
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"error": {"code": "AUTH_001", "message": "expired"}}, 401
        )

        with pytest.raises(AuthAiError) as caught:
            await wallet.get_account()

        assert caught.value.code == "API_001"
        assert len(idp.requests) == 2
        assert tokens.invalidated == ["wallet"]

    @pytest.mark.parametrize("balance", [5, "1.5", "12abc", "", "1" * 20, None])
    async def test_rejects_a_balance_that_is_not_an_integer_string(
        self, idp: MockIdp, wallet: WalletClient, balance: object
    ) -> None:
        idp.api_handler = lambda _request: json_response({**ACCOUNT, "balance": balance})

        with pytest.raises(AuthAiError) as caught:
            await wallet.get_account()

        assert caught.value.code == "API_002"

    async def test_rejects_an_unexpected_currency(self, idp: MockIdp, wallet: WalletClient) -> None:
        idp.api_handler = lambda _request: json_response(
            {**ACCOUNT, "balance": "1", "currency": "usd"}
        )

        with pytest.raises(AuthAiError) as caught:
            await wallet.get_account()

        assert caught.value.code == "API_002"

    async def test_rejects_a_body_that_is_not_json(
        self, idp: MockIdp, wallet: WalletClient
    ) -> None:
        idp.api_handler = lambda _request: httpx2.Response(200, text="<html>")

        with pytest.raises(AuthAiError) as caught:
            await wallet.get_account()

        assert caught.value.code == "API_002"

    async def test_surfaces_the_auth_service_error_code(
        self, idp: MockIdp, wallet: WalletClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"error": {"code": "AUTH_011", "message": "scope"}}, 403
        )

        with pytest.raises(AuthAiError) as caught:
            await wallet.get_account()

        assert caught.value.code == "API_001"
        assert caught.value.details == {"status": 403, "apiCode": "AUTH_011"}

    async def test_reports_a_failure_without_an_error_body_by_status(
        self, idp: MockIdp, wallet: WalletClient
    ) -> None:
        idp.api_handler = lambda _request: httpx2.Response(502, text="bad gateway")

        with pytest.raises(AuthAiError) as caught:
            await wallet.get_account()

        assert caught.value.code == "API_001"
        assert caught.value.details == {"status": 502}


class TestStatsAndSessionUsage:
    async def test_parses_the_spend_statistics(self, idp: MockIdp, wallet: WalletClient) -> None:
        idp.api_handler = lambda _request: json_response(
            {
                "days": 7,
                "total": "18420",
                "notBilled": "0",
                "calls": 6,
                "series": [{"date": "2026-10-30", "amount": "18420", "count": 6}],
                "byApplication": [APPLICATION],
                "byKind": [{"kind": "llm", "amount": "18420", "count": 6}],
                "byModel": [MODEL],
                "daily": [
                    {
                        "date": "2026-10-30",
                        "amount": "18420",
                        "count": 6,
                        "byApplication": [APPLICATION],
                        "byModel": [MODEL],
                    }
                ],
            }
        )

        stats = await wallet.get_stats(days=7)

        assert stats.total == 18420
        assert stats.not_billed == 0
        assert stats.by_model[0].total_tokens == 1600
        assert stats.by_kind[0].kind == "llm"
        assert stats.daily[0].by_application[0].slug == "my-app"
        assert last_request(idp).url.params["days"] == "7"

        serialised = stats.to_json()
        assert serialised["total"] == "18420"
        assert serialised["daily"][0]["byModel"][0]["amount"] == "18420"

        await wallet.get_stats()
        assert last_request(idp).url.query == b""

    async def test_reads_what_a_session_spent(self, idp: MockIdp, wallet: WalletClient) -> None:
        idp.api_handler = lambda _request: json_response(
            {
                "sessionId": "s 1",
                "applicationSlug": "my-app",
                "days": 30,
                "total": "18420",
                "notBilled": "0",
                "calls": 6,
                "byModel": [MODEL],
            }
        )

        usage = await wallet.get_session_usage("s 1", days=30)

        assert usage.total == 18420
        assert usage.session_id == "s 1"
        assert last_request(idp).url.path == "/api/user/wallet/usage"
        assert last_request(idp).url.params["sessionId"] == "s 1"
        assert last_request(idp).url.params["days"] == "30"


class TestTransactionsAndTopup:
    async def test_pages_through_the_ledger(self, idp: MockIdp, wallet: WalletClient) -> None:
        idp.api_handler = lambda _request: json_response(
            {
                "items": [
                    {
                        "id": "t1",
                        "type": "topup",
                        "amount": "5000000",
                        "delta": "5000000",
                        "balanceAfter": "5000000",
                        "applicationId": None,
                        "metadata": {"invoice": "INV-1"},
                        "createdAt": "2026-10-31T08:00:00.000Z",
                    }
                ],
                "nextCursor": "c2",
            }
        )

        page = await wallet.list_transactions(limit=1, cursor="c1", type="topup")

        assert page.next_cursor == "c2"
        assert page.items[0].delta == 5_000_000
        assert page.items[0].balance_after == 5_000_000
        assert page.items[0].application_id is None
        assert page.items[0].metadata == {"invoice": "INV-1"}
        assert page.items[0].created_at == datetime(2026, 10, 31, 8, 0, tzinfo=UTC)
        params = last_request(idp).url.params
        assert last_request(idp).url.path == "/api/user/wallet/transactions"
        assert params["limit"] == "1"
        assert params["cursor"] == "c1"
        assert params["type"] == "topup"
        assert page.to_json()["items"][0]["delta"] == "5000000"

    async def test_rejects_an_unknown_transaction_type(
        self, idp: MockIdp, wallet: WalletClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {
                "items": [
                    {
                        "id": "t1",
                        "type": "gift",
                        "amount": "1",
                        "delta": "1",
                        "balanceAfter": "1",
                        "applicationId": None,
                        "metadata": {},
                        "createdAt": "2026-10-31T08:00:00.000Z",
                    }
                ],
                "nextCursor": None,
            }
        )

        with pytest.raises(AuthAiError) as caught:
            await wallet.list_transactions()

        assert caught.value.code == "API_002"

    async def test_tells_whether_online_topup_is_enabled(
        self, idp: MockIdp, wallet: WalletClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"enabled": False, "currency": "eur", "minCents": 500, "maxCents": 50000}
        )

        options = await wallet.get_topup_options()

        assert options.enabled is False
        assert options.min_cents == 500
        assert options.max_cents == 50000

    def test_links_to_the_profile_page_where_checkout_needs_the_users_session(
        self, wallet: WalletClient
    ) -> None:
        assert wallet.topup_url() == f"{ISSUER}/profile"


class TestFormatEuros:
    @pytest.mark.parametrize(
        ("amount", "digits", "text"),
        [
            (0, 2, "0.00"),
            (5_000_000, 2, "5.00"),
            (1_234_567, 2, "1.23"),
            (1_234_567, 6, "1.234567"),
            (1_999_999, 0, "1"),
            (999_999, 2, "0.99"),
            (-500_000, 2, "-0.50"),
            (-1, 2, "0.00"),
            (MICRO_PER_EUR * 1_000_000, 2, "1000000.00"),
        ],
    )
    def test_formats(self, amount: int, digits: int, text: str) -> None:
        assert format_euros(amount, digits) == text

    def test_defaults_to_two_fraction_digits(self) -> None:
        assert format_euros(1_234_567) == "1.23"

    @pytest.mark.parametrize("digits", [-1, 7])
    def test_refuses_a_digit_count_outside_0_to_6(self, digits: int) -> None:
        with pytest.raises(ValueError, match="fraction_digits"):
            format_euros(1, digits)
