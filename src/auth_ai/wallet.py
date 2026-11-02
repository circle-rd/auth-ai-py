from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any, Final, Literal

from pydantic import BeforeValidator, PlainSerializer

from .http import ApiModel

if TYPE_CHECKING:
    from .http import JsonHttp

#: 1 EUR in the ledger unit.
MICRO_PER_EUR: Final = 1_000_000

#: Key handed to the token supplier: the wallet audience of auth-service.
WALLET_SCOPE_KEY: Final = "wallet"

_AMOUNT_PATTERN: Final = re.compile(r"-?[0-9]{1,19}")


def _parse_amount(value: object) -> int:
    if isinstance(value, str) and _AMOUNT_PATTERN.fullmatch(value):
        return int(value)
    raise ValueError("must be an integer string of micro-euros")


# Amounts travel as integer strings of micro-euros: a JSON number cannot carry them exactly.
type Amount = Annotated[
    int,
    BeforeValidator(_parse_amount),
    PlainSerializer(str, return_type=str, when_used="json"),
]

type WalletTransactionType = Literal["topup", "grant", "refund", "usage", "adjust", "reversal"]


class WalletAccount(ApiModel):
    #: Negative when usage or a refund exceeded the credit.
    balance: Amount
    is_unlimited: bool
    #: Whether new spending is allowed: unlimited, or a strictly positive balance.
    can_spend: bool
    currency: Literal["eur"]


class WalletTransaction(ApiModel):
    id: str
    type: WalletTransactionType
    amount: Amount
    delta: Amount
    balance_after: Amount
    application_id: str | None
    metadata: dict[str, Any]
    created_at: datetime


class WalletTransactionPage(ApiModel):
    items: list[WalletTransaction]
    next_cursor: str | None


class ModelUsage(ApiModel):
    #: `mcp` for tool calls, `other` when the gateway reported no model.
    model: str
    amount: Amount
    count: int
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ApplicationUsage(ApiModel):
    application_id: str | None
    name: str | None
    slug: str | None
    amount: Amount
    count: int


class DailyPoint(ApiModel):
    date: str
    amount: Amount
    count: int


class KindUsage(ApiModel):
    kind: str
    amount: Amount
    count: int


class DailyUsage(ApiModel):
    date: str
    amount: Amount
    count: int
    by_application: list[ApplicationUsage]
    by_model: list[ModelUsage]


class WalletStats(ApiModel):
    days: int
    total: Amount
    #: Part of `total` never deducted: usage on an unlimited account.
    not_billed: Amount
    calls: int
    series: list[DailyPoint]
    by_application: list[ApplicationUsage]
    by_kind: list[KindUsage]
    by_model: list[ModelUsage]
    daily: list[DailyUsage]


class WalletSessionUsage(ApiModel):
    session_id: str
    application_slug: str | None
    days: int
    total: Amount
    not_billed: Amount
    calls: int
    by_model: list[ModelUsage]


class TopupOptions(ApiModel):
    enabled: bool
    currency: Literal["eur"]
    min_cents: int
    max_cents: int


def format_euros(amount: int, fraction_digits: int = 2) -> str:
    """Exact decimal euros of a micro-euro amount, e.g. `5_000_000` gives `"5.00"`.

    The amount is truncated toward zero at `fraction_digits` (0 to 6, 2 by
    default): rounding up could show a user more credit than they hold.
    """
    if not 0 <= fraction_digits <= 6:
        raise ValueError("fraction_digits must be an integer from 0 to 6")
    whole, micro = divmod(abs(amount), MICRO_PER_EUR)
    text = str(whole)
    if fraction_digits:
        text += f".{micro:06d}"[: fraction_digits + 1]
    # A negative amount truncated to zero is not a debt worth a minus sign.
    return f"-{text}" if amount < 0 and any(c in "123456789" for c in text) else text


class WalletClient:
    """The signed-in user's own wallet, read with their access token.

    The token is minted for the auth-service audience with the `wallet:self:read`
    scope. Debits are made by the gateway after each call: an application only
    reads, and refills by sending the user to `topup_url()`.
    """

    def __init__(self, http: JsonHttp, issuer: str) -> None:
        self._http = http
        self._issuer = issuer

    async def get_account(self) -> WalletAccount:
        """Decide with `can_spend` rather than recomputing it from the balance."""
        return await self._http.request(
            "GET", "/api/user/wallet", scope=WALLET_SCOPE_KEY, schema=WalletAccount
        )

    async def get_stats(self, *, days: int | None = None) -> WalletStats:
        """`days` is 1 to 90, 30 by default."""
        return await self._http.request(
            "GET",
            "/api/user/wallet/stats",
            scope=WALLET_SCOPE_KEY,
            query={"days": days},
            schema=WalletStats,
        )

    async def get_session_usage(
        self, session_id: str, *, days: int | None = None
    ) -> WalletSessionUsage:
        """What one chat session spent, for the calling application only.

        The id is the one passed to the gateway as `metadata.session_id`.
        """
        return await self._http.request(
            "GET",
            "/api/user/wallet/usage",
            scope=WALLET_SCOPE_KEY,
            query={"sessionId": session_id, "days": days},
            schema=WalletSessionUsage,
        )

    async def list_transactions(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        type: WalletTransactionType | None = None,  # noqa: A002
    ) -> WalletTransactionPage:
        """Newest first, keyset-paginated: pass `next_cursor` back until it is None."""
        return await self._http.request(
            "GET",
            "/api/user/wallet/transactions",
            scope=WALLET_SCOPE_KEY,
            query={"limit": limit, "cursor": cursor, "type": type},
            schema=WalletTransactionPage,
        )

    async def get_topup_options(self) -> TopupOptions:
        return await self._http.request(
            "GET",
            "/api/user/wallet/topup-options",
            scope=WALLET_SCOPE_KEY,
            schema=TopupOptions,
        )

    def topup_url(self) -> str:
        """The Credit tab of the user's profile.

        Checkout needs the user's session, not a bearer token, so an application
        links there instead of creating it.
        """
        return f"{self._issuer}/profile"
