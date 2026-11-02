from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import quote

from ..http import ApiModel

if TYPE_CHECKING:
    from ..http import JsonHttp

SCOPE = "billing:read"


class PlanRef(ApiModel):
    id: str
    name: str


class SubscriptionView(ApiModel):
    plan: PlanRef
    is_active: bool
    expires_at: str | None
    stripe_status: str | None
    current_period_start: str | None
    current_period_end: str | None
    cancel_at_period_end: bool
    canceled_at: str | None


class FeatureUsage(ApiModel):
    feature_key: str
    unit: str | None
    #: The plan's hard cap for the period; -1 means unlimited.
    usage_limit: int | float
    used: int | float
    #: Units left before the cap; None when unlimited.
    remaining: int | float | None


class UsageView(ApiModel):
    period_start: str
    features: list[FeatureUsage]


class InvoiceView(ApiModel):
    id: str
    status: str
    billing_reason: str | None
    currency: str
    amount_due: int
    amount_paid: int
    amount_remaining: int
    period_start: str | None
    period_end: str | None
    created_at: str
    hosted_invoice_url: str | None
    invoice_pdf: str | None


class InvoicePage(ApiModel):
    items: list[InvoiceView]
    next_cursor: str | None


class _SubscriptionResponse(ApiModel):
    subscription: SubscriptionView | None


def _user_path(user_id: str) -> str:
    return f"/api/app/billing/users/{quote(user_id, safe='')}"


class BillingApi:
    """What a user holds and has consumed in this application.

    The application is the one behind the machine token: it cannot read another one.
    """

    def __init__(self, http: JsonHttp) -> None:
        self._http = http

    async def get_subscription(self, user_id: str) -> SubscriptionView | None:
        """None when the user holds no subscription."""
        response = await self._http.request(
            "GET",
            f"{_user_path(user_id)}/subscription",
            scope=SCOPE,
            schema=_SubscriptionResponse,
        )
        return response.subscription

    async def get_usage(self, user_id: str) -> UsageView:
        return await self._http.request(
            "GET", f"{_user_path(user_id)}/usage", scope=SCOPE, schema=UsageView
        )

    async def list_invoices(
        self, user_id: str, *, limit: int | None = None, cursor: str | None = None
    ) -> InvoicePage:
        """Newest first, keyset-paginated: pass `next_cursor` back until it is None.

        `limit` is 1 to 100.
        """
        return await self._http.request(
            "GET",
            f"{_user_path(user_id)}/invoices",
            scope=SCOPE,
            query={"limit": limit, "cursor": cursor},
            schema=InvoicePage,
        )
