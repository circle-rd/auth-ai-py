from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..errors import ERR
from ..messages import WebRequest, WebResponse, json_response

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ..ai import AiClient
    from .sessions import Session

type RouteHandler = Callable[[WebRequest], Awaitable[WebResponse]]


class _StatsQuery(BaseModel):
    model_config = ConfigDict(extra="ignore")

    days: int | None = Field(default=None, ge=1, le=90)


def create_ai_routes(
    ai: AiClient,
    require_session: Callable[[WebRequest], Awaitable[Session]],
) -> dict[str, RouteHandler]:
    """Wallet and model reads for the application's own frontend, which holds no token.

    The backend calls auth-service and the gateway on the user's behalf.
    """

    async def wallet(request: WebRequest) -> WebResponse:
        session = await require_session(request)
        user = ai.for_user(session.user_id)
        account = await user.wallet.get_account()
        return json_response({**account.to_json(), "topupUrl": user.wallet.topup_url()})

    async def wallet_stats(request: WebRequest) -> WebResponse:
        session = await require_session(request)
        query = {name: values[0] for name, values in parse_qs(urlsplit(request.url).query).items()}
        try:
            parsed = _StatsQuery.model_validate(query)
        except ValidationError as err:
            raise ERR.REQ_001(cause=err) from err
        stats = await ai.for_user(session.user_id).wallet.get_stats(days=parsed.days)
        return json_response(stats.to_json())

    async def models(request: WebRequest) -> WebResponse:
        session = await require_session(request)
        listed = await ai.for_user(session.user_id).gateway.list_models()
        return json_response({"models": [m.model_dump(mode="json") for m in listed]})

    return {"/wallet": wallet, "/wallet/stats": wallet_stats, "/models": models}
