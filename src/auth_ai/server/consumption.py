from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Final
from urllib.parse import quote

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    StringConstraints,
    ValidationError,
)

from ..errors import ERR
from ..http import ApiModel

if TYPE_CHECKING:
    from ..http import JsonHttp

WRITE_SCOPE: Final = "consumption:write"
READ_SCOPE: Final = "consumption:read"


class _Report(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: Annotated[str, Field(min_length=1)]
    # Alphanumeric and dots, 64 characters at most.
    key: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9.]+$")]
    # May be negative to credit back.
    value: StrictInt | Annotated[StrictFloat, Field(allow_inf_nan=False)]
    idempotency_key: (
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
        | None
    ) = None


class ConsumptionTotal(ApiModel):
    key: str
    #: A decimal string: the running total is not bounded by a double.
    total: str


class ConsumptionAggregate(ConsumptionTotal):
    updated_at: str


class _ReportResponse(ApiModel):
    success: bool
    metered: bool = False
    aggregate: ConsumptionTotal


class _AggregateList(ApiModel):
    aggregates: list[ConsumptionAggregate]


class _AggregateOne(ApiModel):
    aggregate: ConsumptionAggregate


@dataclass(frozen=True, slots=True)
class ConsumptionResult:
    aggregate: ConsumptionTotal
    #: True when the key prices a metered feature and was billed through Stripe.
    metered: bool


def _user_path(user_id: str) -> str:
    return f"/api/app/consumption/users/{quote(user_id, safe='')}"


class ConsumptionApi:
    """Usage the application reports for its users, for features billed on consumption.

    The application is the one behind the machine token.
    """

    def __init__(self, http: JsonHttp) -> None:
        self._http = http

    async def report(
        self,
        user_id: str,
        key: str,
        value: float,
        *,
        idempotency_key: str | None = None,
    ) -> ConsumptionResult:
        """Reports `value` units of `key` for a user.

        The same `idempotency_key` reported twice counts once: set it to make
        retries safe.
        """
        try:
            report = _Report(user_id=user_id, key=key, value=value, idempotency_key=idempotency_key)
        except ValidationError as err:
            issues = "; ".join(
                f"{'.'.join(str(p) for p in issue['loc'])}: {issue['msg']}"
                for issue in err.errors(include_input=False, include_url=False)
            )
            raise ERR.CFG_001(f"Invalid consumption report: {issues}", cause=err) from err
        body: dict[str, str | int | float] = {"key": report.key, "value": report.value}
        if report.idempotency_key is not None:
            body["idempotencyKey"] = report.idempotency_key
        response = await self._http.request(
            "POST",
            _user_path(report.user_id),
            scope=WRITE_SCOPE,
            body=body,
            schema=_ReportResponse,
        )
        if not response.success:
            raise ERR.API_002()
        return ConsumptionResult(aggregate=response.aggregate, metered=response.metered)

    async def list_aggregates(self, user_id: str) -> list[ConsumptionAggregate]:
        """Every running total of a user."""
        response = await self._http.request(
            "GET", _user_path(user_id), scope=READ_SCOPE, schema=_AggregateList
        )
        return response.aggregates

    async def get_aggregate(self, user_id: str, key: str) -> ConsumptionAggregate:
        """One running total; rejects (API_001, CONS_003) when the key was never reported."""
        response = await self._http.request(
            "GET",
            f"{_user_path(user_id)}/{quote(key, safe='')}",
            scope=READ_SCOPE,
            schema=_AggregateOne,
        )
        return response.aggregate
