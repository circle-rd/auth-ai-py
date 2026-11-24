from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Annotated, Final, Literal, Self
from urllib.parse import quote

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    StringConstraints,
    ValidationError,
    model_validator,
)

from ..errors import ERR, AuthAiError
from ..http import ApiModel, to_wire_datetime
from ..resource_types import (
    AccessibleResource,
    AccessKind,
    OwnerType,
    ResourcePermission,
    ResourceStatus,
)

if TYPE_CHECKING:
    from ..http import JsonHttp

AUTHORIZE_SCOPE: Final = "resources:authorize"
VALIDATE_SCOPE: Final = "resources:validate"
USAGE_SCOPE: Final = "resources:usage:write"
_GATEWAY_PATH: Final = "/api/internal/gateway"
_RESOURCES_PATH: Final = f"{_GATEWAY_PATH}/resources"
_USAGE_FUTURE_TOLERANCE: Final = timedelta(minutes=5)
_USAGE_PAST_WINDOW: Final = timedelta(days=30)
_UUID_PATTERN: Final = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

type ResourceId = Annotated[str, Field(pattern=_UUID_PATTERN)]

type EventSource = Literal["gateway", "ssh", "external", "api"]
type ValidationResult = Literal["validated", "validation_failed"]
type UsageSource = Literal["provider", "unsupported"]


class _AuthorizeInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_id: Annotated[str, Field(min_length=1, max_length=256)]
    actor_client_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    resource_uri: Annotated[str, Field(min_length=3, max_length=512)]
    audience: Annotated[str, Field(min_length=1, max_length=2048)]
    permission: ResourcePermission | None = None
    request_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    source: EventSource | None = None


class _AccessibleInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_id: Annotated[str, Field(min_length=1, max_length=256)]
    scheme: Annotated[str, Field(pattern=r"^[a-z][a-z0-9]{0,49}$")] | None = None


class _ValidationInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    resource_id: ResourceId
    result: ValidationResult
    reason: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] | None = None
    evidence: dict[str, object] | None = None


class _InvalidationInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    resource_id: ResourceId
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]


class _UsageInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: Annotated[str, Field(min_length=1, max_length=2048)]
    started_at: AwareDatetime
    resource_id: ResourceId
    resource_uri: Annotated[str, Field(min_length=3, max_length=512)]
    request_id: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    occurred_at: AwareDatetime
    usage_source: UsageSource
    cost_usd: Annotated[str, Field(pattern=r"^(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$")] | None = None
    prompt_tokens: Annotated[int, Field(ge=0)] | None = None
    completion_tokens: Annotated[int, Field(ge=0)] | None = None
    total_tokens: Annotated[int, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def _check_accounting(self) -> Self:
        now = datetime.now(UTC)
        if not now - _USAGE_PAST_WINDOW <= self.occurred_at <= now + _USAGE_FUTURE_TOLERANCE:
            raise ValueError("occurred_at is outside the accepted accounting window")
        tokens = (self.prompt_tokens, self.completion_tokens, self.total_tokens)
        if self.usage_source == "unsupported":
            if self.cost_usd is not None or any(t is not None for t in tokens):
                raise ValueError("unsupported usage must not carry cost or tokens")
        elif self.cost_usd is None:
            raise ValueError("provider usage requires a reported cost")
        return self


class Denied(ApiModel):
    """The user may not use the resource. The answer carries no reason, on purpose."""

    decision: Literal["deny"]


class Allowed(ApiModel):
    """The user may use the resource."""

    decision: Literal["allow"]
    #: Hand it to `record_usage`: it names the person and the application.
    decision_id: str
    expires_at: datetime
    resource_id: str
    resource_uri: str
    application_slug: str
    owner_type: OwnerType
    #: Present only when the calling application owns the resource.
    owner_id: str | None = None
    access_kind: AccessKind
    #: The level the user holds: `read`, or `write` which also covers `read`.
    permission: ResourcePermission


# Only `Allowed` carries data; a decision this SDK does not know fails validation,
# so an unexpected answer can never read as an admission.
type AuthorizeDecision = Allowed | Denied


class _DecisionResponse(RootModel[Annotated[Allowed | Denied, Field(discriminator="decision")]]):
    model_config = ConfigDict(frozen=True)


class _AccessibleList(ApiModel):
    resources: list[AccessibleResource]


class ResourceState(ApiModel):
    id: str
    uri: str
    status: ResourceStatus
    validation_error: str | None


class _ResourceResponse(ApiModel):
    resource: ResourceState


class RecordedUsage(ApiModel):
    id: str
    resource_id: str
    request_id: str
    occurred_at: str


class UsageReceipt(ApiModel):
    usage: RecordedUsage
    #: `True` when the event had already been recorded.
    replayed: bool


def _invalid(what: str, err: ValidationError) -> AuthAiError:
    issues = "; ".join(
        f"{'.'.join(str(p) for p in issue['loc'])}: {issue['msg']}"
        for issue in err.errors(include_input=False, include_url=False)
    )
    return ERR.CFG_001(f"Invalid {what}: {issues}", cause=err)


class ResourcesApi:
    """Resource sharing from the side of an adapter service or of a scheme owner.

    The decision point stays auth-service: these calls ask it, they never decide.

    `resources:authorize` is granted to an application's machine credential. Every
    decision is taken for that application: it sees the resources it owns and the
    ones shared with it, never everything a user owns. `resources:validate` is
    granted to new confidential applications and acts only for the resource schemes
    bound to the calling client.
    """

    def __init__(self, http: JsonHttp) -> None:
        self._http = http

    async def authorize(
        self,
        *,
        subject_id: str,
        resource_uri: str,
        audience: str,
        actor_client_id: str | None = None,
        permission: ResourcePermission | None = None,
        request_id: str | None = None,
        source: EventSource | None = None,
    ) -> AuthorizeDecision:
        """Asks whether a user may use a resource through the calling application.

        Needs `resources:authorize`. Take `subject_id` and `audience` from a token you
        verified, never from the request body; the calling application is the machine
        credential itself. Anything other than an `Allowed` answer is a refusal, and
        so is a raised error: fail closed. A denial carries no reason, so it cannot be
        used to probe. `permission` is the level the request needs (`read` by default,
        `write` covers `read`); `Allowed.permission` is the level the user holds.
        `actor_client_id` is the client the end user came through (the verified `azp`),
        recorded in the access log only. `request_id` correlates the access event with
        your own request id; `source` is recorded too (`gateway` by default).
        """
        try:
            body = _AuthorizeInput(
                subject_id=subject_id,
                actor_client_id=actor_client_id,
                resource_uri=resource_uri,
                audience=audience,
                permission=permission,
                request_id=request_id,
                source=source,
            )
        except ValidationError as err:
            raise _invalid("authorize request", err) from err
        response = await self._http.request(
            "POST",
            f"{_GATEWAY_PATH}/authorize",
            scope=AUTHORIZE_SCOPE,
            body={
                "subjectId": body.subject_id,
                "resourceUri": body.resource_uri,
                "audience": body.audience,
                **({} if body.actor_client_id is None else {"actorClientId": body.actor_client_id}),
                **({} if body.permission is None else {"permission": body.permission}),
                **({} if body.request_id is None else {"requestId": body.request_id}),
                **({} if body.source is None else {"source": body.source}),
            },
            schema=_DecisionResponse,
        )
        return response.root

    async def list_accessible(
        self, subject_id: str, *, scheme: str | None = None
    ) -> list[AccessibleResource]:
        """Every validated resource a user may use through the calling application.

        Each one carries the `permission` the user holds. Use it to filter a listing,
        never as the admission of a request: call `authorize` for that. `scheme`
        narrows the list, e.g. `llm`. Needs `resources:authorize`.
        """
        try:
            query = _AccessibleInput(subject_id=subject_id, scheme=scheme)
        except ValidationError as err:
            raise _invalid("accessible query", err) from err
        response = await self._http.request(
            "GET",
            f"{_RESOURCES_PATH}/accessible",
            scope=AUTHORIZE_SCOPE,
            query={"subjectId": query.subject_id, "scheme": query.scheme},
            schema=_AccessibleList,
        )
        return response.resources

    async def validate(
        self,
        resource_id: str,
        *,
        result: ValidationResult,
        reason: str | None = None,
        evidence: dict[str, object] | None = None,
    ) -> ResourceState:
        """Reports the outcome of the ownership check the validator ran on a resource.

        Only the client bound to the resource's scheme may call it; auth-service
        refuses any other with `AUTH_011`. `reason` (500 characters at most) is shown
        to the owner when validation failed. `evidence` is the proof the validator
        gathered: never put a secret in it. Needs `resources:validate`.
        """
        try:
            outcome = _ValidationInput(
                resource_id=resource_id, result=result, reason=reason, evidence=evidence
            )
        except ValidationError as err:
            raise _invalid("validation outcome", err) from err
        body: dict[str, object] = {"result": outcome.result}
        if outcome.reason is not None:
            body["reason"] = outcome.reason
        if outcome.evidence is not None:
            body["evidence"] = outcome.evidence
        response = await self._http.request(
            "POST",
            f"{_RESOURCES_PATH}/{quote(outcome.resource_id, safe='')}/validate",
            scope=VALIDATE_SCOPE,
            body=body,
            schema=_ResourceResponse,
        )
        return response.resource

    async def invalidate(self, resource_id: str, reason: str) -> ResourceState:
        """Disables a resource whose ownership was lost (a host key changed, the object deleted).

        New access is refused at once. The reason is kept in the audit trail. Only the
        client bound to the scheme may call it. Needs `resources:validate`.
        """
        try:
            outcome = _InvalidationInput(resource_id=resource_id, reason=reason)
        except ValidationError as err:
            raise _invalid("invalidation reason", err) from err
        response = await self._http.request(
            "POST",
            f"{_RESOURCES_PATH}/{quote(outcome.resource_id, safe='')}/invalidate",
            scope=VALIDATE_SCOPE,
            body={"reason": outcome.reason},
            schema=_ResourceResponse,
        )
        return response.resource

    async def record_usage(
        self,
        *,
        decision_id: str,
        started_at: datetime,
        resource_id: str,
        resource_uri: str,
        request_id: str,
        occurred_at: datetime,
        usage_source: UsageSource,
        cost_usd: str | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
        total_tokens: int | None = None,
    ) -> UsageReceipt:
        """Records the usage a provider billed for a shared resource. Needs `resources:usage:write`.

        auth-service owns accounting; this is the only write, and the scope is granted
        to the platform's metering components, never by default. `decision_id` is the
        one `authorize` returned when it admitted the request: it names the person and
        the application, so a usage event cannot claim another one. It lives 60 seconds
        and only the client that obtained it may present it; `started_at` (timezone-aware)
        is when the admitted request started and must fall within that lifetime
        (`RES_016` otherwise). `request_id` is the event's trusted identifier (64
        lowercase hex characters): replaying an event is safe and answers
        `replayed=True`. `occurred_at` is timezone-aware, at most five minutes ahead and
        30 days back. `cost_usd` is a plain decimal string, required for `provider`
        usage; `unsupported` carries no cost and no tokens. A payload that conflicts
        with the stored event is refused (`RES_012`), and so is a caller with no access
        to the resource (`RES_011`).
        """
        try:
            usage = _UsageInput(
                decision_id=decision_id,
                started_at=started_at,
                resource_id=resource_id,
                resource_uri=resource_uri,
                request_id=request_id,
                occurred_at=occurred_at,
                usage_source=usage_source,
                cost_usd=cost_usd,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
            )
        except ValidationError as err:
            raise _invalid("usage record", err) from err
        return await self._http.request(
            "POST",
            f"{_GATEWAY_PATH}/usage",
            scope=USAGE_SCOPE,
            body={
                "decisionId": usage.decision_id,
                "startedAt": to_wire_datetime(usage.started_at),
                "resourceId": usage.resource_id,
                "resourceUri": usage.resource_uri,
                "requestId": usage.request_id,
                "occurredAt": to_wire_datetime(usage.occurred_at),
                "usageSource": usage.usage_source,
                "costUsd": usage.cost_usd,
                "promptTokens": usage.prompt_tokens,
                "completionTokens": usage.completion_tokens,
                "totalTokens": usage.total_tokens,
            },
            schema=UsageReceipt,
        )
