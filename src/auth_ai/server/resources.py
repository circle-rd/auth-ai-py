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
from ..http import ApiModel

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

type OwnerType = Literal["user", "application"]
type AccessKind = Literal["owner", "grant"]
type GrantSubjectType = Literal["user", "organization", "plan", "everyone"]
type ResourceStatus = Literal["pending_validation", "validation_failed", "validated", "disabled"]
type EventSource = Literal["gateway", "ssh", "external", "api"]
type ValidationResult = Literal["validated", "validation_failed"]
type UsageSource = Literal["provider", "unsupported"]


class _AuthorizeInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_id: Annotated[str, Field(min_length=1, max_length=256)]
    client_id: Annotated[str, Field(min_length=1, max_length=256)]
    resource_uri: Annotated[str, Field(min_length=3, max_length=512)]
    audience: Annotated[str, Field(min_length=1, max_length=2048)]
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

    subject_id: Annotated[str, Field(min_length=1, max_length=256)]
    client_id: Annotated[str, Field(min_length=1, max_length=256)]
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
    resource_id: str
    resource_uri: str
    application_slug: str
    owner_type: OwnerType
    owner_id: str
    access_kind: AccessKind


# Only `Allowed` carries data; a decision this SDK does not know fails validation,
# so an unexpected answer can never read as an admission.
type AuthorizeDecision = Allowed | Denied


class _DecisionResponse(RootModel[Annotated[Allowed | Denied, Field(discriminator="decision")]]):
    model_config = ConfigDict(frozen=True)


class AccessibleResource(ApiModel):
    resource_id: str
    resource_uri: str
    scheme: str
    display_name: str
    application_id: str
    application_slug: str
    application_name: str
    owner_type: OwnerType
    owner_id: str
    access_kind: AccessKind
    #: Set when `access_kind` is `grant`.
    grant_subject_type: GrantSubjectType | None = None


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

    `resources:authorize` reaches every user and every resource of the instance, so a
    superadmin grants it only to a trusted enforcement point. `resources:validate` is
    granted to new confidential applications and acts only for the resource schemes
    bound to the calling client.
    """

    def __init__(self, http: JsonHttp) -> None:
        self._http = http

    async def authorize(
        self,
        *,
        subject_id: str,
        client_id: str,
        resource_uri: str,
        audience: str,
        request_id: str | None = None,
        source: EventSource | None = None,
    ) -> AuthorizeDecision:
        """Asks whether a user may use a resource. Needs `resources:authorize`.

        Take `subject_id`, `client_id` and `audience` from a token you verified, never
        from the request body. Anything other than an `Allowed` answer is a refusal,
        and so is a raised error: fail closed. A denial carries no reason, so it
        cannot be used to probe. `request_id` correlates the access event with your
        own request id; `source` is recorded in the access log (`gateway` by default).
        """
        try:
            body = _AuthorizeInput(
                subject_id=subject_id,
                client_id=client_id,
                resource_uri=resource_uri,
                audience=audience,
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
                "clientId": body.client_id,
                "resourceUri": body.resource_uri,
                "audience": body.audience,
                **({} if body.request_id is None else {"requestId": body.request_id}),
                **({} if body.source is None else {"source": body.source}),
            },
            schema=_DecisionResponse,
        )
        return response.root

    async def list_accessible(
        self, subject_id: str, *, scheme: str | None = None
    ) -> list[AccessibleResource]:
        """Every validated resource a user may use, across applications.

        Use it to filter a listing, never as the admission of a request: call
        `authorize` for that. `scheme` narrows the list, e.g. `llm`. Needs
        `resources:authorize`.
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
        subject_id: str,
        client_id: str,
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
        to the platform's metering components, never by default. `request_id` is the
        event's trusted identifier (64 lowercase hex characters): replaying an event is
        safe and answers `replayed=True`. `occurred_at` is timezone-aware, at most five
        minutes ahead and 30 days back. `cost_usd` is a plain decimal string, required
        for `provider` usage; `unsupported` carries no cost and no tokens. A payload
        that conflicts with the stored event is refused (`RES_012`), and so is a caller
        with no access to the resource (`RES_011`).
        """
        try:
            usage = _UsageInput(
                subject_id=subject_id,
                client_id=client_id,
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
                "subjectId": usage.subject_id,
                "clientId": usage.client_id,
                "resourceId": usage.resource_id,
                "resourceUri": usage.resource_uri,
                "requestId": usage.request_id,
                "occurredAt": usage.occurred_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                "usageSource": usage.usage_source,
                "costUsd": usage.cost_usd,
                "promptTokens": usage.prompt_tokens,
                "completionTokens": usage.completion_tokens,
                "totalTokens": usage.total_tokens,
            },
            schema=UsageReceipt,
        )
