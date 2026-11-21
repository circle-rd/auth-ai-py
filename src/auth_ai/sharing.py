from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any, Final, Literal, Self
from urllib.parse import quote

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from .errors import ERR, AuthAiError
from .http import ApiModel

if TYPE_CHECKING:
    from .http import JsonHttp

RESOURCE_SCOPE_KEY: Final = "resources"
_USER_PATH: Final = "/api/user"
_RESOURCES_PATH: Final = f"{_USER_PATH}/resources"
_UUID_PATTERN: Final = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SCHEME_PATTERN: Final = r"^[a-z][a-z0-9]{0,49}$"

type ResourceId = Annotated[str, Field(pattern=_UUID_PATTERN)]
type Scheme = Annotated[str, Field(pattern=_SCHEME_PATTERN)]
type OwnerType = Literal["user", "application"]
type AccessKind = Literal["owner", "grant"]
type GrantSubjectType = Literal["user", "organization", "plan", "everyone"]
type ResourceStatus = Literal["pending_validation", "validation_failed", "validated", "disabled"]


class Resource(ApiModel):
    id: str
    application_id: str
    application_slug: str | None = None
    application_name: str | None = None
    scheme: str
    scheme_display_name: str | None = None
    locator: str | None = None
    uri: str
    display_name: str
    owner_type: OwnerType
    owner_id: str
    status: ResourceStatus
    listed: bool
    metadata: dict[str, Any] | None = None
    validation_requested_at: datetime | None = None
    validated_at: datetime | None = None
    validation_error: str | None = None
    created_at: datetime
    updated_at: datetime


class Grant(ApiModel):
    id: str
    resource_id: str
    subject_type: GrantSubjectType
    subject_id: str | None
    permission: str
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    created_by: str
    created_at: datetime


class Organization(ApiModel):
    id: str
    name: str
    slug: str | None = None
    logo: str | None = None
    role: str
    created_at: datetime


class MemberApplication(ApiModel):
    id: str
    name: str
    slug: str
    description: str | None = None
    icon: str | None = None
    can_create: bool


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
    grant_subject_type: GrantSubjectType | None = None


class CatalogueApplication(ApiModel):
    slug: str
    name: str


class Catalogue(ApiModel):
    applications: list[CatalogueApplication]
    resources: list[AccessibleResource]
    enabled_schemes: list[str]


class ValidationRequest(ApiModel):
    resource: Resource
    validator_url: str | None
    validation_command: str | None


class DeletedResource(ApiModel):
    resource: Resource
    removed: bool


class _ResourceResponse(ApiModel):
    resource: Resource


class _ResourceList(ApiModel):
    resources: list[Resource]


class _GrantList(ApiModel):
    grants: list[Grant]


class _GrantResponse(ApiModel):
    grant: Grant


class _OrganizationList(ApiModel):
    organizations: list[Organization]


class _ApplicationList(ApiModel):
    applications: list[MemberApplication]


class _AccessibleList(ApiModel):
    resources: list[AccessibleResource]


class Audience(BaseModel):
    """Who a resource is shared with at creation time.

    A user may be named by id or by e-mail. auth-service resolves the e-mail
    among the application's active members and gives the same answer for an
    unknown address and a non-member.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: Literal["user", "organization", "plan", "everyone"]
    user_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    email: Annotated[str, StringConstraints(strip_whitespace=True, max_length=320)] | None = None
    organization_id: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    plan_id: Annotated[str, Field(pattern=_UUID_PATTERN)] | None = None

    @classmethod
    def user(cls, *, id: str | None = None, email: str | None = None) -> Audience:  # noqa: A002
        return cls(type="user", user_id=id, email=email)

    @classmethod
    def organization(cls, organization_id: str) -> Audience:
        return cls(type="organization", organization_id=organization_id)

    @classmethod
    def plan(cls, plan_id: str) -> Audience:
        return cls(type="plan", plan_id=plan_id)

    @classmethod
    def everyone(cls) -> Audience:
        return cls(type="everyone")

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        provided = [
            value
            for value in (self.user_id, self.email, self.organization_id, self.plan_id)
            if value is not None
        ]
        if self.type == "everyone":
            if provided:
                raise ValueError("everyone takes no target")
            return self
        if self.type == "user":
            if len(provided) != 1 or self.organization_id or self.plan_id:
                raise ValueError("a user audience takes exactly one of user_id or email")
            if self.email == "":
                raise ValueError("email must not be empty")
            return self
        if self.type == "organization":
            if self.organization_id is None or len(provided) != 1:
                raise ValueError("an organization audience takes organization_id")
            return self
        if self.plan_id is None or len(provided) != 1:
            raise ValueError("a plan audience takes plan_id")
        return self

    def to_wire(self) -> dict[str, str]:
        if self.type == "user":
            return (
                {"type": "user", "userId": self.user_id}
                if self.user_id is not None
                else {"type": "user", "email": self.email or ""}
            )
        if self.type == "organization":
            return {"type": "organization", "organizationId": self.organization_id or ""}
        if self.type == "plan":
            return {"type": "plan", "planId": self.plan_id or ""}
        return {"type": "everyone"}


class _CreateInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    application_id: ResourceId
    scheme: Scheme
    locator: (
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
        | None
    ) = None
    display_name: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)
    ]
    metadata: dict[str, Any] | None = None
    audience: Audience | None = None


class _UpdateInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    display_name: (
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
        | None
    ) = None
    listed: bool | None = None
    metadata: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> Self:
        if self.display_name is None and self.listed is None and self.metadata is None:
            raise ValueError("at least one field is required")
        return self


class _GrantInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_type: GrantSubjectType
    subject_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    subject_email: (
        Annotated[str, StringConstraints(strip_whitespace=True, max_length=320)] | None
    ) = None
    expires_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _check_subject(self) -> Self:
        if self.subject_type == "everyone":
            if self.subject_id is not None or self.subject_email is not None:
                raise ValueError("everyone takes no subject")
            return self
        if self.subject_type == "user" and self.subject_email is not None:
            if self.subject_id is not None:
                raise ValueError("give either subject_id or subject_email")
            if self.subject_email == "":
                raise ValueError("subject_email must not be empty")
            return self
        if self.subject_email is not None:
            raise ValueError("only a user grant accepts subject_email")
        if not self.subject_id:
            raise ValueError("subject_id is required")
        return self


def _invalid(what: str, err: ValidationError) -> AuthAiError:
    issues = "; ".join(
        f"{'.'.join(str(p) for p in issue['loc'])}: {issue['msg']}"
        for issue in err.errors(include_input=False, include_url=False)
    )
    return ERR.CFG_001(f"Invalid {what}: {issues}", cause=err)


class ResourceSharingClient:
    """The signed-in user's own resources and shares.

    Every call uses the user's access token for the auth-service audience with
    the `resources:self:manage` scope, which `resource_sharing=True` adds at
    sign-in. The token belongs to the user: an application can act only on what
    that user owns or administers.
    """

    def __init__(self, http: JsonHttp) -> None:
        self._http = http

    async def list_member_applications(self) -> list[MemberApplication]:
        response = await self._http.request(
            "GET",
            f"{_USER_PATH}/resource-applications",
            scope=RESOURCE_SCOPE_KEY,
            schema=_ApplicationList,
        )
        return response.applications

    async def list_organizations(self) -> list[Organization]:
        """The organizations the user belongs to, for an organization audience."""
        response = await self._http.request(
            "GET",
            f"{_USER_PATH}/organizations",
            scope=RESOURCE_SCOPE_KEY,
            schema=_OrganizationList,
        )
        return response.organizations

    async def list_owned(self) -> list[Resource]:
        response = await self._http.request(
            "GET",
            _RESOURCES_PATH,
            scope=RESOURCE_SCOPE_KEY,
            schema=_ResourceList,
        )
        return response.resources

    async def get(self, resource_id: str) -> Resource:
        await self._validate_id(resource_id, "resource id")
        response = await self._http.request(
            "GET",
            f"{_RESOURCES_PATH}/{quote(resource_id, safe='')}",
            scope=RESOURCE_SCOPE_KEY,
            schema=_ResourceResponse,
        )
        return response.resource

    async def create(
        self,
        *,
        application_id: str,
        scheme: str,
        display_name: str,
        locator: str | None = None,
        metadata: dict[str, Any] | None = None,
        audience: Audience | None = None,
    ) -> Resource:
        """Declares a resource owned by the user.

        The resource starts in `pending_validation`; the application that owns the
        scheme must call `machine.resources.validate`. `audience` shares it in the
        same call, so a refused audience never leaves a half-declared resource.
        """
        try:
            data = _CreateInput(
                application_id=application_id,
                scheme=scheme,
                locator=locator,
                display_name=display_name,
                metadata=metadata,
                audience=audience,
            )
        except ValidationError as err:
            raise _invalid("resource", err) from err
        body: dict[str, Any] = {
            "applicationId": data.application_id,
            "scheme": data.scheme,
            "displayName": data.display_name,
        }
        if data.locator is not None:
            body["locator"] = data.locator
        if data.metadata is not None:
            body["metadata"] = data.metadata
        if data.audience is not None:
            body["audience"] = data.audience.to_wire()
        response = await self._http.request(
            "POST", _RESOURCES_PATH, scope=RESOURCE_SCOPE_KEY, body=body, schema=_ResourceResponse
        )
        return response.resource

    async def update(
        self,
        resource_id: str,
        *,
        display_name: str | None = None,
        listed: bool | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Resource:
        await self._validate_id(resource_id, "resource id")
        try:
            data = _UpdateInput(display_name=display_name, listed=listed, metadata=metadata)
        except ValidationError as err:
            raise _invalid("resource update", err) from err
        body: dict[str, Any] = {}
        if data.display_name is not None:
            body["displayName"] = data.display_name
        if data.listed is not None:
            body["listed"] = data.listed
        if data.metadata is not None:
            body["metadata"] = data.metadata
        response = await self._http.request(
            "PATCH",
            f"{_RESOURCES_PATH}/{quote(resource_id, safe='')}",
            scope=RESOURCE_SCOPE_KEY,
            body=body,
            schema=_ResourceResponse,
        )
        return response.resource

    async def delete(self, resource_id: str) -> DeletedResource:
        await self._validate_id(resource_id, "resource id")
        return await self._http.request(
            "DELETE",
            f"{_RESOURCES_PATH}/{quote(resource_id, safe='')}",
            scope=RESOURCE_SCOPE_KEY,
            schema=DeletedResource,
        )

    async def request_validation(self, resource_id: str) -> ValidationRequest:
        await self._validate_id(resource_id, "resource id")
        return await self._http.request(
            "POST",
            f"{_RESOURCES_PATH}/{quote(resource_id, safe='')}/validation-request",
            scope=RESOURCE_SCOPE_KEY,
            schema=ValidationRequest,
        )

    async def list_grants(self, resource_id: str) -> list[Grant]:
        await self._validate_id(resource_id, "resource id")
        response = await self._http.request(
            "GET",
            f"{_RESOURCES_PATH}/{quote(resource_id, safe='')}/grants",
            scope=RESOURCE_SCOPE_KEY,
            schema=_GrantList,
        )
        return response.grants

    async def create_grant(
        self,
        resource_id: str,
        *,
        subject_type: GrantSubjectType,
        subject_id: str | None = None,
        subject_email: str | None = None,
        expires_at: datetime | None = None,
    ) -> Grant:
        """Shares an existing resource.

        A `user` subject is named by id or by e-mail, never both. `expires_at`
        must be timezone-aware and in the future.
        """
        await self._validate_id(resource_id, "resource id")
        try:
            data = _GrantInput(
                subject_type=subject_type,
                subject_id=subject_id,
                subject_email=subject_email,
                expires_at=expires_at,
            )
        except ValidationError as err:
            raise _invalid("grant", err) from err
        if data.expires_at is not None and data.expires_at <= datetime.now(UTC):
            raise ERR.CFG_001("Invalid grant: expires_at must be in the future")
        body: dict[str, Any] = {"subjectType": data.subject_type}
        if data.subject_id is not None:
            body["subjectId"] = data.subject_id
        if data.subject_email is not None:
            body["subjectEmail"] = data.subject_email
        if data.expires_at is not None:
            body["expiresAt"] = data.expires_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        response = await self._http.request(
            "POST",
            f"{_RESOURCES_PATH}/{quote(resource_id, safe='')}/grants",
            scope=RESOURCE_SCOPE_KEY,
            body=body,
            schema=_GrantResponse,
        )
        return response.grant

    async def revoke_grant(self, resource_id: str, grant_id: str) -> Grant:
        await self._validate_id(resource_id, "resource id")
        await self._validate_id(grant_id, "grant id")
        response = await self._http.request(
            "DELETE",
            f"{_RESOURCES_PATH}/{quote(resource_id, safe='')}/grants/{quote(grant_id, safe='')}",
            scope=RESOURCE_SCOPE_KEY,
            schema=_GrantResponse,
        )
        return response.grant

    async def list_accessible(
        self, *, scheme: str | None = None, application_id: str | None = None
    ) -> list[AccessibleResource]:
        """Every validated resource the user may use; a listing filter, not an admission."""
        if scheme is not None and not re.fullmatch(_SCHEME_PATTERN, scheme):
            raise ERR.CFG_001("Invalid accessible query: scheme has an invalid shape")
        if application_id is not None and not re.fullmatch(_UUID_PATTERN, application_id):
            raise ERR.CFG_001("Invalid accessible query: application_id is not a UUID")
        response = await self._http.request(
            "GET",
            f"{_USER_PATH}/accessible-resources",
            scope=RESOURCE_SCOPE_KEY,
            query={"scheme": scheme, "applicationId": application_id},
            schema=_AccessibleList,
        )
        return response.resources

    async def get_catalogue(self) -> Catalogue:
        return await self._http.request(
            "GET",
            f"{_USER_PATH}/resource-catalogue",
            scope=RESOURCE_SCOPE_KEY,
            schema=Catalogue,
        )

    @staticmethod
    async def _validate_id(value: str, what: str) -> None:
        if not re.fullmatch(_UUID_PATTERN, value):
            raise ERR.CFG_001(f"Invalid {what}: must be a UUID")
