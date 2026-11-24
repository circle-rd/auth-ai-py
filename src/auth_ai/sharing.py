from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import quote

from pydantic import ValidationError

from .errors import ERR, AuthAiError
from .http import ApiModel, to_wire_datetime
from .resource_types import (
    AccessibleResource,
    GrantSubjectType,
    OwnerType,
    ResourcePermission,
    ResourceStatus,
)
from .sharing_inputs import (
    SCHEME_PATTERN,
    UUID_PATTERN,
    Audience,
    BulkShareInput,
    CreateInput,
    GrantInput,
    GrantUpdateInput,
    UpdateInput,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .http import JsonHttp

RESOURCE_SCOPE_KEY: Final = "resources"
_USER_PATH: Final = "/api/user"
_RESOURCES_PATH: Final = f"{_USER_PATH}/resources"


class Resource(ApiModel):
    id: str
    application_id: str
    application_slug: str | None = None
    application_name: str | None = None
    scheme: str
    scheme_display_name: str | None = None
    #: The levels the scheme supports; present on single-resource answers.
    permissions: list[ResourcePermission] | None = None
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
    permission: ResourcePermission
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


class BulkShareResult(ApiModel):
    """The outcome of one resource of a bulk share: a grant id, or the refusal code."""

    resource_id: str
    grant_id: str | None
    code: str | None


class _ResourceResponse(ApiModel):
    resource: Resource


class _ResourceList(ApiModel):
    resources: list[Resource]


class _GrantList(ApiModel):
    grants: list[Grant]


class _GrantResponse(ApiModel):
    grant: Grant


class _BulkShareResponse(ApiModel):
    results: list[BulkShareResult]


class _OrganizationList(ApiModel):
    organizations: list[Organization]


class _ApplicationList(ApiModel):
    applications: list[MemberApplication]


class _AccessibleList(ApiModel):
    resources: list[AccessibleResource]


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
    that user owns or administers, and a bearer token sees the resources of its
    own application only.
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

    async def get_resource(self, resource_id: str) -> Resource:
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
            data = CreateInput(
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
            data = UpdateInput(display_name=display_name, listed=listed, metadata=metadata)
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

    async def delete(self, resource_id: str) -> Resource:
        """Deletes a resource for good, with its grants and invitations.

        Refused with `RES_019` while the relay still serves the model.
        """
        await self._validate_id(resource_id, "resource id")
        response = await self._http.request(
            "DELETE",
            f"{_RESOURCES_PATH}/{quote(resource_id, safe='')}",
            scope=RESOURCE_SCOPE_KEY,
            schema=_ResourceResponse,
        )
        return response.resource

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
        permission: ResourcePermission | None = None,
        expires_at: datetime | None = None,
    ) -> Grant:
        """Shares an existing resource.

        A `user` subject is named by id or by e-mail, never both. An `application`
        subject takes the application slug as `subject_id`; a scheme an application
        defines is shared inside that application only. `permission` is `read` by
        default and `write` also covers `read`. `expires_at` must be timezone-aware
        and in the future.
        """
        await self._validate_id(resource_id, "resource id")
        try:
            data = GrantInput(
                subject_type=subject_type,
                subject_id=subject_id,
                subject_email=subject_email,
                permission=permission,
                expires_at=expires_at,
            )
        except ValidationError as err:
            raise _invalid("grant", err) from err
        body: dict[str, Any] = {"subjectType": data.subject_type}
        if data.subject_id is not None:
            body["subjectId"] = data.subject_id
        if data.subject_email is not None:
            body["subjectEmail"] = data.subject_email
        if data.permission is not None:
            body["permission"] = data.permission
        if data.expires_at is not None:
            body["expiresAt"] = to_wire_datetime(data.expires_at)
        response = await self._http.request(
            "POST",
            f"{_RESOURCES_PATH}/{quote(resource_id, safe='')}/grants",
            scope=RESOURCE_SCOPE_KEY,
            body=body,
            schema=_GrantResponse,
        )
        return response.grant

    async def update_grant(
        self, resource_id: str, grant_id: str, *, permission: ResourcePermission
    ) -> Grant:
        """Changes the level of an active grant without revoking it.

        A level the resource's scheme does not support is refused with `RES_014`,
        and an inactive grant with `RES_015`.
        """
        await self._validate_id(resource_id, "resource id")
        await self._validate_id(grant_id, "grant id")
        try:
            data = GrantUpdateInput(permission=permission)
        except ValidationError as err:
            raise _invalid("grant update", err) from err
        response = await self._http.request(
            "PATCH",
            self._grant_path(resource_id, grant_id),
            scope=RESOURCE_SCOPE_KEY,
            body={"permission": data.permission},
            schema=_GrantResponse,
        )
        return response.grant

    async def revoke_grant(self, resource_id: str, grant_id: str) -> Grant:
        """Revokes an active grant: access ends at once and the row stays as history."""
        await self._validate_id(resource_id, "resource id")
        await self._validate_id(grant_id, "grant id")
        response = await self._http.request(
            "DELETE",
            self._grant_path(resource_id, grant_id),
            scope=RESOURCE_SCOPE_KEY,
            schema=_GrantResponse,
        )
        return response.grant

    async def delete_grant(self, resource_id: str, grant_id: str) -> None:
        """Deletes a grant that is already revoked or expired.

        An active grant is refused with `RES_020`: revoke it first.
        """
        await self._validate_id(resource_id, "resource id")
        await self._validate_id(grant_id, "grant id")
        await self._http.request_empty(
            "DELETE",
            self._grant_path(resource_id, grant_id),
            scope=RESOURCE_SCOPE_KEY,
            query={"permanent": "true"},
        )

    async def share_with_application(
        self,
        resource_ids: Sequence[str],
        *,
        application_slug: str,
        permission: ResourcePermission | None = None,
        expires_at: datetime | None = None,
    ) -> list[BulkShareResult]:
        """Shares up to 100 of the user's resources with one application in a call.

        Each resource is checked like a single grant: a refusal is reported on its
        own entry (`code`) and does not stop the others.
        """
        try:
            data = BulkShareInput(
                resource_ids=list(resource_ids),
                application_slug=application_slug,
                permission=permission,
                expires_at=expires_at,
            )
        except ValidationError as err:
            raise _invalid("resource share", err) from err
        body: dict[str, Any] = {
            "resourceIds": data.resource_ids,
            "applicationSlug": data.application_slug,
        }
        if data.permission is not None:
            body["permission"] = data.permission
        if data.expires_at is not None:
            body["expiresAt"] = to_wire_datetime(data.expires_at)
        response = await self._http.request(
            "POST",
            f"{_USER_PATH}/resource-shares",
            scope=RESOURCE_SCOPE_KEY,
            body=body,
            schema=_BulkShareResponse,
        )
        return response.results

    async def list_accessible(
        self, *, scheme: str | None = None, application_id: str | None = None
    ) -> list[AccessibleResource]:
        """The validated resources the user may use through the calling application.

        Each one carries the `permission` the user holds. A listing filter, not an
        admission.
        """
        if scheme is not None and not re.fullmatch(SCHEME_PATTERN, scheme):
            raise ERR.CFG_001("Invalid accessible query: scheme has an invalid shape")
        if application_id is not None and not re.fullmatch(UUID_PATTERN, application_id):
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
    def _grant_path(resource_id: str, grant_id: str) -> str:
        return f"{_RESOURCES_PATH}/{quote(resource_id, safe='')}/grants/{quote(grant_id, safe='')}"

    @staticmethod
    async def _validate_id(value: str, what: str) -> None:
        if not re.fullmatch(UUID_PATTERN, value):
            raise ERR.CFG_001(f"Invalid {what}: must be a UUID")
