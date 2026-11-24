from __future__ import annotations

from typing import Literal

from .http import ApiModel

type OwnerType = Literal["user", "application"]
type AccessKind = Literal["owner", "grant"]
type GrantSubjectType = Literal["user", "organization", "plan", "everyone", "application"]
type ResourceStatus = Literal["pending_validation", "validation_failed", "validated", "disabled"]
#: Closed set, ordered from the weakest: `write` covers `read`.
type ResourcePermission = Literal["read", "write"]


class AccessibleResource(ApiModel):
    resource_id: str
    resource_uri: str
    scheme: str
    display_name: str
    application_id: str
    application_slug: str
    application_name: str
    owner_type: OwnerType
    #: Present only for the application that owns the resource.
    owner_id: str | None = None
    access_kind: AccessKind
    #: The level the user holds: the owner and a `write` grant can act.
    permission: ResourcePermission
    #: Set when `access_kind` is `grant`.
    grant_subject_type: GrantSubjectType | None = None
