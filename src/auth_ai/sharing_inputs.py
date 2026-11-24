from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Final, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from .resource_types import GrantSubjectType, ResourcePermission

UUID_PATTERN: Final = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
SCHEME_PATTERN: Final = r"^[a-z][a-z0-9]{0,49}$"
BULK_SHARE_LIMIT: Final = 100

type ResourceId = Annotated[str, Field(pattern=UUID_PATTERN)]
type Scheme = Annotated[str, Field(pattern=SCHEME_PATTERN)]


def _require_future(expires_at: datetime | None) -> None:
    if expires_at is not None and expires_at <= datetime.now(UTC):
        raise ValueError("expires_at must be in the future")


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
    plan_id: Annotated[str, Field(pattern=UUID_PATTERN)] | None = None

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


class CreateInput(BaseModel):
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


class UpdateInput(BaseModel):
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


class GrantInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_type: GrantSubjectType
    subject_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    subject_email: (
        Annotated[str, StringConstraints(strip_whitespace=True, max_length=320)] | None
    ) = None
    permission: ResourcePermission | None = None
    expires_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _check_subject(self) -> Self:
        _require_future(self.expires_at)
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


class GrantUpdateInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    permission: ResourcePermission


class BulkShareInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    resource_ids: Annotated[list[ResourceId], Field(min_length=1, max_length=BULK_SHARE_LIMIT)]
    application_slug: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)
    ]
    permission: ResourcePermission | None = None
    expires_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _check_expiry(self) -> Self:
        _require_future(self.expires_at)
        return self
