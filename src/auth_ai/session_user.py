from __future__ import annotations

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

from .claims import FeatureValue, IdTokenClaims


class SessionUser(BaseModel):
    """What a signed-in user looks like to the application's frontend.

    Profile and entitlements, with the absent claims normalised to empty values.
    Tokens, `sid` and timestamps never reach the browser. Serialised with
    `to_json()`, the members are camelCase, as the browser clients expect.
    """

    model_config = ConfigDict(frozen=True, alias_generator=to_camel, populate_by_name=True)

    sub: str
    name: str | None = None
    email: str | None = None
    email_verified: bool | None = None
    picture: str | None = None
    roles: list[str]
    permissions: list[str]
    features: dict[str, FeatureValue]
    plan: str | None = None
    org_id: str | None = None

    def to_json(self) -> dict[str, object]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def to_session_user(claims: IdTokenClaims) -> SessionUser:
    return SessionUser(
        sub=claims.sub,
        name=claims.name,
        email=claims.email,
        email_verified=claims.email_verified,
        picture=claims.picture,
        roles=claims.roles or [],
        permissions=claims.permissions or [],
        features=claims.features or {},
        plan=claims.plan,
        org_id=claims.org_id,
    )
