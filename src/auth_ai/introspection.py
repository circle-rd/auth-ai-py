from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class IntrospectionResult(BaseModel):
    """RFC 7662 answer. Unknown members are kept as is."""

    model_config = ConfigDict(extra="allow", frozen=True)

    active: bool
    scope: str | None = None
    client_id: str | None = None
    sub: str | None = None
    username: str | None = None
    iss: str | None = None
    aud: str | list[str] | None = None
    exp: int | float | None = None
    iat: int | float | None = None
