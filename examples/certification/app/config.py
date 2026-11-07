from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, SecretStr, ValidationError

if TYPE_CHECKING:
    from collections.abc import Mapping

MIN_COOKIE_SECRET_LENGTH = 32


def _absolute_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("must be an absolute http(s) URL")
    return value


def _site_url(value: str) -> str:
    parts = urlsplit(_absolute_url(value))
    if parts.path or parts.query or parts.fragment:
        raise ValueError("must be an origin: no path, query, fragment or trailing slash")
    return value


type _Url = Annotated[str, AfterValidator(_absolute_url)]
type _Site = Annotated[str, AfterValidator(_site_url)]


class ConfigError(Exception):
    """The environment is invalid; the message names variables, never values."""


class Config(BaseModel):
    model_config = ConfigDict(frozen=True)

    port: int = Field(default=3000, gt=0, lt=65536, alias="PORT")
    public_url: _Site = Field(alias="PUBLIC_URL")
    auth_issuer: _Url = Field(alias="AUTH_ISSUER")
    auth_client_id: str = Field(min_length=1, alias="AUTH_CLIENT_ID")
    auth_client_secret: SecretStr = Field(min_length=1, alias="AUTH_CLIENT_SECRET")
    cookie_secret: SecretStr = Field(min_length=MIN_COOKIE_SECRET_LENGTH, alias="COOKIE_SECRET")


def load_config(env: Mapping[str, str]) -> Config:
    try:
        return Config.model_validate(dict(env))
    except ValidationError as err:
        names = dict.fromkeys(
            ".".join(str(part) for part in issue["loc"])
            for issue in err.errors(include_input=False, include_url=False)
        )
        raise ConfigError(f"Invalid environment: {', '.join(names)}") from None
