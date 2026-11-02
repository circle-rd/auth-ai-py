from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Final, Literal
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    model_validator,
)

from .errors import ERR

if TYPE_CHECKING:
    from pydantic_core.core_schema import ValidatorFunctionWrapHandler

DEFAULT_SCOPES: Final = (
    "openid",
    "profile",
    "email",
    "roles",
    "permissions",
    "features",
    "offline_access",
)

# Scope that lets a user token read the user's own wallet.
WALLET_SELF_SCOPE: Final = "wallet:self:read"

_LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})


def _split(value: str) -> tuple[str, str]:
    """Scheme and host of an absolute URL, empty when `value` is not one."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return "", ""
    return parts.scheme, parts.hostname or ""


def _require_url(value: str) -> str:
    scheme, host = _split(value)
    if not scheme or not host:
        raise ValueError("must be an absolute URL")
    return value


def _require_issuer(value: str) -> str:
    scheme, host = _split(value)
    if scheme != "https" or not host:
        raise ValueError("must be an https URL")
    if value.endswith("/"):
        raise ValueError("must not end with a slash: it is compared verbatim to `iss`")
    return value


# http is allowed for loopback only, so local development needs no tunnel.
def _require_redirect_uri(value: str) -> str:
    scheme, host = _split(value)
    if not host or not (scheme == "https" or (scheme == "http" and host in _LOOPBACK_HOSTS)):
        raise ValueError("must be https (http is only accepted for localhost)")
    return value


# An audience is compared verbatim to `aud`: a trailing slash would never match.
def _require_gateway_url(value: str) -> str:
    _require_redirect_uri(value)
    if value.endswith("/"):
        raise ValueError("must not end with a slash: it is compared verbatim to `aud`")
    return value


def _require_openid(scopes: tuple[str, ...]) -> tuple[str, ...]:
    if "openid" not in scopes:
        raise ValueError("must include `openid`")
    return scopes


type _NonEmpty = Annotated[str, Field(min_length=1)]
type _Issuer = Annotated[str, AfterValidator(_require_issuer)]
type _RedirectUri = Annotated[str, AfterValidator(_require_redirect_uri)]
type _GatewayUrl = Annotated[str, AfterValidator(_require_gateway_url)]
type _Url = Annotated[str, AfterValidator(_require_url)]


class AuthClientConfig(BaseModel):
    """Configuration of an `AuthClient`: raises `AuthAiError` (CFG_001) when invalid.

    With `gateway_url`, the sign-in also asks for the audiences of the gateway and
    of auth-service (which serves the wallet) and for the wallet scope: this is
    what the application's "LiteLLM support" switch authorises.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    issuer: _Issuer
    client_id: _NonEmpty
    # Absent for a public client, which then relies on PKCE alone.
    client_secret: SecretStr | None = Field(default=None, min_length=1)
    token_endpoint_auth_method: Literal["client_secret_basic", "client_secret_post"] = (
        "client_secret_basic"
    )
    redirect_uri: _RedirectUri
    post_logout_redirect_uri: _RedirectUri | None = None
    scopes: Annotated[tuple[_NonEmpty, ...], AfterValidator(_require_openid)] = DEFAULT_SCOPES
    # RFC 8707 audiences requested at sign-in; each refresh narrows to one.
    resources: tuple[_Url, ...] = ()
    # Public URL of the LiteLLM gateway: turns on the gateway and wallet audiences.
    gateway_url: _GatewayUrl | None = None
    clock_tolerance_seconds: Annotated[int, Field(ge=0, le=300)] = 5
    timeout_seconds: Annotated[float, Field(gt=0)] = 10.0

    @model_validator(mode="wrap")
    @classmethod
    def _report_as_cfg_001(
        cls, data: object, handler: ValidatorFunctionWrapHandler
    ) -> AuthClientConfig:
        try:
            config: AuthClientConfig = handler(data)
        except ValidationError as err:
            issues = "; ".join(
                f"{'.'.join(str(part) for part in issue['loc']) or '(root)'}: {issue['msg']}"
                for issue in err.errors(include_input=False, include_url=False)
            )
            raise ERR.CFG_001(f"Invalid SDK configuration: {issues}", cause=err) from err
        if config.gateway_url is None:
            return config
        return config.model_copy(
            update={
                "scopes": tuple(dict.fromkeys([*config.scopes, WALLET_SELF_SCOPE])),
                "resources": tuple(
                    dict.fromkeys([*config.resources, config.gateway_url, config.issuer])
                ),
            }
        )
