from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final, Literal, Protocol
from urllib.parse import urlsplit

from ..errors import ERR

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..config import AuthClientConfig

_UNSAFE_PARAMETER: Final = re.compile(r'["\\\r\n]')


class _HasConfig(Protocol):
    @property
    def config(self) -> AuthClientConfig: ...


def protected_resource_metadata(
    auth: _HasConfig,
    *,
    resource: str,
    scopes_supported: Sequence[str] | None = None,
) -> dict[str, object]:
    """RFC 9728 metadata, which lets MCP and OAuth clients find the authorization server.

    `resource` is the audience this API accepts: its RFC 8707 resource identifier.
    """
    metadata: dict[str, object] = {
        "resource": resource,
        "authorization_servers": [auth.config.issuer],
        "bearer_methods_supported": ["header"],
    }
    if scopes_supported is not None:
        metadata["scopes_supported"] = list(scopes_supported)
    return metadata


def protected_resource_metadata_path(resource: str) -> str:
    """Where RFC 9728 §3 serves the metadata of `resource`.

    The well-known segment sits between the host and the resource path.
    """
    path = urlsplit(resource).path
    return f"/.well-known/oauth-protected-resource{'' if path in ('', '/') else path}"


def bearer_challenge(
    resource_metadata_url: str,
    *,
    error: Literal["invalid_token", "insufficient_scope"] | None = None,
    scope: str | None = None,
) -> str:
    """Value of the `WWW-Authenticate` header of a 401 or 403 response.

    `resource_metadata_url` is the absolute URL of the metadata document,
    advertised to unauthenticated clients.
    """
    parameters = [("resource_metadata", resource_metadata_url)]
    if error:
        parameters.append(("error", error))
    if scope:
        parameters.append(("scope", scope))
    for name, value in parameters:
        if _UNSAFE_PARAMETER.search(value):
            raise ERR.CFG_001(f"Invalid {name} in a Bearer challenge")
    return "Bearer " + ", ".join(f'{name}="{value}"' for name, value in parameters)
