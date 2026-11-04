from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from ..errors import ERR
from ..http import JsonHttp
from .billing import BillingApi
from .consumption import ConsumptionApi
from .machine_tokens import ClientCredentialsAuth, MachineTokenProvider

if TYPE_CHECKING:
    import httpx2

    from ..config import AuthClientConfig


class MachineAuth(ClientCredentialsAuth, Protocol):
    @property
    def config(self) -> AuthClientConfig: ...

    @property
    def http(self) -> httpx2.AsyncClient: ...


class MachineApi:
    """The auth-service REST API as the application's backend.

    Every call carries a `client_credentials` token minted from the application's
    own secret. The scopes `billing:read`, `consumption:read` and
    `consumption:write` must be granted to the application by a superadmin.
    """

    def __init__(self, auth: MachineAuth) -> None:
        if auth.config.client_secret is None:
            raise ERR.CFG_001("The machine API requires a confidential client")
        http = JsonHttp(
            base_url=auth.config.issuer,
            http=auth.http,
            timeout_seconds=auth.config.timeout_seconds,
            tokens=MachineTokenProvider(auth),
        )
        self.billing = BillingApi(http)
        self.consumption = ConsumptionApi(http)
