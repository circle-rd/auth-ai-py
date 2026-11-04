from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from .errors import ERR
from .gateway import GatewayClient
from .http import JsonHttp
from .wallet import WalletClient

if TYPE_CHECKING:
    import httpx2

    from .config import AuthClientConfig
    from .grants import AccessToken


class AiAuth(Protocol):
    @property
    def config(self) -> AuthClientConfig: ...

    @property
    def http(self) -> httpx2.AsyncClient: ...


class AiGrants(Protocol):
    async def get_access_token(
        self, grant_id: str, *, resource: str | None = None
    ) -> AccessToken: ...

    def invalidate(self, grant_id: str, resource: str | None = None) -> None: ...


class _AudienceTokens:
    """Mints the access token of one user for one audience, from the grant manager.

    Serves both the wallet (a single audience, so the key is ignored) and the gateway.
    """

    def __init__(self, grants: AiGrants, grant_id: str, resource: str) -> None:
        self._grants = grants
        self._grant_id = grant_id
        self._resource = resource

    async def get_token(self, key: str | None = None) -> str:
        token = await self._grants.get_access_token(self._grant_id, resource=self._resource)
        return token.access_token

    def invalidate(self, key: str | None = None) -> None:
        self._grants.invalidate(self._grant_id, self._resource)


class UserAi:
    """What an application does for one signed-in user: read the wallet, call the gateway."""

    def __init__(self, auth: AiAuth, grants: AiGrants, grant_id: str) -> None:
        self._auth = auth
        config = auth.config
        self.wallet = WalletClient(
            JsonHttp(
                base_url=config.issuer,
                http=auth.http,
                timeout_seconds=config.timeout_seconds,
                tokens=_AudienceTokens(grants, grant_id, config.issuer),
            ),
            config.issuer,
        )
        self._gateway_tokens = (
            _AudienceTokens(grants, grant_id, config.gateway_url) if config.gateway_url else None
        )
        self._gateway: GatewayClient | None = None

    @property
    def gateway(self) -> GatewayClient:
        """Needs `gateway_url` in the client configuration."""
        config = self._auth.config
        if not config.gateway_url or self._gateway_tokens is None:
            raise ERR.CFG_001("The gateway requires `gateway_url` in the configuration")
        if self._gateway is None:
            self._gateway = GatewayClient(
                gateway_url=config.gateway_url,
                tokens=self._gateway_tokens,
                http=self._auth.http,
                timeout_seconds=config.timeout_seconds,
            )
        return self._gateway


class AiClient:
    """Wallet and gateway clients bound to a user's grant.

    Each call mints (or reuses) a short-lived access token for the right audience:
    the wallet is served by auth-service, the gateway by its own URL.
    """

    def __init__(self, *, auth: AiAuth, grants: AiGrants) -> None:
        self._auth = auth
        self._grants = grants

    def for_user(self, grant_id: str) -> UserAi:
        """`grant_id` is the key the user's refresh token was saved under (typically `sub`)."""
        return UserAi(self._auth, self._grants, grant_id)
