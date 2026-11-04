from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final, Protocol

import httpx2
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from .errors import ERR
from .gateway_errors import to_gateway_error
from .transport import build_http_client

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Mapping

_SERVER_NAME_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


class _GatewayModelBase(BaseModel):
    # LiteLLM adds members across versions: keep them as is.
    model_config = ConfigDict(extra="allow", frozen=True)


class GatewayModel(_GatewayModelBase):
    id: str
    object: str | None = None
    created: int | None = None
    owned_by: str | None = None


class _ModelList(BaseModel):
    data: list[GatewayModel]


class GatewayAgent(_GatewayModelBase):
    agent_id: str
    agent_name: str


class GatewayMcpServer(_GatewayModelBase):
    server_id: str
    server_name: str | None = None
    alias: str | None = None
    description: str | None = None
    transport: str | None = None


class GatewayTokens(Protocol):
    """Supplies the access token minted for the gateway audience."""

    async def get_token(self) -> str: ...

    def invalidate(self) -> None:
        """Drops the token the gateway refused, so the next call mints a fresh one."""
        ...


class GatewayAuth(httpx2.Auth):
    """Signs requests to the gateway with a fresh user token.

    Give it to an OpenAI-compatible SDK through `GatewayClient.create_http_client()`.
    It refuses any other origin so that the token cannot leak, and a 401 drops the
    cached token: retrying the call mints a new one.
    """

    def __init__(self, gateway_url: str, tokens: GatewayTokens) -> None:
        self._origin = httpx2.URL(gateway_url).copy_with(path="/", query=None, fragment=None)
        self._tokens = tokens

    async def async_auth_flow(
        self, request: httpx2.Request
    ) -> AsyncGenerator[httpx2.Request, httpx2.Response]:
        url = request.url
        if (url.scheme, url.host, url.port) != (
            self._origin.scheme,
            self._origin.host,
            self._origin.port,
        ):
            raise ERR.CFG_001("This client only serves requests to the gateway")
        request.headers["authorization"] = f"Bearer {await self._tokens.get_token()}"
        response = yield request
        if response.status_code == httpx2.codes.UNAUTHORIZED:
            self._tokens.invalidate()


class GatewayClient:
    """The LiteLLM gateway on behalf of a signed-in user.

    The user's access token is the API key: it lives one hour, so it is minted per
    call (and cached by the grant manager) and never stored. The gateway bills the
    user's wallet.
    """

    def __init__(
        self,
        *,
        gateway_url: str,
        tokens: GatewayTokens,
        http: httpx2.AsyncClient,
        timeout_seconds: float,
    ) -> None:
        self._gateway_url = gateway_url
        self._tokens = tokens
        self._http = http
        self._timeout = timeout_seconds
        self.auth = GatewayAuth(gateway_url, tokens)

    @property
    def openai_base_url(self) -> str:
        """`base_url` of an OpenAI-compatible SDK."""
        return f"{self._gateway_url}/v1"

    def create_http_client(
        self,
        *,
        timeout: float | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> httpx2.AsyncClient:
        """An `httpx2.AsyncClient` signing every request with a fresh user token.

        Pass it to an OpenAI-compatible SDK together with
        `base_url=openai_base_url` and any placeholder `api_key`. The caller owns
        the client and closes it.
        """
        return build_http_client(
            timeout_seconds=self._timeout if timeout is None else timeout,
            transport=transport,
            auth=self.auth,
        )

    async def get_access_token(self) -> str:
        """A fresh access token, for clients that cannot take an `httpx2` client."""
        return await self._tokens.get_token()

    async def list_models(self) -> list[GatewayModel]:
        """The models the user's plan may call."""
        return (await self._get_json("/v1/models", TypeAdapter(_ModelList))).data

    async def list_agents(self) -> list[GatewayAgent]:
        """The agents the user's plan may reach."""
        return await self._get_json("/v1/agents", TypeAdapter(list[GatewayAgent]))

    async def list_mcp_servers(self) -> list[GatewayMcpServer]:
        """The MCP servers the user's plan may reach."""
        return await self._get_json("/v1/mcp/server", TypeAdapter(list[GatewayMcpServer]))

    def mcp_url(self, server_name: str | None = None) -> str:
        """Endpoint of the gateway's MCP server, or of one registered server.

        Connect an MCP client to it with the `Authorization: Bearer` header of
        `get_access_token()`.
        """
        if server_name is None:
            return f"{self._gateway_url}/mcp"
        if not _SERVER_NAME_PATTERN.fullmatch(server_name):
            raise ERR.CFG_001("Invalid MCP server name")
        return f"{self._gateway_url}/{server_name}/mcp"

    async def post_json(self, path: str, body: Mapping[str, object]) -> object:
        """POSTs JSON to a gateway route (`/v1/chat/completions`, `/v1/embeddings`…).

        Returns the parsed answer, which the caller validates. A refusal becomes a
        gateway error: GW_001 when the wallet cannot pay (402).
        """
        return await self._send("POST", path, json=body)

    async def _get_json[T](self, path: str, adapter: TypeAdapter[T]) -> T:
        body = await self._send("GET", path)
        try:
            return adapter.validate_python(body)
        except ValidationError as err:
            raise ERR.GW_005(cause=err) from err

    async def _send(
        self, method: str, path: str, *, json: Mapping[str, object] | None = None
    ) -> object:
        try:
            response = await self._http.request(
                method,
                f"{self._gateway_url}{path}",
                json=json,
                headers={"accept": "application/json"},
                auth=self.auth,
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx2.HTTPError as err:
            raise ERR.GW_004("The gateway is unreachable", cause=err) from err
        try:
            body: object = response.json()
        except ValueError:
            body = None
        if not response.is_success:
            raise to_gateway_error(response.status_code, body, response.headers)
        return body
