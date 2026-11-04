from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Protocol

import httpx2
from pydantic import BaseModel, ConfigDict, ValidationError
from pydantic.alias_generators import to_camel

from .errors import ERR, AuthAiError

if TYPE_CHECKING:
    from collections.abc import Mapping


class _ApiErrorDetail(BaseModel):
    code: str
    message: str


class _ApiErrorBody(BaseModel):
    error: _ApiErrorDetail


class HttpTokens(Protocol):
    """Supplies the bearer token of a call, by the scope or audience the endpoint requires."""

    async def get_token(self, key: str) -> str: ...

    def invalidate(self, key: str) -> None:
        """Drops a token the API refused, so the retry mints a fresh one."""
        ...


class JsonHttp:
    """Authenticated JSON calls to the auth-service REST API."""

    def __init__(
        self,
        *,
        base_url: str,
        http: httpx2.AsyncClient,
        timeout_seconds: float,
        tokens: HttpTokens,
    ) -> None:
        self._base_url = base_url
        self._http = http
        self._timeout = timeout_seconds
        self._tokens = tokens

    async def request[M: BaseModel](
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        scope: str,
        schema: type[M],
        query: Mapping[str, str | int | None] | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> M:
        """`path` is relative to the base URL and its segments must already be URL-encoded.

        `scope` is the key passed to the token supplier: a machine scope, or an
        audience.
        """
        response = await self._send(method, path, scope, query, body)
        # A revoked or rotated credential surfaces as 401: retry once with a fresh token.
        if response.status_code == httpx2.codes.UNAUTHORIZED:
            self._tokens.invalidate(scope)
            response = await self._send(method, path, scope, query, body)
        if not response.is_success:
            raise _to_error(response)
        try:
            return schema.model_validate(response.json())
        except (ValueError, ValidationError) as err:
            raise ERR.API_002(cause=err) from err

    async def _send(
        self,
        method: str,
        path: str,
        scope: str,
        query: Mapping[str, str | int | None] | None,
        body: Mapping[str, Any] | None,
    ) -> httpx2.Response:
        params = {k: str(v) for k, v in (query or {}).items() if v is not None}
        token = await self._tokens.get_token(scope)
        try:
            return await self._http.request(
                method,
                f"{self._base_url}{path}",
                params=params,
                json=body,
                headers={
                    "authorization": f"Bearer {token}",
                    "accept": "application/json",
                },
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx2.HTTPError as err:
            raise ERR.API_001("auth-service is unreachable", cause=err) from err


def _to_error(response: httpx2.Response) -> AuthAiError:
    status = response.status_code
    try:
        parsed = _ApiErrorBody.model_validate(response.json())
    except (ValueError, ValidationError):
        return ERR.API_001(f"auth-service answered {status}", details={"status": status})
    code, message = parsed.error.code, parsed.error.message
    return ERR.API_001(
        f"auth-service answered {status} {code}: {message}",
        details={"status": status, "apiCode": code},
    )


class ApiModel(BaseModel):
    """Base of the models that mirror an auth-service answer (camelCase on the wire)."""

    model_config = ConfigDict(
        frozen=True,
        extra="ignore",
        alias_generator=to_camel,
        populate_by_name=True,
    )

    def to_json(self) -> dict[str, Any]:
        """JSON-ready dict with the wire names, e.g. for the BFF routes."""
        return self.model_dump(mode="json", by_alias=True)
