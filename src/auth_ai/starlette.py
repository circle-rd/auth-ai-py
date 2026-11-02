"""Starlette and FastAPI adapter for the backend-for-frontend routes.

Requires the `starlette` (or `fastapi`) extra.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import httpx
from starlette.requests import Request  # noqa: TC002 - FastAPI resolves the annotation at runtime
from starlette.responses import Response

from .errors import AuthAiError
from .messages import WebRequest, WebResponse
from .server.backchannel_logout import MAX_BODY_BYTES
from .web.http import error_response

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from starlette.applications import Starlette

    from .web.handlers import AuthHandlers
    from .web.sessions import Session

_METHODS: Final = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


async def _read_body(request: Request) -> bytes:
    """The body, capped: the SDK's POST routes take a tiny form at most."""
    if request.method == "GET":
        return b""
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            break
    return b"".join(chunks)


async def to_web_request(request: Request, origin: str, *, with_body: bool = False) -> WebRequest:
    """A `WebRequest` built on the registered origin: the Host header is not trusted.

    The body is read only on request: the session dependencies must leave it to your route.
    """
    query = request.scope.get("query_string", b"").decode("latin-1")
    url = f"{origin}{request.url.path}" + (f"?{query}" if query else "")
    headers = httpx.Headers(
        [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers.raw]
    )
    body = await _read_body(request) if with_body else b""
    return WebRequest(request.method, url, headers, body)


def to_response(response: WebResponse) -> Response:
    sent = Response(content=response.body, status_code=response.status)
    for name, value in response.headers:
        # `append` keeps repeated headers such as Set-Cookie apart.
        sent.headers.append(name, value)
    return sent


def auth_endpoint(
    handlers: AuthHandlers,
) -> Callable[[Request], Awaitable[Response]]:
    """The ASGI endpoint serving every route below `handlers.base_path`."""

    async def endpoint(request: Request) -> Response:
        web_request = await to_web_request(request, handlers.origin, with_body=True)
        response = await handlers.handle(web_request)
        return Response(status_code=404) if response is None else to_response(response)

    return endpoint


def auth_error_handler(
    on_error: Callable[[BaseException], None] | None = None,
) -> Callable[[Request, Exception], Awaitable[Response]]:
    """Exception handler answering an `AuthAiError` with the public error envelope."""

    async def handler(_request: Request, exc: Exception) -> Response:
        return to_response(error_response(exc, on_error))

    return handler


def install_auth(app: Starlette, handlers: AuthHandlers) -> None:
    """Serves the sign-in routes of `handlers` on `app` (Starlette or FastAPI).

    Also makes `AuthAiError` raised by `require_auth` or by your own routes answer
    with the public error envelope (code and generic message only); server-side
    failures reach the handlers' `on_error`.
    """
    app.add_route(f"{handlers.base_path}/{{path:path}}", auth_endpoint(handlers), methods=_METHODS)
    app.add_exception_handler(AuthAiError, auth_error_handler(handlers.on_error))


def require_auth(handlers: AuthHandlers) -> Callable[[Request], Awaitable[Session]]:
    """Dependency answering 401 `SES_001` to signed-out requests and returning the session.

    FastAPI: `Depends(require_auth(handlers))`. Starlette: call it in your endpoint.
    """

    async def dependency(request: Request) -> Session:
        return await handlers.require_session(await to_web_request(request, handlers.origin))

    return dependency


def load_session(
    handlers: AuthHandlers,
) -> Callable[[Request], Awaitable[Session | None]]:
    """Dependency returning the session when signed in and None otherwise."""

    async def dependency(request: Request) -> Session | None:
        return await handlers.get_session(await to_web_request(request, handlers.origin))

    return dependency
