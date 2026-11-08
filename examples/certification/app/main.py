from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Final

import uvicorn
from fastapi import FastAPI, Response
from starlette.datastructures import MutableHeaders

from auth_ai import AuthClient, AuthClientConfig, GrantManager, MemoryGrantStore
from auth_ai.starlette import install_auth
from auth_ai.web import AuthHandlers, MemorySessionStore, Session

from .config import load_config

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Sequence

    from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger("certification")

CONTENT_SECURITY_POLICY: Final = (
    "default-src 'none'; img-src 'self' https:; script-src 'self'; "
    "style-src 'self'; connect-src 'self'; base-uri 'none'; "
    "frame-ancestors 'none'"
)
PUBLIC_DIR: Final = Path(__file__).resolve().parent.parent / "public"
STATIC_FILES: Final = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/alps.jpg": ("alps.jpg", "image/jpeg"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}

config = load_config(os.environ)

auth = AuthClient(
    AuthClientConfig(
        issuer=config.auth_issuer,
        client_id=config.auth_client_id,
        client_secret=config.auth_client_secret,
        redirect_uri=f"{config.public_url}/auth/callback",
        post_logout_redirect_uri=f"{config.public_url}/auth/logout/callback",
    )
)

grants = GrantManager(auth=auth, store=MemoryGrantStore())


def _log_handler_error(error: BaseException) -> None:
    log.warning("auth handler error: %s", error)


def _log_sessions_ended(sessions: Sequence[Session]) -> None:
    log.info("sessions ended: %d", len(sessions))


handlers = AuthHandlers(
    auth=auth,
    grants=grants,
    sessions=MemorySessionStore(),
    secret=config.cookie_secret.get_secret_value(),
    require_provider_session=not config.oidf_mock_compat,
    allow_missing_logout_token_typ=config.oidf_mock_compat,
    on_error=_log_handler_error,
    on_sessions_ended=_log_sessions_ended,
)


class _NoAccessLog(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return False


logging.getLogger("uvicorn.access").addFilter(_NoAccessLog())


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["content-security-policy"] = CONTENT_SECURITY_POLICY
                headers["x-content-type-options"] = "nosniff"
                headers["referrer-policy"] = "no-referrer"
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestLogMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        status = HTTPStatus.INTERNAL_SERVER_ERROR.value

        async def send_logging_status(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_logging_status)
        finally:
            log.info("%s %s -> %d", scope.get("method"), scope.get("path"), status)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    try:
        yield
    finally:
        await auth.aclose()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLogMiddleware)
install_auth(app, handlers)


def _static(file_name: str, media_type: str) -> Callable[[], Awaitable[Response]]:
    body = (PUBLIC_DIR / file_name).read_bytes()

    async def serve() -> Response:
        return Response(body, media_type=media_type)

    return serve


for static_path, (static_file, static_type) in STATIC_FILES.items():
    app.add_api_route(
        static_path,
        _static(static_file, static_type),
        methods=["GET", "HEAD"],
        include_in_schema=False,
    )


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    return {"ok": True}


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    uvicorn.run(
        app,
        host="0.0.0.0",  # noqa: S104 - the container is reached from the edge network
        port=config.port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


if __name__ == "__main__":
    main()
