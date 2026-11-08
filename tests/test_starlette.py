import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Annotated
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import httpx2
import pytest
from fastapi import Depends, FastAPI
from pydantic import BaseModel
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from auth_ai import ERR
from auth_ai.messages import WebResponse
from auth_ai.server.backchannel_logout import MAX_BODY_BYTES
from auth_ai.starlette import (
    install_auth,
    load_session,
    require_auth,
    to_response,
    to_web_request,
)
from auth_ai.web.handlers import AuthHandlers
from auth_ai.web.sessions import Session
from tests.support.bff import (
    FORM,
    LOGIN_COOKIE,
    ORIGIN,
    SESSION_COOKIE,
    BffHarness,
)
from tests.support.mock_idp import ISSUER, MockIdp, json_response


class Echo(BaseModel):
    message: str


def starlette_app(handlers: AuthHandlers) -> Starlette:
    require = require_auth(handlers)
    load = load_session(handlers)

    async def private(request: Request) -> Response:
        session = await require(request)
        return JSONResponse({"sub": session.user_id, "roles": session.claims.roles})

    async def maybe(request: Request) -> Response:
        return JSONResponse({"signedIn": await load(request) is not None})

    async def public(_request: Request) -> Response:
        return JSONResponse({"ok": True})

    async def host(request: Request) -> Response:
        return JSONResponse({"host": request.headers["host"]})

    async def echo(request: Request) -> Response:
        await require(request)
        return JSONResponse({"echo": await request.json()})

    async def forbidden(_request: Request) -> Response:
        raise ERR.TOK_004("Missing scope billing:write", details={"scope": "billing:write"})

    app = Starlette(
        routes=[
            Route("/private", private),
            Route("/maybe", maybe),
            Route("/public", public),
            Route("/host", host),
            Route("/echo", echo, methods=["POST"]),
            Route("/forbidden", forbidden),
        ]
    )
    install_auth(app, handlers)
    return app


def fastapi_app(handlers: AuthHandlers) -> FastAPI:
    require = require_auth(handlers)
    load = load_session(handlers)
    app = FastAPI()

    @app.get("/private")
    async def private(session: Annotated[Session, Depends(require)]) -> dict[str, object]:
        return {"sub": session.user_id, "roles": session.claims.roles}

    @app.get("/maybe")
    async def maybe(session: Annotated[Session | None, Depends(load)]) -> dict[str, object]:
        return {"signedIn": session is not None}

    @app.get("/public")
    async def public() -> dict[str, object]:
        return {"ok": True}

    @app.get("/host")
    async def host(request: Request) -> dict[str, object]:
        return {"host": request.headers["host"]}

    @app.post("/echo")
    async def echo(
        payload: Echo, _session: Annotated[Session, Depends(require)]
    ) -> dict[str, object]:
        return {"echo": payload.model_dump()}

    @app.get("/forbidden")
    async def forbidden() -> dict[str, object]:
        raise ERR.TOK_004("Missing scope billing:write", details={"scope": "billing:write"})

    install_auth(app, handlers)
    return app


type AppFactory = Callable[[AuthHandlers], Starlette]
FACTORIES: dict[str, AppFactory] = {"starlette": starlette_app, "fastapi": fastapi_app}


@pytest.fixture(params=sorted(FACTORIES))
def make_app(request: pytest.FixtureRequest) -> AppFactory:
    factory: AppFactory = FACTORIES[request.param]
    return factory


@pytest.fixture
async def bff(idp: MockIdp) -> AsyncIterator[BffHarness]:
    harness = BffHarness(idp)
    yield harness
    await harness.aclose()


@asynccontextmanager
async def serve(app: Starlette) -> AsyncIterator[httpx2.AsyncClient]:
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url=ORIGIN) as client:
        yield client


@pytest.fixture
async def client(bff: BffHarness, make_app: AppFactory) -> AsyncIterator[httpx2.AsyncClient]:
    async with serve(make_app(bff.handlers)) as served:
        yield served


def cookies_of(response: httpx2.Response) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for line in response.headers.get_list("set-cookie"):
        name, _, value = line.split(";", 1)[0].partition("=")
        cookies[name] = value
    return cookies


async def sign_in(client: httpx2.AsyncClient, bff: BffHarness) -> str:
    login = await client.get("/auth/login?next=/home")
    assert login.status_code == 302
    authorize = parse_qs(urlsplit(login.headers["location"]).query)
    bff.nonce = authorize["nonce"][0]
    callback = await client.get(
        f"/auth/callback?code=abc&state={authorize['state'][0]}&iss={quote(ISSUER, safe='')}",
        headers={"cookie": f"{LOGIN_COOKIE}={cookies_of(login)[LOGIN_COOKIE]}"},
    )
    assert callback.status_code == 303
    assert callback.headers["location"] == "/home"
    # Cookies are sent explicitly: the jar would leak a session into the signed-out cases.
    client.cookies.clear()
    return cookies_of(callback)[SESSION_COOKIE]


def as_user(cookie: str) -> dict[str, str]:
    return {"cookie": f"{SESSION_COOKIE}={cookie}"}


class TestRoutes:
    async def test_serves_login_with_its_cookie_and_redirect(
        self, client: httpx2.AsyncClient
    ) -> None:
        response = await client.get("/auth/login")
        assert response.status_code == 302
        assert response.headers["location"].startswith(f"{ISSUER}/authorize")
        assert response.headers["cache-control"] == "no-store"
        assert response.headers.get_list("set-cookie")[0].startswith(f"{LOGIN_COOKIE}=")

    async def test_completes_a_sign_in_and_serves_me(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        cookie = await sign_in(client, bff)
        me = await client.get("/auth/me", headers=as_user(cookie))
        assert me.status_code == 200
        assert "application/json" in me.headers["content-type"]
        assert me.json()["user"]["roles"] == ["editor"]

    async def test_keeps_every_set_cookie_header_of_the_callback(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        login = await client.get("/auth/login")
        authorize = parse_qs(urlsplit(login.headers["location"]).query)
        bff.nonce = authorize["nonce"][0]
        callback = await client.get(
            f"/auth/callback?code=abc&state={authorize['state'][0]}&iss={quote(ISSUER, safe='')}",
            headers={"cookie": f"{LOGIN_COOKIE}={cookies_of(login)[LOGIN_COOKIE]}"},
        )
        cookies = callback.headers.get_list("set-cookie")
        assert len(cookies) == 2
        assert cookies[0].startswith(f"{LOGIN_COOKIE}=;")
        assert cookies[1].startswith(f"{SESSION_COOKIE}=")

    async def test_logs_out_and_clears_the_cookie(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        cookie = await sign_in(client, bff)

        response = await client.post(
            "/auth/logout",
            headers={**as_user(cookie), "origin": ORIGIN, "accept": "application/json"},
        )

        assert response.status_code == 200
        assert response.json()["logoutUrl"].startswith(f"{ISSUER}/end-session")
        assert "Max-Age=0" in response.headers.get_list("set-cookie")[0]
        assert (await client.get("/auth/me", headers=as_user(cookie))).status_code == 401

    async def test_refuses_a_cross_site_logout(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        cookie = await sign_in(client, bff)
        response = await client.post(
            "/auth/logout", headers={**as_user(cookie), "origin": "https://evil.test"}
        )
        assert response.status_code == 403
        assert (await client.get("/auth/me", headers=as_user(cookie))).status_code == 200

    async def test_reads_the_back_channel_logout_form(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        cookie = await sign_in(client, bff)

        response = await client.post(
            "/auth/backchannel-logout",
            headers=FORM,
            content=urlencode({"logout_token": bff.logout_token()}),
        )

        assert response.status_code == 200
        assert response.content == b""
        assert (await client.get("/auth/me", headers=as_user(cookie))).status_code == 401

    async def test_caps_the_back_channel_logout_body(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        cookie = await sign_in(client, bff)
        oversized = urlencode({"logout_token": bff.logout_token(), "padding": "a" * MAX_BODY_BYTES})

        response = await client.post("/auth/backchannel-logout", headers=FORM, content=oversized)

        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}
        assert (await client.get("/auth/me", headers=as_user(cookie))).status_code == 200

    async def test_caps_a_back_channel_logout_body_sent_without_a_length(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        async def chunks() -> AsyncIterator[bytes]:
            yield f"logout_token={bff.logout_token()}&padding=".encode()
            for _ in range(2 * MAX_BODY_BYTES // 1024):
                yield b"a" * 1024

        response = await client.post("/auth/backchannel-logout", headers=FORM, content=chunks())

        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}

    async def test_answers_405_and_404_through_the_handlers(
        self, client: httpx2.AsyncClient
    ) -> None:
        wrong_method = await client.post("/auth/login")
        assert wrong_method.status_code == 405
        assert wrong_method.headers["allow"] == "GET"
        assert (await client.put("/auth/me")).status_code == 405
        nothing = await client.get("/auth/nothing")
        assert nothing.status_code == 404
        assert nothing.content == b""
        assert (await client.get("/public")).json() == {"ok": True}

    async def test_builds_urls_on_the_registered_origin_not_on_the_host_header(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        assert (await client.get("/host", headers={"host": "evil.test"})).json() == {
            "host": "evil.test"
        }

        response = await client.get("/auth/login", headers={"host": "evil.test"})

        assert response.status_code == 302
        assert "evil.test" not in response.headers["location"]
        assert all("evil.test" not in str(r.url) for r in bff.idp.requests)

    async def test_does_not_trust_the_host_header_of_the_callback(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        login = await client.get("/auth/login")
        authorize = parse_qs(urlsplit(login.headers["location"]).query)
        bff.nonce = authorize["nonce"][0]

        callback = await client.get(
            f"/auth/callback?code=abc&state={authorize['state'][0]}&iss={quote(ISSUER, safe='')}",
            headers={
                "host": "evil.test",
                "cookie": f"{LOGIN_COOKIE}={cookies_of(login)[LOGIN_COOKIE]}",
            },
        )

        assert callback.status_code == 303
        token_request = bff.idp.requests_to("/token")[0]
        assert token_request.form.get("redirect_uri") == f"{ORIGIN}/auth/callback"

    async def test_ignores_a_path_that_is_not_a_route(self, client: httpx2.AsyncClient) -> None:
        assert (await client.get("/auth/login//")).status_code == 404


class TestDependencies:
    async def test_require_auth_answers_401_to_a_signed_out_request(
        self, client: httpx2.AsyncClient
    ) -> None:
        response = await client.get("/private")
        assert response.status_code == 401
        assert response.json() == {"error": {"code": "SES_001", "message": "Not signed in"}}

    async def test_require_auth_answers_401_to_a_forged_cookie(
        self, client: httpx2.AsyncClient
    ) -> None:
        assert (await client.get("/private", headers=as_user("forged"))).status_code == 401

    async def test_require_auth_exposes_the_session_to_the_route(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        cookie = await sign_in(client, bff)
        response = await client.get("/private", headers=as_user(cookie))
        assert response.json() == {"sub": "user-1", "roles": ["editor"]}

    async def test_load_session_never_blocks(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        assert (await client.get("/maybe")).json() == {"signedIn": False}
        cookie = await sign_in(client, bff)
        assert (await client.get("/maybe", headers=as_user(cookie))).json() == {"signedIn": True}

    async def test_require_auth_leaves_the_body_to_the_route(
        self, client: httpx2.AsyncClient, bff: BffHarness
    ) -> None:
        cookie = await sign_in(client, bff)
        response = await client.post("/echo", headers=as_user(cookie), json={"message": "hello"})
        assert response.status_code == 200
        assert response.json() == {"echo": {"message": "hello"}}

    async def test_a_signed_out_post_is_refused_before_its_body_matters(
        self, client: httpx2.AsyncClient
    ) -> None:
        response = await client.post("/echo", json={"message": "hello"})
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "SES_001"

    async def test_answers_a_route_error_with_the_public_envelope_only(
        self, client: httpx2.AsyncClient
    ) -> None:
        response = await client.get("/forbidden")
        assert response.status_code == 403
        assert response.json() == {"error": {"code": "TOK_004", "message": "Insufficient scope"}}
        assert "billing" not in response.text

    async def test_reports_a_provider_failure_as_an_error_response_not_a_crash(
        self, bff: BffHarness, make_app: AppFactory
    ) -> None:
        handlers = bff.build(claims_renew_seconds=0)
        async with serve(make_app(handlers)) as client:
            cookie = await sign_in(client, bff)
            bff.idp.token_handler = lambda _request: json_response({"error": "server_error"}, 500)

            for path in ("/private", "/maybe"):
                response = await client.get(path, headers=as_user(cookie))
                assert response.status_code == 502
                assert response.json()["error"]["code"] == "OIDC_003"

    async def test_renews_the_claims_of_a_session_that_is_due(
        self, bff: BffHarness, make_app: AppFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async with serve(make_app(bff.handlers)) as client:
            cookie = await sign_in(client, bff)
            real_time = time.time
            monkeypatch.setattr(time, "time", lambda: real_time() + 901)
            bff.roles = ["admin"]

            response = await client.get("/private", headers=as_user(cookie))

            assert response.json() == {"sub": "user-1", "roles": ["admin"]}
            assert bff.refreshes == 1


class TestAdapterFunctions:
    def test_to_response_keeps_repeated_headers_apart(self) -> None:
        response = to_response(
            WebResponse(
                200,
                (("set-cookie", "a=1"), ("Set-Cookie", "b=2"), ("cache-control", "no-store")),
                b"body",
            )
        )
        assert response.headers.getlist("set-cookie") == ["a=1", "b=2"]
        assert response.headers["cache-control"] == "no-store"
        assert response.body == b"body"
        assert response.status_code == 200

    async def test_to_web_request_is_built_on_the_registered_origin(self) -> None:
        captured: list[Request] = []

        async def endpoint(request: Request) -> Response:
            captured.append(request)
            return Response()

        app = Starlette(routes=[Route("/auth/me", endpoint, methods=["GET", "POST"])])
        async with serve(app) as client:
            await client.post(
                "/auth/me?x=1&y=%2F",
                headers={"host": "evil.test", "cookie": "a=b"},
                content=b"payload",
            )

        [request] = captured
        without_body = await to_web_request(request, ORIGIN)
        assert without_body.url == f"{ORIGIN}/auth/me?x=1&y=%2F"
        assert without_body.method == "POST"
        assert without_body.header("cookie") == "a=b"
        assert without_body.header("host") == "evil.test"
        assert without_body.body == b""
        assert (await to_web_request(request, ORIGIN, with_body=True)).body == b"payload"

    async def test_a_query_less_request_has_no_trailing_question_mark(self) -> None:
        captured: list[str] = []

        async def endpoint(request: Request) -> Response:
            captured.append((await to_web_request(request, ORIGIN)).url)
            return Response()

        async with serve(Starlette(routes=[Route("/x", endpoint)])) as client:
            await client.get("/x")

        assert captured == [f"{ORIGIN}/x"]
