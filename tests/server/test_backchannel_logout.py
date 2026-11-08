from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlencode

import pytest

from auth_ai import AuthAiError, AuthClient
from auth_ai.messages import WebRequest, WebResponse
from auth_ai.server import (
    BackchannelLogoutEvent,
    BackchannelLogoutHandler,
    MemoryReplayStore,
    verify_logout_token,
)
from auth_ai.server import backchannel_logout as logout_module
from tests.support.mock_idp import CLIENT_ID, ISSUER, MockIdp, now_seconds

EVENT = "http://schemas.openid.net/event/backchannel-logout"
URL = "https://app.test/backchannel-logout"
FORM = "application/x-www-form-urlencoded"


@dataclass
class Recorder:
    events: list[BackchannelLogoutEvent] = field(default_factory=list)
    errors: list[BaseException] = field(default_factory=list)
    failure: Exception | None = None

    async def on_logout(self, event: BackchannelLogoutEvent) -> None:
        if self.failure is not None:
            raise self.failure
        self.events.append(event)

    def on_error(self, error: BaseException) -> None:
        self.errors.append(error)


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
def handle(auth: AuthClient, recorder: Recorder) -> BackchannelLogoutHandler:
    return BackchannelLogoutHandler(
        auth=auth, on_logout=recorder.on_logout, on_error=recorder.on_error
    )


def logout_claims(**overrides: Any) -> dict[str, Any]:
    iat = now_seconds()
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-1",
        "sid": "sid-1",
        "iat": iat,
        "exp": iat + 120,
        "jti": str(uuid.uuid4()),
        "events": {EVENT: {}},
        **overrides,
    }
    # A None override removes the claim.
    return {name: value for name, value in claims.items() if value is not None}


def logout_token(idp: MockIdp, typ: str | None = "logout+jwt", **overrides: Any) -> str:
    return idp.sign_jwt(
        logout_claims(**overrides),
        typ=typ,
        omit_typ=typ is None,
    )


def post(token: str | None, *, headers: dict[str, str] | None = None) -> WebRequest:
    body = urlencode({"logout_token": token}) if token else ""
    return WebRequest.create(
        "POST", URL, headers={"content-type": FORM, **(headers or {})}, body=body.encode()
    )


def error_body(response: WebResponse) -> object:
    return response.json()


class TestBackchannelLogoutHandler:
    async def test_ends_the_session_named_by_a_valid_token(
        self, idp: MockIdp, handle: BackchannelLogoutHandler, recorder: Recorder
    ) -> None:
        response = await handle(post(logout_token(idp)))

        assert response.status == 200
        assert response.header("cache-control") == "no-store"
        assert recorder.events == [BackchannelLogoutEvent(sid="sid-1", sub="user-1")]
        assert recorder.errors == []

    async def test_accepts_missing_typ_only_when_explicitly_configured(
        self, idp: MockIdp, auth: AuthClient, recorder: Recorder
    ) -> None:
        handler = BackchannelLogoutHandler(
            auth=auth,
            on_logout=recorder.on_logout,
            allow_missing_typ=True,
            on_error=recorder.on_error,
        )

        response = await handler(post(logout_token(idp, typ=None)))

        assert response.status == 200
        assert recorder.events == [BackchannelLogoutEvent(sid="sid-1", sub="user-1")]

    async def test_supports_a_synchronous_callback(self, idp: MockIdp, auth: AuthClient) -> None:
        events: list[BackchannelLogoutEvent] = []
        handler = BackchannelLogoutHandler(auth=auth, on_logout=events.append)

        response = await handler(post(logout_token(idp)))

        assert response.status == 200
        assert events == [BackchannelLogoutEvent(sid="sid-1", sub="user-1")]

    async def test_refuses_a_replayed_token(
        self, idp: MockIdp, handle: BackchannelLogoutHandler, recorder: Recorder
    ) -> None:
        token = logout_token(idp)

        assert (await handle(post(token))).status == 200
        replay = await handle(post(token))

        assert replay.status == 400
        assert error_body(replay) == {"error": "invalid_request"}
        assert len(recorder.events) == 1
        assert len(recorder.errors) == 1

    @pytest.mark.parametrize(
        ("typ", "overrides"),
        [
            pytest.param("JWT", {}, id="a wrong typ"),
            pytest.param(None, {}, id="no typ"),
            pytest.param("logout+jwt", {"aud": "other-app"}, id="another audience"),
            pytest.param("logout+jwt", {"iss": "https://evil.test"}, id="another issuer"),
            pytest.param("logout+jwt", {"events": {}}, id="no event"),
            pytest.param("logout+jwt", {"events": "text"}, id="events that are not an object"),
            pytest.param("logout+jwt", {"nonce": "n"}, id="a nonce"),
            pytest.param("logout+jwt", {"sid": None}, id="no sid"),
            pytest.param("logout+jwt", {"sid": ""}, id="an empty sid"),
            pytest.param("logout+jwt", {"jti": None}, id="no jti"),
            pytest.param("logout+jwt", {"sub": None}, id="no sub"),
            pytest.param("logout+jwt", {"iat": None}, id="no iat"),
            pytest.param("logout+jwt", {"exp": None}, id="no exp"),
            pytest.param("logout+jwt", {"iat": True}, id="a boolean iat"),
            pytest.param("logout+jwt", {"iat": now_seconds() + 3600}, id="an iat in the future"),
            pytest.param(
                "logout+jwt", {"exp": now_seconds() + 7200}, id="a lifetime beyond 10 minutes"
            ),
            pytest.param(
                "logout+jwt",
                {"iat": now_seconds() - 600, "exp": now_seconds() - 300},
                id="an expiry in the past",
            ),
        ],
    )
    async def test_rejects_a_token_with(
        self,
        idp: MockIdp,
        handle: BackchannelLogoutHandler,
        recorder: Recorder,
        typ: str | None,
        overrides: dict[str, Any],
    ) -> None:
        response = await handle(post(logout_token(idp, typ, **overrides)))

        assert response.status == 400
        assert error_body(response) == {"error": "invalid_request"}
        assert recorder.events == []
        assert len(recorder.errors) == 1

    async def test_rejects_a_token_signed_by_an_unknown_key(
        self, idp: MockIdp, handle: BackchannelLogoutHandler, recorder: Recorder
    ) -> None:
        forged = idp.sign_jwt(logout_claims(), typ="logout+jwt", key=idp.generate_foreign_key())

        assert (await handle(post(forged))).status == 400
        assert recorder.events == []

    async def test_does_not_let_a_failed_validation_burn_the_jti(
        self, idp: MockIdp, handle: BackchannelLogoutHandler
    ) -> None:
        await handle(post(logout_token(idp, jti="shared-jti", nonce="n")))

        assert (await handle(post(logout_token(idp, jti="shared-jti")))).status == 200

    @pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
    async def test_answers_405_to_anything_but_post(
        self, handle: BackchannelLogoutHandler, method: str
    ) -> None:
        response = await handle(WebRequest.create(method, URL))

        assert response.status == 405
        assert response.header("allow") == "POST"
        assert response.header("cache-control") == "no-store"

    async def test_rejects_a_body_that_is_not_a_form(
        self, idp: MockIdp, handle: BackchannelLogoutHandler
    ) -> None:
        request = WebRequest.create(
            "POST",
            URL,
            headers={"content-type": "application/json"},
            body=f'{{"logout_token": "{logout_token(idp)}"}}'.encode(),
        )

        assert (await handle(request)).status == 400

    async def test_rejects_a_form_without_logout_token(
        self, handle: BackchannelLogoutHandler
    ) -> None:
        assert (await handle(post(None))).status == 400

    async def test_rejects_an_oversized_body_before_any_validation(
        self, idp: MockIdp, handle: BackchannelLogoutHandler
    ) -> None:
        assert (await handle(post("x" * 20_000))).status == 400

        lying = post("x", headers={"content-length": "99999"})
        assert (await handle(lying)).status == 400
        assert idp.requests == []

    async def test_answers_500_and_reports_when_ending_the_session_fails(
        self, idp: MockIdp, handle: BackchannelLogoutHandler, recorder: Recorder
    ) -> None:
        recorder.failure = RuntimeError("db down")

        response = await handle(post(logout_token(idp)))

        assert response.status == 500
        assert error_body(response) == {"error": "server_error"}
        assert len(recorder.errors) == 1
        assert str(recorder.errors[0]) == "db down"

    async def test_works_without_an_error_callback(
        self, auth: AuthClient, recorder: Recorder
    ) -> None:
        quiet = BackchannelLogoutHandler(auth=auth, on_logout=recorder.on_logout)

        assert (await quiet(post("not-a-jwt"))).status == 400

    async def test_reports_a_rejected_token_as_an_auth_ai_error(
        self, handle: BackchannelLogoutHandler, recorder: Recorder
    ) -> None:
        await handle(post("not-a-jwt"))

        assert isinstance(recorder.errors[0], AuthAiError)
        assert recorder.errors[0].code == "TOK_001"


class TestVerifyLogoutToken:
    async def test_returns_the_claims(self, idp: MockIdp, auth: AuthClient) -> None:
        claims = await verify_logout_token(auth, logout_token(idp, jti="j1"), MemoryReplayStore())

        assert (claims.sid, claims.sub, claims.jti) == ("sid-1", "user-1", "j1")

    async def test_rejects_a_token_already_claimed_in_the_replay_store(
        self, idp: MockIdp, auth: AuthClient
    ) -> None:
        store = MemoryReplayStore()
        token = logout_token(idp)
        await verify_logout_token(auth, token, store)

        with pytest.raises(AuthAiError) as raised:
            await verify_logout_token(auth, token, store)

        assert raised.value.code == "TOK_001"


class TestMemoryReplayStore:
    async def test_accepts_a_jti_again_once_its_token_expired(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = 1_793_433_600.0
        monkeypatch.setattr(logout_module, "time", SimpleNamespace(time=lambda: now))
        store = MemoryReplayStore()

        assert await store.claim("j", now + 120) is True
        assert await store.claim("j", now + 120) is False

        now += 121
        assert await store.claim("j", now + 120) is True
