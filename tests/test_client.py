from __future__ import annotations

import base64
import hashlib
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

import httpx2
import pytest

from auth_ai import AuthAiError, AuthClient, AuthClientConfig, LoginHandshake
from tests.support.mock_idp import (
    CLIENT_ID,
    CLIENT_SECRET,
    ISSUER,
    REDIRECT_URI,
    MockIdp,
    create_test_auth,
    json_response,
    now_seconds,
)

RESOURCES = ["https://app.test", "https://llm.test"]


@pytest.fixture
async def auth(idp: MockIdp) -> AsyncIterator[AuthClient]:
    client = create_test_auth(
        idp, post_logout_redirect_uri="https://app.test/", resources=RESOURCES
    )
    yield client
    await client.http.aclose()


def query_of(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(url).query)


def callback_url(handshake: LoginHandshake, extra: str = "") -> str:
    return f"{REDIRECT_URI}?code=abc&state={handshake.state}&iss={quote(ISSUER, safe='')}{extra}"


def respond_with_tokens(idp: MockIdp, handshake: LoginHandshake, **claims: Any) -> None:
    id_token = idp.id_token(
        **{
            "nonce": handshake.nonce,
            "sid": "sid-1",
            "roles": ["editor"],
            "features": {"maxProjects": 10},
            **claims,
        }
    )
    idp.token_handler = lambda _request: json_response(
        {
            "access_token": "access-1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-1",
            "scope": "openid roles",
            "id_token": id_token,
        }
    )


def bearer_token_response(**extra: Any) -> httpx2.Response:
    return json_response({"access_token": "a", "token_type": "Bearer", "expires_in": 60, **extra})


async def expect_error(awaitable: Any, code: str) -> AuthAiError:
    with pytest.raises(AuthAiError) as excinfo:
        await awaitable
    assert excinfo.value.code == code
    return excinfo.value


class TestStartLogin:
    async def test_builds_a_pkce_authorization_url_requesting_every_resource(
        self, auth: AuthClient
    ) -> None:
        request = await auth.start_login(prompt="login")
        params = query_of(request.url)

        assert request.url.startswith(f"{ISSUER}/authorize?")
        assert params["client_id"] == [CLIENT_ID]
        assert params["response_type"] == ["code"]
        assert params["redirect_uri"] == [REDIRECT_URI]
        assert "offline_access" in params["scope"][0]
        assert params["state"] == [request.handshake.state]
        assert params["nonce"] == [request.handshake.nonce]
        assert params["prompt"] == ["login"]
        assert params["resource"] == RESOURCES
        assert params["code_challenge_method"] == ["S256"]
        digest = hashlib.sha256(request.handshake.code_verifier.encode()).digest()
        assert params["code_challenge"] == [base64.urlsafe_b64encode(digest).rstrip(b"=").decode()]

    async def test_creates_distinct_secrets_per_attempt_and_discovers_once(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        first = await auth.start_login()
        second = await auth.start_login(login_hint="a@b.c")

        assert first.handshake.state != second.handshake.state
        assert first.handshake.code_verifier != second.handshake.code_verifier
        assert query_of(second.url)["login_hint"] == ["a@b.c"]
        assert len(idp.requests_to("/.well-known/openid-configuration")) == 1

    async def test_the_handshake_does_not_leak_through_repr(self, auth: AuthClient) -> None:
        handshake = (await auth.start_login()).handshake
        text = repr(handshake)
        assert handshake.code_verifier not in text
        assert handshake.state not in text
        assert handshake.nonce not in text


class TestDiscovery:
    async def test_fails_with_oidc_001_and_retries_on_the_next_call(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.discovery_failures = 1
        await expect_error(auth.start_login(), "OIDC_001")
        assert (await auth.start_login()).url

    async def test_rejects_a_provider_without_asymmetric_signing_algorithms(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.metadata["id_token_signing_alg_values_supported"] = ["HS256"]
        await expect_error(auth.start_login(), "OIDC_001")

    async def test_rejects_a_provider_advertising_only_the_deprecated_eddsa(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.metadata["id_token_signing_alg_values_supported"] = ["EdDSA"]
        await expect_error(auth.start_login(), "OIDC_001")

    async def test_rejects_a_document_naming_another_issuer(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.metadata["issuer"] = "https://evil.test"
        await expect_error(auth.start_login(), "OIDC_001")

    async def test_rejects_a_document_without_jwks_uri(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        del idp.metadata["jwks_uri"]
        await expect_error(auth.start_login(), "OIDC_001")

    async def test_keeps_discovery_working_with_a_non_https_userinfo_endpoint(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.metadata["userinfo_endpoint"] = "http://idp.test/userinfo"

        await auth.start_login()

    async def test_rejects_a_malformed_document(self, auth: AuthClient, idp: MockIdp) -> None:
        idp.metadata.pop("token_endpoint")
        await expect_error(auth.start_login(), "OIDC_001")

    async def test_rediscovers_after_an_hour(
        self, auth: AuthClient, idp: MockIdp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await auth.start_login()
        real = __import__("time").monotonic()
        monkeypatch.setattr("auth_ai.provider.time.monotonic", lambda: real + 3601)
        await auth.start_login()
        assert len(idp.requests_to("/.well-known/openid-configuration")) == 2


class TestHandleCallback:
    async def test_exchanges_the_code_and_returns_verified_claims(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        respond_with_tokens(idp, handshake)

        result = await auth.handle_callback(callback_url(handshake), handshake)

        assert result.session_id == "sid-1"
        assert result.claims.roles == ["editor"]
        assert result.claims.features == {"maxProjects": 10}
        assert result.tokens.access_token == "access-1"
        assert result.tokens.refresh_token == "refresh-1"
        assert result.tokens.expires_at > now_seconds()
        assert result.id_token == result.tokens.id_token

        [request] = idp.requests_to("/token")
        assert request.form["grant_type"] == "authorization_code"
        assert request.form["code_verifier"] == handshake.code_verifier
        assert request.form["redirect_uri"] == REDIRECT_URI
        assert "resource" not in request.form
        scheme, encoded = request.headers["authorization"].split(" ")
        assert scheme == "Basic"
        identifier, secret = base64.b64decode(encoded).decode().split(":")
        assert (unquote(identifier), unquote(secret)) == (CLIENT_ID, CLIENT_SECRET)

    async def test_form_urlencodes_the_credentials_before_the_basic_encoding(
        self, idp: MockIdp
    ) -> None:
        client = create_test_auth(idp, client_secret="p@ss:w/rd+1")
        idp.token_handler = lambda _request: bearer_token_response()
        await client.refresh("refresh-1")
        [request] = idp.requests_to("/token")
        encoded = request.headers["authorization"].split(" ")[1]
        assert base64.b64decode(encoded).decode() == f"{CLIENT_ID}:p%40ss%3Aw%2Frd%2B1"
        await client.http.aclose()

    async def test_rejects_a_callback_carrying_another_state(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        respond_with_tokens(idp, handshake)
        forged = LoginHandshake(
            state="someone-else", nonce=handshake.nonce, code_verifier=handshake.code_verifier
        )

        err = await expect_error(auth.handle_callback(callback_url(handshake), forged), "OIDC_002")

        assert err.details == {"reason": "state_mismatch"}
        assert idp.requests_to("/token") == []

    async def test_rejects_a_callback_without_state(self, auth: AuthClient) -> None:
        handshake = (await auth.start_login()).handshake
        url = f"{REDIRECT_URI}?code=abc&iss={quote(ISSUER, safe='')}"
        await expect_error(auth.handle_callback(url, handshake), "OIDC_002")

    async def test_rejects_a_callback_without_code(self, auth: AuthClient) -> None:
        handshake = (await auth.start_login()).handshake
        url = f"{REDIRECT_URI}?state={handshake.state}&iss={quote(ISSUER, safe='')}"
        err = await expect_error(auth.handle_callback(url, handshake), "OIDC_002")
        assert err.details == {"reason": "missing_code"}

    async def test_rejects_a_repeated_parameter(self, auth: AuthClient) -> None:
        handshake = (await auth.start_login()).handshake
        url = callback_url(handshake, "&code=other")
        err = await expect_error(auth.handle_callback(url, handshake), "OIDC_002")
        assert err.details == {"reason": "repeated_parameter"}

    async def test_requires_the_issuer_when_the_provider_advertises_it(
        self, auth: AuthClient
    ) -> None:
        handshake = (await auth.start_login()).handshake
        url = f"{REDIRECT_URI}?code=abc&state={handshake.state}"
        err = await expect_error(auth.handle_callback(url, handshake), "OIDC_002")
        assert err.details == {"reason": "missing_iss"}

    async def test_accepts_a_missing_issuer_when_the_provider_does_not_advertise_it(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.metadata["authorization_response_iss_parameter_supported"] = False
        handshake = (await auth.start_login()).handshake
        respond_with_tokens(idp, handshake)
        url = f"{REDIRECT_URI}?code=abc&state={handshake.state}"
        assert (await auth.handle_callback(url, handshake)).session_id == "sid-1"

    async def test_rejects_a_callback_naming_another_issuer(self, auth: AuthClient) -> None:
        handshake = (await auth.start_login()).handshake
        url = f"{REDIRECT_URI}?code=abc&state={handshake.state}&iss=https%3A%2F%2Fevil.test"
        err = await expect_error(auth.handle_callback(url, handshake), "OIDC_002")
        assert err.details == {"reason": "iss_mismatch"}

    async def test_surfaces_an_authorization_error_from_the_provider(
        self, auth: AuthClient
    ) -> None:
        handshake = (await auth.start_login()).handshake
        url = f"{REDIRECT_URI}?error=access_denied&state={handshake.state}"
        err = await expect_error(auth.handle_callback(url, handshake), "OIDC_002")
        assert err.details == {"oauthError": "access_denied"}

    async def test_surfaces_a_token_endpoint_rejection_without_leaking_the_code(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        idp.token_handler = lambda _request: json_response(
            {"error": "invalid_grant", "error_description": "code expired"}, 400
        )

        err = await expect_error(
            auth.handle_callback(callback_url(handshake), handshake), "OIDC_003"
        )

        assert err.details == {
            "oauthError": "invalid_grant",
            "status": 400,
            "description": "code expired",
        }
        assert "abc" not in str(err.to_json())

    async def test_rejects_an_id_token_signed_by_an_unknown_key(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        now = now_seconds()
        forged = idp.sign_jwt(
            {
                "iss": ISSUER,
                "sub": "attacker",
                "aud": CLIENT_ID,
                "iat": now,
                "exp": now + 300,
                "nonce": handshake.nonce,
            },
            key=idp.generate_foreign_key(),
        )
        idp.token_handler = lambda _request: bearer_token_response(id_token=forged)
        await expect_error(auth.handle_callback(callback_url(handshake), handshake), "TOK_001")

    async def test_rejects_an_id_token_issued_for_another_audience(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        respond_with_tokens(idp, handshake, aud="another-app")
        await expect_error(auth.handle_callback(callback_url(handshake), handshake), "TOK_001")

    async def test_rejects_an_id_token_bound_to_another_nonce(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        respond_with_tokens(idp, handshake, nonce="replayed")
        await expect_error(auth.handle_callback(callback_url(handshake), handshake), "TOK_001")

    async def test_rejects_an_id_token_without_the_nonce(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        idp.token_handler = lambda _request: bearer_token_response(id_token=idp.id_token())
        await expect_error(auth.handle_callback(callback_url(handshake), handshake), "TOK_001")

    async def test_rejects_id_token_claims_of_an_unexpected_shape(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        respond_with_tokens(idp, handshake, roles="admin")
        await expect_error(auth.handle_callback(callback_url(handshake), handshake), "TOK_001")

    async def test_rejects_a_token_response_without_expires_in(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        id_token = idp.id_token(nonce=handshake.nonce)
        idp.token_handler = lambda _request: json_response(
            {"access_token": "a", "token_type": "Bearer", "id_token": id_token}
        )
        await expect_error(auth.handle_callback(callback_url(handshake), handshake), "OIDC_003")

    async def test_rejects_a_non_bearer_token_type(self, auth: AuthClient, idp: MockIdp) -> None:
        idp.token_handler = lambda _request: json_response(
            {"access_token": "a", "token_type": "mac", "expires_in": 60}
        )
        await expect_error(auth.refresh("refresh-1"), "OIDC_003")

    async def test_rejects_a_token_response_without_an_id_token(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        idp.token_handler = lambda _request: bearer_token_response()
        await expect_error(auth.handle_callback(callback_url(handshake), handshake), "OIDC_002")

    async def test_reports_no_session_id_when_the_provider_omits_sid(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        idp.token_handler = lambda _request: bearer_token_response(
            id_token=idp.id_token(nonce=handshake.nonce)
        )
        result = await auth.handle_callback(callback_url(handshake), handshake)
        assert result.session_id is None


class TestUserInfo:
    async def test_rejects_a_non_https_userinfo_endpoint(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.metadata["userinfo_endpoint"] = "http://idp.test/userinfo"

        await expect_error(auth.fetch_userinfo("access-1"), "OIDC_003")

    async def test_parses_the_standard_address_claim(self, auth: AuthClient, idp: MockIdp) -> None:
        idp.userinfo_handler = lambda _request: json_response(
            {"sub": "user-1", "address": {"locality": "Paris", "country": "FR"}}
        )

        userinfo = await auth.fetch_userinfo("access-1")

        assert userinfo.address is not None
        assert userinfo.address.locality == "Paris"
        assert userinfo.address.country == "FR"

    async def test_never_merges_security_sensitive_claims_from_userinfo(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        handshake = (await auth.start_login()).handshake
        respond_with_tokens(idp, handshake)
        idp.userinfo_handler = lambda _request: json_response(
            {
                "sub": "user-1",
                "sid": "another-session",
                "azp": "another-client",
                "email": "ada@example.com",
            }
        )

        result = await auth.handle_callback(callback_url(handshake), handshake)

        assert result.claims.sid == "sid-1"
        assert result.claims.azp is None
        assert result.claims.email == "ada@example.com"


class TestRefresh:
    async def test_narrows_to_one_resource_without_sending_a_scope(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.token_handler = lambda _request: json_response(
            {
                "access_token": "access-2",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-2",
            }
        )

        tokens = await auth.refresh("refresh-1", resource="https://llm.test")

        assert tokens.access_token == "access-2"
        assert tokens.refresh_token == "refresh-2"
        [request] = idp.requests_to("/token")
        assert request.form["grant_type"] == "refresh_token"
        assert request.form["refresh_token"] == "refresh-1"
        assert request.form["resource"] == "https://llm.test"
        assert "scope" not in request.form

    async def test_reports_an_absent_rotation_as_no_refresh_token(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.token_handler = lambda _request: bearer_token_response()
        tokens = await auth.refresh("refresh-1")
        assert tokens.refresh_token is None
        assert "resource" not in idp.requests_to("/token")[0].form

    async def test_surfaces_invalid_grant_with_its_oauth_error_code(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.token_handler = lambda _request: json_response({"error": "invalid_grant"}, 400)
        err = await expect_error(auth.refresh("stale"), "OIDC_003")
        assert (err.details or {})["oauthError"] == "invalid_grant"

    async def test_wraps_a_transport_failure(self, auth: AuthClient, idp: MockIdp) -> None:
        def fail(_request: Any) -> httpx2.Response:
            raise httpx2.ConnectError("unreachable")

        idp.token_handler = fail
        await expect_error(auth.refresh("refresh-1"), "OIDC_003")

    async def test_answers_a_non_json_error_with_its_status_only(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.token_handler = lambda _request: httpx2.Response(502, text="bad gateway")
        err = await expect_error(auth.refresh("refresh-1"), "OIDC_003")
        assert err.details == {"status": 502}

    async def test_rejects_a_success_with_an_unexpected_shape(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.token_handler = lambda _request: json_response({"access_token": 1})
        await expect_error(auth.refresh("refresh-1"), "OIDC_003")


class TestLogoutUrl:
    async def test_builds_an_rp_initiated_logout_url(self, auth: AuthClient) -> None:
        url = await auth.logout_url(id_token_hint="id.token", state="s")
        parts = urlsplit(url)
        params = parse_qs(parts.query)

        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{ISSUER}/end-session"
        assert params["id_token_hint"] == ["id.token"]
        assert params["post_logout_redirect_uri"] == ["https://app.test/"]
        assert params["client_id"] == [CLIENT_ID]
        assert params["state"] == ["s"]

    async def test_fails_when_the_provider_has_no_end_session_endpoint(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        del idp.metadata["end_session_endpoint"]
        await expect_error(auth.logout_url(), "OIDC_004")


class TestRevokeAndIntrospect:
    async def test_revokes_a_refresh_token(self, auth: AuthClient, idp: MockIdp) -> None:
        await auth.revoke("refresh-1", "refresh_token")
        [request] = idp.requests_to("/revoke")
        assert request.form["token"] == "refresh-1"
        assert request.form["token_type_hint"] == "refresh_token"

    async def test_fails_a_revocation_the_provider_rejects(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.revocation_status = 400
        await expect_error(auth.revoke("refresh-1"), "OIDC_003")

    async def test_fails_when_the_provider_has_no_revocation_endpoint(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        del idp.metadata["revocation_endpoint"]
        await expect_error(auth.revoke("t"), "OIDC_004")

    async def test_introspects_a_token(self, auth: AuthClient, idp: MockIdp) -> None:
        idp.introspection = {"active": True, "sub": "u1", "scope": "openid"}
        result = await auth.introspect("access-1", "access_token")
        assert (result.active, result.sub) == (True, "u1")
        assert idp.requests_to("/introspect")[0].form["token"] == "access-1"

    async def test_fails_on_an_introspection_of_an_unexpected_shape(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.introspection = {"sub": "u1"}
        await expect_error(auth.introspect("t"), "OIDC_003")

    async def test_fails_when_the_provider_has_no_introspection_endpoint(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        del idp.metadata["introspection_endpoint"]
        await expect_error(auth.introspect("t"), "OIDC_004")


class TestClientAuthentication:
    async def test_a_public_client_sends_no_client_authentication(self, idp: MockIdp) -> None:
        public = AuthClient(
            AuthClientConfig(issuer=ISSUER, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI),
            http_client=idp.http_client(),
        )
        idp.token_handler = lambda _request: bearer_token_response()
        await public.refresh("refresh-1")
        [request] = idp.requests_to("/token")
        assert "authorization" not in request.headers
        assert "client_secret" not in request.form
        assert request.form["client_id"] == CLIENT_ID
        await public.http.aclose()

    async def test_client_secret_post_sends_the_credentials_in_the_body(self, idp: MockIdp) -> None:
        client = create_test_auth(idp, token_endpoint_auth_method="client_secret_post")
        idp.token_handler = lambda _request: bearer_token_response()
        await client.refresh("refresh-1")
        [request] = idp.requests_to("/token")
        assert "authorization" not in request.headers
        assert request.form["client_secret"] == CLIENT_SECRET
        await client.http.aclose()


class TestVerifyIdToken:
    async def test_verifies_a_refreshed_id_token_on_demand(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        claims = await auth.verify_id_token(idp.id_token(org_id="org-1"))
        assert claims.org_id == "org-1"

    async def test_rejects_an_expired_id_token(self, auth: AuthClient, idp: MockIdp) -> None:
        now = now_seconds()
        expired = idp.id_token(iat=now - 600, exp=now - 300)
        await expect_error(auth.verify_id_token(expired), "TOK_001")

    async def test_tolerates_the_configured_clock_skew(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        now = now_seconds()
        claims = await auth.verify_id_token(idp.id_token(iat=now - 60, exp=now - 2))
        assert claims.sub == "user-1"


class TestClientCredentials:
    async def test_requests_a_machine_token_with_the_given_scope_and_resource(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.token_handler = lambda _request: json_response(
            {"access_token": "m", "token_type": "Bearer", "expires_in": 60}
        )

        tokens = await auth.client_credentials(scope="billing:read", resource="https://app.test")

        assert tokens.access_token == "m"
        assert tokens.refresh_token is None
        [request] = idp.requests_to("/token")
        assert request.form["grant_type"] == "client_credentials"
        assert request.form["scope"] == "billing:read"
        assert request.form["resource"] == "https://app.test"

    async def test_surfaces_a_rejected_client(self, auth: AuthClient, idp: MockIdp) -> None:
        idp.token_handler = lambda _request: json_response({"error": "invalid_scope"}, 400)
        err = await expect_error(auth.client_credentials(scope="wallet:debit"), "OIDC_003")
        assert (err.details or {})["oauthError"] == "invalid_scope"

    async def test_explains_a_client_authentication_challenge(
        self, auth: AuthClient, idp: MockIdp
    ) -> None:
        idp.token_handler = lambda _request: httpx2.Response(
            401, headers={"www-authenticate": 'Basic realm="token"'}
        )
        err = await expect_error(auth.client_credentials(), "OIDC_003")
        assert err.details == {"status": 401}
        assert "client_secret" in err.message

    async def test_is_refused_to_a_public_client(self, idp: MockIdp) -> None:
        public = AuthClient(
            AuthClientConfig(issuer=ISSUER, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI),
            http_client=idp.http_client(),
        )
        await expect_error(public.client_credentials(), "CFG_001")
        await public.http.aclose()


class TestVerifyJwt:
    async def test_verifies_against_the_provider_keys(self, auth: AuthClient, idp: MockIdp) -> None:
        claims = await auth.verify_jwt(idp.id_token(), audience=CLIENT_ID)
        assert claims["sub"] == "user-1"

    async def test_refetches_the_keys_for_an_unknown_kid_once_per_cooldown(
        self, auth: AuthClient, idp: MockIdp, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await auth.verify_jwt(idp.id_token(), audience=CLIENT_ID)
        assert len(idp.requests_to("/jwks")) == 1

        rotated = idp.generate_foreign_key()
        token = idp.sign_jwt(
            {"iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "exp": now_seconds() + 60},
            key=rotated,
            kid="key-2",
        )
        idp.jwks_overrides = [
            idp.private_key.as_dict(private=False, alg="ES256"),
            {**rotated.as_dict(private=False, alg="ES256"), "kid": "key-2"},
        ]

        await expect_error(auth.verify_jwt(token, audience=CLIENT_ID), "TOK_001")
        assert len(idp.requests_to("/jwks")) == 1

        real = __import__("time").monotonic()
        monkeypatch.setattr("auth_ai.jwt.time.monotonic", lambda: real + 31)
        assert (await auth.verify_jwt(token, audience=CLIENT_ID))["sub"] == "u"
        assert len(idp.requests_to("/jwks")) == 2

    async def test_rejects_a_token_of_the_wrong_type(self, auth: AuthClient, idp: MockIdp) -> None:
        token = idp.sign_jwt(
            {"iss": ISSUER, "sub": "u", "aud": CLIENT_ID, "exp": now_seconds() + 60}, typ="JWT"
        )
        await expect_error(auth.verify_jwt(token, audience=CLIENT_ID, typ="logout+jwt"), "TOK_001")

    async def test_rejects_a_token_that_is_not_a_jwt(self, auth: AuthClient) -> None:
        await expect_error(auth.verify_jwt("not-a-jwt", audience=CLIENT_ID), "TOK_001")

    async def test_reports_unavailable_keys(self, auth: AuthClient, idp: MockIdp) -> None:
        idp.metadata["jwks_uri"] = f"{ISSUER}/missing"
        await expect_error(auth.verify_jwt(idp.id_token(), audience=CLIENT_ID), "TOK_001")


class TestLifecycle:
    async def test_owns_and_closes_its_default_http_client(self) -> None:
        config = AuthClientConfig(issuer=ISSUER, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI)
        async with AuthClient(config) as client:
            assert not client.http.is_closed
        assert client.http.is_closed

    async def test_never_closes_a_client_it_was_given(self, idp: MockIdp) -> None:
        http = idp.http_client()
        config = AuthClientConfig(issuer=ISSUER, client_id=CLIENT_ID, redirect_uri=REDIRECT_URI)
        async with AuthClient(config, http_client=http):
            pass
        assert not http.is_closed
        await http.aclose()

    async def test_accepts_a_plain_mapping_and_reports_a_bad_one_as_cfg_001(self) -> None:
        client = AuthClient(
            {"issuer": ISSUER, "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI}
        )
        assert client.config.client_id == CLIENT_ID
        await client.aclose()
        with pytest.raises(AuthAiError) as excinfo:
            AuthClient({"issuer": "http://insecure"})
        assert excinfo.value.code == "CFG_001"
