from __future__ import annotations

from typing import Any

import pytest

from auth_ai import AuthAiError, AuthClient
from auth_ai.claims import AccessTokenClaims
from auth_ai.server import (
    BearerVerifier,
    VerifiedAccessToken,
    extract_bearer_token,
    require_scopes,
)
from tests.support.mock_idp import CLIENT_ID, ISSUER, MockIdp, now_seconds

AUDIENCE = "https://api.app.test"


@pytest.fixture
def verifier(auth: AuthClient) -> BearerVerifier:
    return BearerVerifier(auth, audience=AUDIENCE)


def access_token(idp: MockIdp, **overrides: Any) -> str:
    iat = now_seconds()
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "user-1",
        "aud": [AUDIENCE, "https://llm.test"],
        "azp": CLIENT_ID,
        "scope": "openid roles",
        "iat": iat,
        "exp": iat + 3600,
        "roles": ["editor"],
        "features": {"maxProjects": 10},
        **overrides,
    }
    # A None override removes the claim.
    return idp.sign_jwt({name: value for name, value in claims.items() if value is not None})


def verified_with_scopes(*scopes: str) -> VerifiedAccessToken:
    now = now_seconds()
    return VerifiedAccessToken(
        user_id="user-1",
        client_id=CLIENT_ID,
        scopes=scopes,
        audiences=(AUDIENCE,),
        claims=AccessTokenClaims(
            iss=ISSUER, sub="user-1", aud=AUDIENCE, exp=now + 3600, iat=now, azp=CLIENT_ID
        ),
    )


class TestExtractBearerToken:
    @pytest.mark.parametrize("header", ["Bearer a.b.c", "bearer a.b.c", "BEARER a.b.c"])
    def test_extracts_the_token_whatever_the_scheme_case(self, header: str) -> None:
        assert extract_bearer_token(header) == "a.b.c"

    @pytest.mark.parametrize(
        "header", [None, "", "Basic abc", "Bearer", "Bearer a b", "Token a.b.c"]
    )
    def test_rejects_a_missing_or_malformed_header(self, header: str | None) -> None:
        with pytest.raises(AuthAiError) as raised:
            extract_bearer_token(header)

        assert raised.value.code == "TOK_003"


class TestBearerVerifier:
    async def test_returns_the_user_client_scopes_and_entitlements(
        self, idp: MockIdp, verifier: BearerVerifier
    ) -> None:
        verified = await verifier.verify(access_token(idp))

        assert verified.user_id == "user-1"
        assert verified.client_id == CLIENT_ID
        assert verified.scopes == ("openid", "roles")
        assert verified.audiences == (AUDIENCE, "https://llm.test")
        assert verified.claims.roles == ["editor"]
        assert verified.claims.features == {"maxProjects": 10}

    async def test_accepts_a_single_string_audience(
        self, idp: MockIdp, verifier: BearerVerifier
    ) -> None:
        verified = await verifier.verify(access_token(idp, aud=AUDIENCE))

        assert verified.audiences == (AUDIENCE,)

    async def test_recognises_a_machine_token_by_sub_equal_to_azp(
        self, idp: MockIdp, verifier: BearerVerifier
    ) -> None:
        verified = await verifier.verify(access_token(idp, sub=CLIENT_ID, aud=AUDIENCE, scope=None))

        assert verified.user_id is None
        assert verified.scopes == ()
        assert verified.audiences == (AUDIENCE,)

    async def test_verifies_the_token_of_an_authorization_header(
        self, idp: MockIdp, verifier: BearerVerifier
    ) -> None:
        verified = await verifier.verify_header(f"Bearer {access_token(idp)}")
        assert verified.user_id == "user-1"

        with pytest.raises(AuthAiError) as raised:
            await verifier.verify_header(None)
        assert raised.value.code == "TOK_003"

    async def test_rejects_a_token_minted_for_another_audience(
        self, idp: MockIdp, verifier: BearerVerifier
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await verifier.verify(access_token(idp, aud="https://other.test"))

        assert raised.value.code == "TOK_001"

    async def test_rejects_an_expired_token(self, idp: MockIdp, verifier: BearerVerifier) -> None:
        iat = now_seconds() - 7200

        with pytest.raises(AuthAiError) as raised:
            await verifier.verify(access_token(idp, iat=iat, exp=iat + 3600))

        assert raised.value.code == "TOK_001"

    async def test_rejects_a_token_signed_by_an_unknown_key(
        self, idp: MockIdp, verifier: BearerVerifier
    ) -> None:
        forged = idp.sign_jwt(
            {
                "iss": ISSUER,
                "sub": "admin",
                "aud": AUDIENCE,
                "azp": CLIENT_ID,
                "iat": now_seconds(),
                "exp": now_seconds() + 3600,
            },
            key=idp.generate_foreign_key(),
        )

        with pytest.raises(AuthAiError) as raised:
            await verifier.verify(forged)

        assert raised.value.code == "TOK_001"

    async def test_rejects_a_token_from_another_issuer(
        self, idp: MockIdp, verifier: BearerVerifier
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await verifier.verify(access_token(idp, iss="https://evil.test"))

        assert raised.value.code == "TOK_001"

    async def test_rejects_a_token_bound_to_no_client(
        self, idp: MockIdp, verifier: BearerVerifier
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await verifier.verify(access_token(idp, azp=None))

        assert raised.value.code == "TOK_001"

    async def test_rejects_an_opaque_token_without_calling_the_provider(
        self, idp: MockIdp, verifier: BearerVerifier
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await verifier.verify("opaque-token")

        assert raised.value.code == "TOK_001"
        assert idp.requests == []

    def test_refuses_a_malformed_audience_at_construction(self, auth: AuthClient) -> None:
        with pytest.raises(AuthAiError) as raised:
            BearerVerifier(auth, audience="api")

        assert raised.value.code == "CFG_001"


class TestRequireScopes:
    def test_passes_when_every_scope_is_present(self) -> None:
        require_scopes(verified_with_scopes("a", "b"), "a", "b")

    def test_names_the_missing_scopes(self) -> None:
        with pytest.raises(AuthAiError) as raised:
            require_scopes(verified_with_scopes("a"), "a", "b", "c")

        assert raised.value.code == "TOK_004"
        assert raised.value.details == {"missing": "b c"}
