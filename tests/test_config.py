from __future__ import annotations

import pytest

from auth_ai import DEFAULT_SCOPES, WALLET_SELF_SCOPE, AuthAiError, AuthClientConfig

VALID: dict[str, object] = {
    "issuer": "https://auth.example.com",
    "client_id": "my-app",
    "redirect_uri": "https://app.example.com/callback",
}
GATEWAY_URL = "https://llm.example.com"


def parse(**overrides: object) -> AuthClientConfig:
    return AuthClientConfig.model_validate({**VALID, **overrides})


def rejection(input_: dict[str, object]) -> AuthAiError:
    with pytest.raises(AuthAiError) as caught:
        AuthClientConfig.model_validate(input_)
    return caught.value


class TestAuthClientConfig:
    def test_applies_the_documented_defaults(self) -> None:
        config = parse()

        assert config.scopes == DEFAULT_SCOPES
        assert config.resources == ()
        assert config.token_endpoint_auth_method == "client_secret_basic"
        assert config.clock_tolerance_seconds == 5
        assert config.timeout_seconds == 10
        assert config.client_secret is None

    def test_accepts_an_http_redirect_uri_on_loopback_only(self) -> None:
        assert (
            parse(redirect_uri="http://localhost:3000/callback").redirect_uri
            == "http://localhost:3000/callback"
        )
        err = rejection({**VALID, "redirect_uri": "http://app.example.com/callback"})
        assert err.code == "CFG_001"

    def test_accepts_path_based_issuer_with_trailing_slash(self) -> None:
        issuer = "https://www.certification.openid.net/test/a/rp-py-basic/"
        assert parse(issuer=issuer).issuer == issuer

    @pytest.mark.parametrize(
        ("label", "override"),
        [
            ("an http issuer", {"issuer": "http://auth.example.com"}),
            ("an issuer with a query", {"issuer": "https://auth.example.com?tenant=1"}),
            ("an issuer with a fragment", {"issuer": "https://auth.example.com#tenant"}),
            ("scopes without openid", {"scopes": ["profile"]}),
            ("a non-URL resource", {"resources": ["not a url"]}),
            ("a non-URL redirect URI", {"redirect_uri": "not a url"}),
            ("an empty client id", {"client_id": ""}),
            ("an unknown auth method", {"token_endpoint_auth_method": "none"}),
            ("an unknown option", {"clientId": "typo"}),
        ],
    )
    def test_rejects(self, label: str, override: dict[str, object]) -> None:
        err = rejection({**VALID, **override})

        assert err.code == "CFG_001"
        assert next(iter(override)) in err.message

    def test_names_every_missing_field_and_never_echoes_the_secret(self) -> None:
        err = rejection({"client_secret": "super-secret-value"})

        assert err.code == "CFG_001"
        assert "issuer" in err.message
        assert "client_id" in err.message
        assert "redirect_uri" in err.message
        assert "super-secret-value" not in err.message

    def test_does_not_expose_the_secret_in_repr(self) -> None:
        config = parse(client_secret="super-secret-value")

        assert "super-secret-value" not in repr(config)
        assert config.client_secret is not None
        assert config.client_secret.get_secret_value() == "super-secret-value"

    def test_rejects_an_empty_secret(self) -> None:
        assert rejection({**VALID, "client_secret": ""}).code == "CFG_001"


class TestGatewayUrl:
    def test_adds_the_gateway_and_auth_service_audiences_and_the_wallet_scope(self) -> None:
        config = parse(resources=["https://app.example.com"], gateway_url=GATEWAY_URL)

        assert config.resources == ("https://app.example.com", GATEWAY_URL, VALID["issuer"])
        assert WALLET_SELF_SCOPE in config.scopes
        assert config.scopes == (*DEFAULT_SCOPES, WALLET_SELF_SCOPE)

    def test_does_not_duplicate_what_the_application_already_listed(self) -> None:
        config = parse(
            resources=[GATEWAY_URL, VALID["issuer"]],
            scopes=["openid", WALLET_SELF_SCOPE],
            gateway_url=GATEWAY_URL,
        )

        assert config.resources == (GATEWAY_URL, VALID["issuer"])
        assert config.scopes == ("openid", WALLET_SELF_SCOPE)

    def test_applies_to_a_config_built_with_keyword_arguments(self) -> None:
        config = AuthClientConfig(
            issuer="https://auth.example.com",
            client_id="my-app",
            redirect_uri="https://app.example.com/callback",
            gateway_url=GATEWAY_URL,
        )

        assert config.resources == (GATEWAY_URL, "https://auth.example.com")
        assert config.scopes == (*DEFAULT_SCOPES, WALLET_SELF_SCOPE)

    def test_leaves_scopes_and_resources_alone_without_a_gateway(self) -> None:
        config = parse()

        assert WALLET_SELF_SCOPE not in config.scopes
        assert config.resources == ()
        assert config.gateway_url is None

    @pytest.mark.parametrize("value", ["https://llm.example.com/", "ftp://llm.example.com", "llm"])
    def test_rejects(self, value: str) -> None:
        assert rejection({**VALID, "gateway_url": value}).code == "CFG_001"

    def test_accepts_a_loopback_gateway_over_http_for_local_development(self) -> None:
        assert parse(gateway_url="http://localhost:4000").gateway_url == "http://localhost:4000"
