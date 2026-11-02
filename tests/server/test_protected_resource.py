from __future__ import annotations

import pytest

from auth_ai import AuthAiError, AuthClient
from auth_ai.server import (
    bearer_challenge,
    protected_resource_metadata,
    protected_resource_metadata_path,
)
from tests.support.mock_idp import ISSUER

RESOURCE_METADATA_URL = "https://app.test/.well-known/oauth-protected-resource"


class TestProtectedResourceMetadata:
    def test_points_at_the_provider_as_authorization_server(self, auth: AuthClient) -> None:
        metadata = protected_resource_metadata(
            auth, resource="https://api.app.test", scopes_supported=["openid", "roles"]
        )

        assert metadata == {
            "resource": "https://api.app.test",
            "authorization_servers": [ISSUER],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["openid", "roles"],
        }

    def test_omits_scopes_when_none_are_declared(self, auth: AuthClient) -> None:
        metadata = protected_resource_metadata(auth, resource="https://api.app.test")

        assert "scopes_supported" not in metadata


class TestProtectedResourceMetadataPath:
    @pytest.mark.parametrize(
        ("resource", "path"),
        [
            ("https://api.app.test", "/.well-known/oauth-protected-resource"),
            ("https://api.app.test/", "/.well-known/oauth-protected-resource"),
            ("https://app.test/api/v1", "/.well-known/oauth-protected-resource/api/v1"),
        ],
    )
    def test_inserts_the_well_known_segment_before_the_resource_path(
        self, resource: str, path: str
    ) -> None:
        assert protected_resource_metadata_path(resource) == path


class TestBearerChallenge:
    def test_advertises_the_metadata_document(self) -> None:
        assert (
            bearer_challenge(RESOURCE_METADATA_URL)
            == f'Bearer resource_metadata="{RESOURCE_METADATA_URL}"'
        )

    def test_adds_the_error_and_scope(self) -> None:
        challenge = bearer_challenge(
            RESOURCE_METADATA_URL, error="insufficient_scope", scope="billing:read"
        )

        assert challenge == (
            f'Bearer resource_metadata="{RESOURCE_METADATA_URL}", '
            'error="insufficient_scope", scope="billing:read"'
        )

    @pytest.mark.parametrize("unsafe", ['a", error="none', "a\\b", "a\r\nX-Injected: 1"])
    def test_refuses_a_value_that_would_break_out_of_the_header(self, unsafe: str) -> None:
        with pytest.raises(AuthAiError) as raised:
            bearer_challenge(RESOURCE_METADATA_URL, scope=unsafe)

        assert raised.value.code == "CFG_001"
