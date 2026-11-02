from __future__ import annotations

import pytest
from pydantic import ValidationError

from auth_ai import (
    AccessTokenClaims,
    FeatureValue,
    IdTokenClaims,
    get_feature,
    has_feature,
    has_permission,
    has_role,
    to_session_user,
)

BASE = {"iss": "https://idp", "sub": "u1", "aud": "app", "exp": 2, "iat": 1}


class Entitlements:
    def __init__(
        self,
        roles: list[str] | None = None,
        permissions: list[str] | None = None,
        features: dict[str, FeatureValue] | None = None,
    ) -> None:
        self.roles = roles
        self.permissions = permissions
        self.features = features


FULL = Entitlements(
    roles=["editor"],
    permissions=["reports", "documents.write"],
    features={"maxProjects": 10, "apiAccess": False, "beta": True, "empty": "", "zero": 0},
)
EMPTY = Entitlements()


class TestIdTokenClaims:
    def test_parses_entitlement_claims_and_keeps_unknown_ones(self) -> None:
        claims = IdTokenClaims.model_validate(
            {
                **BASE,
                "sid": "s1",
                "roles": ["editor"],
                "permissions": ["documents.write"],
                "features": {"maxProjects": 10, "apiAccess": True, "tier": "gold"},
                "plan": "Premium",
                "org_id": "org-1",
                "custom": "kept",
            }
        )

        assert claims.org_id == "org-1"
        assert claims.sid == "s1"
        assert claims.features == {"maxProjects": 10, "apiAccess": True, "tier": "gold"}
        assert claims.model_extra == {"custom": "kept"}

    def test_accepts_an_audience_list(self) -> None:
        claims = IdTokenClaims.model_validate({**BASE, "aud": ["app", "https://llm.test"]})

        assert claims.aud == ["app", "https://llm.test"]

    def test_rejects_a_nested_feature_value(self) -> None:
        with pytest.raises(ValidationError):
            IdTokenClaims.model_validate({**BASE, "features": {"a": {"b": 1}}})

    def test_rejects_claims_without_a_subject(self) -> None:
        without_sub = {key: value for key, value in BASE.items() if key != "sub"}

        with pytest.raises(ValidationError):
            IdTokenClaims.model_validate(without_sub)


class TestAccessTokenClaims:
    def test_requires_the_authorised_party(self) -> None:
        with pytest.raises(ValidationError):
            AccessTokenClaims.model_validate(BASE)

    def test_parses_scope_and_authorised_party(self) -> None:
        claims = AccessTokenClaims.model_validate({**BASE, "azp": "app", "scope": "openid roles"})

        assert claims.azp == "app"
        assert claims.scope == "openid roles"


class TestEntitlementHelpers:
    def test_checks_roles(self) -> None:
        assert has_role(FULL, "editor")
        assert not has_role(FULL, "admin")
        assert not has_role(EMPTY, "editor")

    def test_treats_write_as_implying_read(self) -> None:
        assert has_permission(FULL, "reports")
        assert not has_permission(FULL, "reports", "write")
        assert has_permission(FULL, "documents", "write")
        assert has_permission(FULL, "documents")
        assert not has_permission(FULL, "billing")
        assert not has_permission(EMPTY, "reports")

    def test_enables_a_feature_unless_absent_false_zero_or_empty(self) -> None:
        assert has_feature(FULL, "beta")
        assert has_feature(FULL, "maxProjects")
        assert not has_feature(FULL, "apiAccess")
        assert not has_feature(FULL, "empty")
        assert not has_feature(FULL, "zero")
        assert not has_feature(FULL, "missing")
        assert not has_feature(EMPTY, "beta")

    def test_reads_a_feature_value(self) -> None:
        assert get_feature(FULL, "maxProjects") == 10
        assert get_feature(FULL, "missing") is None

    def test_helpers_accept_parsed_claims(self) -> None:
        claims = IdTokenClaims.model_validate(
            {**BASE, "roles": ["editor"], "permissions": ["reports"], "features": {"beta": True}}
        )

        assert has_role(claims, "editor")
        assert has_permission(claims, "reports")
        assert has_feature(claims, "beta")


class TestSessionUser:
    def test_exposes_profile_and_entitlements_in_camel_case(self) -> None:
        claims = IdTokenClaims.model_validate(
            {
                **BASE,
                "sid": "s1",
                "name": "Ada",
                "email": "ada@example.com",
                "email_verified": True,
                "picture": "https://img.test/ada.png",
                "roles": ["editor"],
                "permissions": ["reports"],
                "features": {"beta": True},
                "plan": "Premium",
                "org_id": "org-1",
                "company": "Analytical",
            }
        )

        assert to_session_user(claims).to_json() == {
            "sub": "u1",
            "name": "Ada",
            "email": "ada@example.com",
            "emailVerified": True,
            "picture": "https://img.test/ada.png",
            "roles": ["editor"],
            "permissions": ["reports"],
            "features": {"beta": True},
            "plan": "Premium",
            "orgId": "org-1",
        }

    def test_normalises_absent_entitlements_to_empty_values(self) -> None:
        user = to_session_user(IdTokenClaims.model_validate(BASE))

        assert user.roles == []
        assert user.permissions == []
        assert user.features == {}
        assert user.to_json() == {"sub": "u1", "roles": [], "permissions": [], "features": {}}

    def test_never_leaks_tokens_session_id_or_timestamps(self) -> None:
        claims = IdTokenClaims.model_validate({**BASE, "sid": "s1", "azp": "app", "nonce": "n"})

        serialised = to_session_user(claims).to_json()

        assert set(serialised) == {"sub", "roles", "permissions", "features"}
