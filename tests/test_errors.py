from __future__ import annotations

import pytest

from auth_ai import ERR, AuthAiError, is_auth_ai_error_code
from auth_ai.errors import DEFAULT_MESSAGES


def test_serialises_code_and_message_without_details_by_default() -> None:
    err = ERR.CFG_001()

    assert isinstance(err, Exception)
    assert isinstance(err, AuthAiError)
    assert err.to_json() == {"code": "CFG_001", "message": "Invalid SDK configuration"}


def test_keeps_custom_message_details_and_cause() -> None:
    cause = ValueError("root")

    err = ERR.CFG_001("issuer must be https", details={"field": "issuer"}, cause=cause)

    assert err.message == "issuer must be https"
    assert str(err) == "issuer must be https"
    assert err.code == "CFG_001"
    assert err.details == {"field": "issuer"}
    assert err.__cause__ is cause
    assert err.to_json() == {
        "code": "CFG_001",
        "message": "issuer must be https",
        "details": {"field": "issuer"},
    }


def test_omits_empty_details_from_json() -> None:
    assert "details" not in ERR.API_001("rejected", details={}).to_json()


def test_public_json_never_exposes_the_developer_message_or_details() -> None:
    err = ERR.API_001(
        "invalid_grant: the refresh token abc was revoked", details={"scope": "wallet:self:read"}
    )

    assert err.to_public_json() == {
        "code": "API_001",
        "message": "auth-service rejected the request",
    }


def test_registry_covers_every_code_with_its_default_message() -> None:
    assert len(DEFAULT_MESSAGES) == 23
    for code, message in DEFAULT_MESSAGES.items():
        err = getattr(ERR, code)()
        assert isinstance(err, AuthAiError)
        assert err.code == code
        assert err.message == message
        assert err.details is None


@pytest.mark.parametrize(
    ("code", "message"),
    [
        ("GW_001", "Insufficient credit: the wallet cannot pay for this call"),
        ("SES_001", "Not signed in"),
        ("TOK_002", "No usable grant for this user: sign in again"),
    ],
)
def test_default_messages(code: str, message: str) -> None:
    assert getattr(ERR, code)().message == message


def test_recognises_registered_codes_only() -> None:
    assert is_auth_ai_error_code("CFG_001")
    assert is_auth_ai_error_code("SRV_001")
    assert not is_auth_ai_error_code("CFG_999")
    assert not is_auth_ai_error_code("")
    assert not is_auth_ai_error_code(None)
    assert not is_auth_ai_error_code(1)
    assert not is_auth_ai_error_code("__class__")
