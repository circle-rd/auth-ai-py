from __future__ import annotations

import pytest

from auth_ai import AuthAiError
from auth_ai.id_token import check_id_token_binding

CLIENT_ID = "test-app"


def check(claims: dict[str, object], nonce: str | None = "n-1") -> None:
    check_id_token_binding(claims, client_id=CLIENT_ID, nonce=nonce)


def reason_of(claims: dict[str, object], nonce: str | None = "n-1") -> str:
    with pytest.raises(AuthAiError) as excinfo:
        check(claims, nonce)
    assert excinfo.value.code == "TOK_001"
    return str((excinfo.value.details or {})["reason"])


class TestNonce:
    def test_accepts_the_nonce_sent_at_sign_in(self) -> None:
        check({"aud": CLIENT_ID, "nonce": "n-1"})

    def test_rejects_another_nonce(self) -> None:
        assert reason_of({"aud": CLIENT_ID, "nonce": "replayed"}) == "nonce_mismatch"

    def test_rejects_a_missing_nonce_when_one_was_sent(self) -> None:
        assert reason_of({"aud": CLIENT_ID}) == "missing_nonce"

    def test_rejects_a_non_string_nonce(self) -> None:
        assert reason_of({"aud": CLIENT_ID, "nonce": 1}) == "missing_nonce"

    def test_does_not_require_a_nonce_when_none_was_sent(self) -> None:
        check({"aud": CLIENT_ID}, nonce=None)

    def test_compares_non_ascii_values_without_raising(self) -> None:
        assert reason_of({"aud": CLIENT_ID, "nonce": "é"}) == "nonce_mismatch"


class TestAuthorizedParty:
    def test_accepts_a_sole_audience_without_azp(self) -> None:
        check({"aud": CLIENT_ID, "nonce": "n-1"})
        check({"aud": [CLIENT_ID], "nonce": "n-1"})

    def test_accepts_azp_naming_this_client(self) -> None:
        check({"aud": [CLIENT_ID, "https://llm.test"], "azp": CLIENT_ID, "nonce": "n-1"})

    def test_requires_azp_when_there_are_several_audiences(self) -> None:
        claims: dict[str, object] = {"aud": [CLIENT_ID, "https://llm.test"], "nonce": "n-1"}
        assert reason_of(claims) == "missing_azp"

    def test_rejects_azp_naming_another_client(self) -> None:
        assert reason_of({"aud": CLIENT_ID, "azp": "other", "nonce": "n-1"}) == "azp_mismatch"
