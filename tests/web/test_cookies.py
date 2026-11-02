from __future__ import annotations

import pytest

from auth_ai import AuthAiError
from auth_ai.web.cookies import clear_cookie, cookie_name, parse_cookies, serialize_cookie


class TestCookieName:
    def test_adds_the_host_prefix_only_over_https(self) -> None:
        assert cookie_name("aai_session", secure=True) == "__Host-aai_session"
        assert cookie_name("aai_session", secure=False) == "aai_session"


class TestParseCookies:
    def test_reads_every_cookie_and_keeps_the_first_of_a_duplicate(self) -> None:
        cookies = parse_cookies("a=1; b=two=2;  c=3; a=other; broken")
        assert cookies == {"a": "1", "b": "two=2", "c": "3"}

    @pytest.mark.parametrize("header", [None, ""])
    def test_tolerates_a_missing_header(self, header: str | None) -> None:
        assert parse_cookies(header) == {}


class TestSerializeCookie:
    def test_builds_a_hardened_cookie(self) -> None:
        cookie = serialize_cookie(
            "__Host-aai_session", "abc.DEF-_~1", max_age_seconds=3600.9, secure=True
        )
        assert cookie == (
            "__Host-aai_session=abc.DEF-_~1; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600; Secure"
        )

    def test_omits_secure_over_plain_http_for_local_development(self) -> None:
        cookie = serialize_cookie("aai_session", "v", max_age_seconds=1, secure=False)
        assert "Secure" not in cookie

    @pytest.mark.parametrize("value", ["a;b", "a b", "a,b", 'a"b', "a\r\nSet-Cookie: x=1", "é"])
    def test_refuses_an_unsafe_value(self, value: str) -> None:
        with pytest.raises(AuthAiError) as raised:
            serialize_cookie("aai", value, max_age_seconds=1, secure=True)
        assert raised.value.code == "CFG_001"

    @pytest.mark.parametrize("name", ["a;b", "a b", "a=b", "", "__Host-"])
    def test_refuses_an_invalid_name(self, name: str) -> None:
        with pytest.raises(AuthAiError) as raised:
            serialize_cookie(name, "v", max_age_seconds=1, secure=True)
        assert raised.value.code == "CFG_001"

    def test_clears_a_cookie_by_expiring_it(self) -> None:
        assert (
            clear_cookie("aai_session", secure=False)
            == "aai_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        )

    def test_never_goes_below_zero_seconds(self) -> None:
        cookie = serialize_cookie("aai", "v", max_age_seconds=-5, secure=False)
        assert "Max-Age=0" in cookie
