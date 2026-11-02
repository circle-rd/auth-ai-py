from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from auth_ai import ERR, AuthAiError
from auth_ai.messages import WebRequest, redirect_response
from auth_ai.web.http import error_response, is_cross_site, safe_redirect_path

ORIGIN = "https://app.test"


class TestSafeRedirectPath:
    @pytest.mark.parametrize("path", ["/dashboard", "/a/b?x=1&y=2#top", "/"])
    def test_keeps_a_same_origin_path(self, path: str) -> None:
        assert safe_redirect_path(path, "/fallback") == path

    @pytest.mark.parametrize(
        "candidate",
        [
            None,
            "",
            "dashboard",
            "//evil.test",
            "//evil.test/path",
            "https://evil.test",
            "javascript:alert(1)",
            "/\\evil.test",
            "/\t/evil.test",
            "/%0d%0aSet-Cookie:x=1/\r\n",
            "/a\nb",
            "/\u007f",
        ],
    )
    def test_falls_back_for_anything_else(self, candidate: str | None) -> None:
        assert safe_redirect_path(candidate, "/fallback") == "/fallback"

    def test_does_not_let_an_encoded_slash_pair_escape_the_origin(self) -> None:
        result = safe_redirect_path("/%2F%2Fevil.test", "/fallback")
        assert urlsplit(f"{ORIGIN}{result}").netloc == "app.test"


class TestIsCrossSite:
    @staticmethod
    def request(headers: dict[str, str]) -> WebRequest:
        return WebRequest.create("POST", f"{ORIGIN}/auth/logout", headers=headers)

    def test_accepts_the_same_origin(self) -> None:
        assert not is_cross_site(self.request({"origin": ORIGIN}), ORIGIN)

    def test_refuses_another_origin_even_when_sec_fetch_site_says_same_origin(self) -> None:
        request = self.request({"origin": "https://evil.test", "sec-fetch-site": "same-origin"})
        assert is_cross_site(request, ORIGIN)

    @pytest.mark.parametrize(
        ("site", "cross"),
        [("cross-site", True), ("same-site", True), ("same-origin", False), ("none", False)],
    )
    def test_falls_back_on_sec_fetch_site_without_an_origin(self, site: str, cross: bool) -> None:
        assert is_cross_site(self.request({"sec-fetch-site": site}), ORIGIN) is cross

    def test_lets_non_browser_clients_through(self) -> None:
        assert not is_cross_site(self.request({}), ORIGIN)


class TestErrorResponse:
    def test_serialises_an_sdk_error_with_its_status(self) -> None:
        response = error_response(ERR.SES_001(), None)
        assert response.status == 401
        assert response.header("cache-control") == "no-store"
        assert response.header("content-type") == "application/json"
        assert response.json() == {"error": {"code": "SES_001", "message": "Not signed in"}}

    @pytest.mark.parametrize(
        ("err", "status"),
        [
            (ERR.SES_002(), 400),
            (ERR.SES_004(), 403),
            (ERR.TOK_001(), 401),
            (ERR.OIDC_003(), 502),
            (ERR.CFG_001(), 500),
        ],
    )
    def test_maps_a_code_to_an_http_status(self, err: AuthAiError, status: int) -> None:
        assert error_response(err, None).status == status

    def test_never_echoes_the_detailed_message_or_the_details_of_an_sdk_error(self) -> None:
        err = ERR.OIDC_003(
            "Token endpoint rejected: invalid_grant (session abc)",
            details={"oauthError": "invalid_grant", "description": "session abc"},
        )
        response = error_response(err, None)
        assert "abc" not in response.body.decode()
        assert response.json() == {"error": {"code": "OIDC_003", "message": "Token request failed"}}

    def test_hides_an_unexpected_failure_and_reports_it(self) -> None:
        reported: list[BaseException] = []
        failure = RuntimeError("db password hunter2")
        response = error_response(failure, reported.append)
        assert response.status == 500
        assert "hunter2" not in response.body.decode()
        assert response.json() == {"error": {"code": "SRV_001", "message": "Internal error"}}
        assert reported == [failure]

    def test_does_not_report_a_client_side_sdk_error(self) -> None:
        reported: list[BaseException] = []
        error_response(ERR.SES_001(), reported.append)
        assert reported == []

    def test_reports_a_server_side_sdk_error_with_its_details(self) -> None:
        reported: list[BaseException] = []
        err = ERR.OIDC_001("Discovery failed: connection refused")
        response = error_response(err, reported.append)
        assert response.status == 502
        assert "refused" not in response.body.decode()
        assert reported == [err]

    def test_keeps_the_given_headers_apart(self) -> None:
        headers = [("set-cookie", "a=1"), ("set-cookie", "b=2")]
        response = error_response(ERR.SES_001(), None, headers)
        assert response.header_values("set-cookie") == ["a=1", "b=2"]


class TestRedirectResponse:
    def test_sets_the_location_and_forbids_caching(self) -> None:
        response = redirect_response("/next", 303)
        assert response.status == 303
        assert response.header("location") == "/next"
        assert response.header("cache-control") == "no-store"
