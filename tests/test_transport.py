from __future__ import annotations

import gzip
from collections.abc import Callable

import brotli
import httpx2
import pytest

from auth_ai import build_http_client


class TestBuildHttpClient:
    def test_negotiates_http2_and_refuses_redirects(self) -> None:
        client = build_http_client(timeout_seconds=5)

        assert client.follow_redirects is False
        assert client._transport._pool._http2 is True  # type: ignore[attr-defined]

    def test_advertises_gzip_and_brotli_responses(self) -> None:
        client = build_http_client(timeout_seconds=5)

        accepted = {item.strip() for item in client.headers["accept-encoding"].split(",")}
        assert {"gzip", "br"} <= accepted

    def test_applies_the_timeout_and_the_auth_it_is_given(self) -> None:
        auth = httpx2.BasicAuth("user", "secret")

        client = build_http_client(timeout_seconds=7, auth=auth)

        assert client.timeout == httpx2.Timeout(7)
        assert client.auth is auth

    @pytest.mark.parametrize(
        ("encoding", "encode"),
        [("gzip", gzip.compress), ("br", brotli.compress)],
    )
    async def test_decodes_compressed_responses(
        self, encoding: str, encode: Callable[[bytes], bytes]
    ) -> None:
        body = encode(b'{"issuer":"https://auth.test"}')

        def handler(_request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(
                200,
                headers={"content-encoding": encoding, "content-type": "application/json"},
                content=body,
            )

        client = build_http_client(timeout_seconds=5, transport=httpx2.MockTransport(handler))
        async with client:
            response = await client.get("https://auth.test/.well-known/openid-configuration")

        assert response.json() == {"issuer": "https://auth.test"}
