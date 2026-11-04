from __future__ import annotations

import httpx2


def build_http_client(
    *,
    timeout_seconds: float,
    transport: httpx2.AsyncBaseTransport | None = None,
    auth: httpx2.Auth | None = None,
) -> httpx2.AsyncClient:
    """The HTTP client every call of the SDK uses.

    HTTP/2 is negotiated over TLS (ALPN) and HTTP/1.1 is the fallback. Responses are
    decompressed from gzip, brotli and zstd when the runtime offers them. Redirects are
    never followed: a redirect from the identity provider or the gateway is refused.
    The caller owns the returned client and closes it.
    """
    return httpx2.AsyncClient(
        http2=True,
        timeout=timeout_seconds,
        transport=transport,
        auth=auth,
        follow_redirects=False,
    )
