from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

import httpx2

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

NO_STORE: Final = "no-store"


@dataclass(frozen=True, slots=True)
class WebRequest:
    """The framework-agnostic view of an incoming HTTP request.

    Adapters build it from their own request type. `url` is absolute: the SDK
    only reads its path and query, never trusts its host.
    """

    method: str
    url: str
    headers: httpx2.Headers = field(default_factory=httpx2.Headers)
    body: bytes = b""

    @classmethod
    def create(
        cls,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
        body: bytes = b"",
    ) -> WebRequest:
        return cls(method.upper(), url, httpx2.Headers(headers), body)

    def header(self, name: str) -> str | None:
        value: str | None = self.headers.get(name)
        return value


@dataclass(frozen=True, slots=True)
class WebResponse:
    """A response the SDK asks the framework adapter to send.

    Headers are a list of pairs: `Set-Cookie` may appear several times.
    """

    status: int
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""

    def header(self, name: str) -> str | None:
        values = self.header_values(name)
        return values[0] if values else None

    def header_values(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for key, value in self.headers if key.lower() == lowered]

    def json(self) -> Any:  # noqa: ANN401
        return json.loads(self.body)


def json_response(
    body: object,
    status: int = 200,
    headers: Iterable[tuple[str, str]] = (),
) -> WebResponse:
    return WebResponse(
        status,
        (
            *headers,
            ("content-type", "application/json"),
            ("cache-control", NO_STORE),
        ),
        json.dumps(body, separators=(",", ":")).encode(),
    )


def redirect_response(
    location: str, status: int, headers: Iterable[tuple[str, str]] = ()
) -> WebResponse:
    return WebResponse(status, (*headers, ("location", location), ("cache-control", NO_STORE)))
