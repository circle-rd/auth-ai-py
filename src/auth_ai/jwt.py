from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

import httpx2
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jws import extract_compact

from .errors import ERR

if TYPE_CHECKING:
    from collections.abc import Sequence

# Re-fetch an unknown `kid` (key rotation) at most once per cooldown.
JWKS_COOLDOWN_SECONDS: Final = 30.0
JWKS_UNKNOWN_KID_COOLDOWN_SECONDS: Final = 1.0
JWKS_MAX_AGE_SECONDS: Final = 3600.0


@dataclass(frozen=True, slots=True)
class VerifiedJwt:
    header: dict[str, Any]
    claims: dict[str, Any]


class RemoteJwks:
    """A JWKS fetched over HTTP and cached: unknown `kid` values refresh it, rate-limited."""

    def __init__(
        self,
        uri: str,
        http: httpx2.AsyncClient,
        timeout_seconds: float,
        algorithms: Sequence[str],
    ) -> None:
        self._uri = uri
        self._http = http
        self._timeout = timeout_seconds
        self._algorithms = frozenset(algorithms)
        self._keys: KeySet | None = None
        self._loaded_at = 0.0
        self._last_unknown_kid_refresh = 0.0
        self._lock = asyncio.Lock()

    async def get(self, kid: str | None) -> KeySet:
        keys = self._keys
        if kid is not None and keys is not None and self._is_fresh() and self._has(keys, kid):
            return keys
        async with self._lock:
            keys = self._keys
            if kid is not None and keys is not None and self._is_fresh() and self._has(keys, kid):
                return keys
            now = time.monotonic()
            stale = keys is None or now - self._loaded_at >= JWKS_MAX_AGE_SECONDS
            unknown_kid = kid is None or (keys is not None and not self._has(keys, kid))
            refresh_unknown = (
                unknown_kid
                and now - self._last_unknown_kid_refresh >= JWKS_UNKNOWN_KID_COOLDOWN_SECONDS
            )
            if stale or refresh_unknown or now - self._loaded_at >= JWKS_COOLDOWN_SECONDS:
                keys = await self._fetch()
                if refresh_unknown:
                    self._last_unknown_kid_refresh = time.monotonic()
            if keys is None:
                raise ERR.TOK_001("The identity provider's keys are unavailable")
            return keys

    def _is_fresh(self) -> bool:
        return time.monotonic() - self._loaded_at < JWKS_MAX_AGE_SECONDS

    @staticmethod
    def _has(keys: KeySet, kid: str | None) -> bool:
        return kid is None or any(key.kid == kid for key in keys.keys)

    def _supports_algorithm(self, key: dict[str, Any]) -> bool:
        if key.get("use") not in {None, "sig"}:
            return False
        if key.get("alg") is not None and key.get("alg") not in self._algorithms:
            return False
        for algorithm in self._algorithms:
            if algorithm.startswith(("RS", "PS")) and key.get("kty") == "RSA":
                return True
            if algorithm == "ES256" and key.get("kty") == "EC" and key.get("crv") == "P-256":
                return True
            if algorithm == "ES384" and key.get("kty") == "EC" and key.get("crv") == "P-384":
                return True
            if algorithm == "ES512" and key.get("kty") == "EC" and key.get("crv") == "P-521":
                return True
            if (
                algorithm == "EdDSA"
                and key.get("kty") == "OKP"
                and key.get("crv") in {"Ed25519", "Ed448"}
            ):
                return True
        return False

    async def _fetch(self) -> KeySet:
        try:
            response = await self._http.get(
                self._uri,
                headers={"accept": "application/json"},
                timeout=self._timeout,
            )
            response.raise_for_status()
            document = response.json()
            if isinstance(document, dict) and isinstance(document.get("keys"), list):
                document = {
                    **document,
                    "keys": [
                        key
                        for key in document["keys"]
                        if isinstance(key, dict) and self._supports_algorithm(key)
                    ],
                }
            keys = KeySet.import_key_set(document)
        except (httpx2.HTTPError, ValueError, JoseError) as err:
            raise ERR.TOK_001("Fetching the provider's keys failed", cause=err) from err
        self._keys = keys
        self._loaded_at = time.monotonic()
        return keys


def _normalise_typ(value: object) -> str:
    text = value.lower() if isinstance(value, str) else ""
    return text.removeprefix("application/")


class JwtVerifier:
    """Verifies the signature, issuer, audience and expiry of a JWT of the provider.

    The accepted algorithms are pinned to the ones the provider declares: `none`
    and HMAC never qualify.
    """

    def __init__(
        self,
        *,
        issuer: str,
        jwks: RemoteJwks,
        algorithms: Sequence[str],
        clock_tolerance_seconds: int,
    ) -> None:
        self._issuer = issuer
        self._jwks = jwks
        self._algorithms = list(algorithms)
        self._leeway = clock_tolerance_seconds

    async def verify(self, token: str, *, audience: str, typ: str | None = None) -> VerifiedJwt:
        try:
            kid = extract_compact(token.encode()).headers().get("kid")
            keys = await self._jwks.get(kid if isinstance(kid, str) else None)
            decoded = jwt.decode(token, keys, algorithms=self._algorithms)
            jwt.JWTClaimsRegistry(
                leeway=self._leeway,
                iss={"essential": True, "value": self._issuer},
                aud={"essential": True, "value": audience},
                sub={"essential": True},
                exp={"essential": True},
            ).validate(decoded.claims)
            if typ is not None and _normalise_typ(decoded.header.get("typ")) != _normalise_typ(typ):
                raise ERR.TOK_001("Unexpected token type")
        except JoseError as err:
            raise ERR.TOK_001(
                f"Token verification failed: {err.error}",
                details={"reason": err.error},
                cause=err,
            ) from err
        return VerifiedJwt(header=dict(decoded.header), claims=dict(decoded.claims))
