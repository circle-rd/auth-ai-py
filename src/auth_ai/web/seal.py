from __future__ import annotations

import hashlib
import time
from typing import Final

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OctKey
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from ..errors import ERR

MIN_SECRET_LENGTH: Final = 32
_ALGORITHMS: Final = ["dir", "A256GCM"]


def derive_seal_key(secret: str) -> OctKey:
    """Derives the AES-256 key sealing the short-lived cookies from the application's secret.

    The secret must be long and random (for example 32 bytes of base64): it is
    never stored or logged.
    """
    if len(secret) < MIN_SECRET_LENGTH:
        raise ERR.CFG_001(f"The secret must be at least {MIN_SECRET_LENGTH} characters long")
    digest = hashlib.sha256(f"auth-ai:seal:{secret}".encode()).digest()
    return OctKey.import_key(digest)


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="ignore")

    data: object


def seal(key: OctKey, data: object, ttl_seconds: int) -> str:
    """Encrypts and authenticates a JSON value into a compact token that expires."""
    now = int(time.time())
    return jwt.encode(
        {"alg": "dir", "enc": "A256GCM"},
        {"data": data, "iat": now, "exp": now + ttl_seconds},
        key,
        algorithms=_ALGORITHMS,
    )


def unseal[T](key: OctKey, token: str, schema: TypeAdapter[T]) -> T:
    """The value of `seal`, validated by `schema`; SES_002 for any tampered or expired token."""
    try:
        decoded = jwt.decode(token, key, algorithms=_ALGORITHMS)
        jwt.JWTClaimsRegistry(exp={"essential": True}).validate(decoded.claims)
        envelope = _Envelope.model_validate(decoded.claims)
        return schema.validate_python(envelope.data)
    except (JoseError, ValidationError, ValueError) as err:
        raise ERR.SES_002(cause=err) from err
