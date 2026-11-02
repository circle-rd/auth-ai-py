from __future__ import annotations

import hmac
from typing import TYPE_CHECKING

from .errors import ERR

if TYPE_CHECKING:
    from collections.abc import Mapping


def check_id_token_binding(
    claims: Mapping[str, object], *, client_id: str, nonce: str | None
) -> None:
    """OIDC Core §3.1.3.7 checks that a JWT verifier does not make.

    The signature, issuer, audience and expiry are the verifier's business. Here:
    the `nonce` echoes the one sent at sign-in (when there was one), and the
    authorized party names this client (it is required when the audience is not
    this client alone).
    """
    if nonce is not None:
        received = claims.get("nonce")
        if not isinstance(received, str):
            raise ERR.TOK_001("The ID token carries no nonce", details={"reason": "missing_nonce"})
        if not hmac.compare_digest(received.encode(), nonce.encode()):
            raise ERR.TOK_001("ID token nonce mismatch", details={"reason": "nonce_mismatch"})

    audience = claims.get("aud")
    sole_audience = audience in (client_id, [client_id])
    authorized_party = claims.get("azp")
    if "azp" not in claims:
        if not sole_audience:
            raise ERR.TOK_001("The ID token lacks azp", details={"reason": "missing_azp"})
    elif authorized_party != client_id:
        raise ERR.TOK_001(
            "The ID token was issued to another party", details={"reason": "azp_mismatch"}
        )
