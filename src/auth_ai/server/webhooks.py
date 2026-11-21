from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime
from typing import TYPE_CHECKING, Final, Literal

from pydantic import ValidationError

from ..errors import ERR
from ..http import ApiModel

if TYPE_CHECKING:
    from collections.abc import Mapping

_HEADER: Final = "x-auth-service-signature"
_DEFAULT_TOLERANCE_SECONDS: Final = 300

type ResourceWebhookEventType = Literal["resource.grant.created", "resource.grant.revoked"]


class WebhookApplication(ApiModel):
    id: str
    slug: str


class WebhookResource(ApiModel):
    id: str
    uri: str
    scheme: str
    display_name: str
    owner_type: Literal["user", "application"]
    owner_id: str
    status: str


class WebhookGrant(ApiModel):
    id: str
    subject_type: Literal["user", "organization", "plan", "everyone"]
    subject_id: str | None = None
    expires_at: datetime | None = None


class WebhookRecipients(ApiModel):
    #: `None` with `all_members=True` means the event concerns the whole application.
    user_ids: list[str] | None = None
    all_members: bool = False


class ResourceEvent(ApiModel):
    """A signed resource-sharing event delivered by auth-service."""

    event_id: str
    type: ResourceWebhookEventType
    occurred_at: datetime
    application: WebhookApplication
    resource: WebhookResource
    grant: WebhookGrant
    recipients: WebhookRecipients


def verify_resource_event(
    headers: Mapping[str, str],
    body: bytes | str,
    secret: str,
    *,
    tolerance_seconds: int = _DEFAULT_TOLERANCE_SECONDS,
    now: float | None = None,
) -> ResourceEvent:
    """Verifies and parses a webhook signed with `X-Auth-Service-Signature`.

    The header is `t=<unix seconds>,v1=<hex HMAC-SHA256>`, computed over
    `<t>.<raw body>`. The timestamp must be within `tolerance_seconds`, so a
    captured delivery cannot be replayed later. Idempotency is the receiver's
    responsibility: deduplicate on `event_id`.
    """
    raw = body.encode("utf-8") if isinstance(body, str) else body
    header = _header(headers, _HEADER)
    if header is None:
        raise ERR.REQ_001("Missing X-Auth-Service-Signature header")

    timestamp: str | None = None
    signatures: list[str] = []
    for part in header.split(","):
        name, _, value = part.strip().partition("=")
        if name == "t":
            timestamp = value
        elif name == "v1":
            signatures.append(value)
    if timestamp is None or not signatures:
        raise ERR.REQ_001("Malformed X-Auth-Service-Signature header")

    try:
        signed_at = int(timestamp)
    except ValueError as err:
        raise ERR.REQ_001("Malformed webhook timestamp", cause=err) from err
    current = time.time() if now is None else now
    if abs(current - signed_at) > tolerance_seconds:
        raise ERR.REQ_001("Webhook timestamp is outside the accepted window")

    expected = hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("ascii") + b"." + raw,
        hashlib.sha256,
    ).hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise ERR.REQ_001("Webhook signature does not match")

    try:
        payload = json.loads(raw)
    except ValueError as err:
        raise ERR.REQ_001("Webhook body is not valid JSON", cause=err) from err
    try:
        return ResourceEvent.model_validate(payload)
    except ValidationError as err:
        raise ERR.REQ_001("Webhook body has an unexpected shape", cause=err) from err


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None
