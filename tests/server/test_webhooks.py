from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import pytest

from auth_ai import AuthAiError
from auth_ai.server import ResourceDeletedEvent, ResourceGrantEvent, verify_resource_event

SECRET = "whsec_test_123"
NOW = 1_800_000_000


def event(**overrides: Any) -> dict[str, Any]:
    return {
        "eventId": "6f1c0f1e-2c3b-4a5d-8e9f-0a1b2c3d4e5f",
        "type": "resource.grant.created",
        "occurredAt": "2026-11-20T10:00:00Z",
        "application": {"id": "app-1", "slug": "gine"},
        "resource": {
            "id": "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11",
            "uri": "gine://job-1",
            "scheme": "gine",
            "displayName": "Firmware",
            "ownerType": "user",
            "ownerId": "user-1",
            "status": "validated",
        },
        "grant": {
            "id": "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
            "subjectType": "user",
            "subjectId": "user-2",
            "permission": "read",
            "previousPermission": None,
            "expiresAt": None,
        },
        "recipients": {"userIds": ["user-2"], "allMembers": False},
        **overrides,
    }


def deleted_event() -> dict[str, Any]:
    return {
        "eventId": "7a2d1f2e-3c4b-4a5d-8e9f-0a1b2c3d4e5f",
        "type": "resource.deleted",
        "occurredAt": "2026-11-20T10:05:00Z",
        "application": {"id": "app-2", "slug": "chat"},
        "resource": {
            "id": "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11",
            "uri": "gine://job-1",
            "scheme": "gine",
            "displayName": "Firmware",
            "ownerType": "user",
        },
    }


def sign(body: bytes, *, timestamp: int = NOW, secret: str = SECRET) -> str:
    digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


class TestVerify:
    def test_parses_a_valid_delivery(self) -> None:
        body = json.dumps(event()).encode()

        parsed = verify_resource_event(
            {"x-auth-service-signature": sign(body)}, body, SECRET, now=NOW
        )

        assert isinstance(parsed, ResourceGrantEvent)
        assert parsed.type == "resource.grant.created"
        assert parsed.resource.uri == "gine://job-1"
        assert parsed.grant.permission == "read"
        assert parsed.recipients.user_ids == ["user-2"]

    def test_parses_a_level_change_with_the_previous_level(self) -> None:
        payload = event(type="resource.grant.updated")
        payload["grant"] = {**payload["grant"], "permission": "write", "previousPermission": "read"}
        body = json.dumps(payload).encode()

        parsed = verify_resource_event(
            {"x-auth-service-signature": sign(body)}, body, SECRET, now=NOW
        )

        assert isinstance(parsed, ResourceGrantEvent)
        assert parsed.type == "resource.grant.updated"
        assert parsed.grant.permission == "write"
        assert parsed.grant.previous_permission == "read"

    def test_parses_a_deletion_which_carries_no_grant_and_no_owner(self) -> None:
        body = json.dumps(deleted_event()).encode()

        parsed = verify_resource_event(
            {"x-auth-service-signature": sign(body)}, body, SECRET, now=NOW
        )

        assert isinstance(parsed, ResourceDeletedEvent)
        assert parsed.resource.owner_id is None
        assert not hasattr(parsed, "grant")

    def test_refuses_a_grant_event_without_a_permission(self) -> None:
        payload = event()
        del payload["grant"]["permission"]
        body = json.dumps(payload).encode()

        with pytest.raises(AuthAiError) as caught:
            verify_resource_event({"x-auth-service-signature": sign(body)}, body, SECRET, now=NOW)

        assert caught.value.code == "REQ_001"

    def test_refuses_an_unknown_event_type(self) -> None:
        body = json.dumps(event(type="resource.exploded")).encode()

        with pytest.raises(AuthAiError) as caught:
            verify_resource_event({"x-auth-service-signature": sign(body)}, body, SECRET, now=NOW)

        assert caught.value.code == "REQ_001"

    def test_accepts_a_string_body_and_mixed_case_header(self) -> None:
        body = json.dumps(event())

        parsed = verify_resource_event(
            {"X-Auth-Service-Signature": sign(body.encode())},
            body,
            SECRET,
            now=NOW,
        )

        assert parsed.application.slug == "gine"

    def test_refuses_a_tampered_body(self) -> None:
        body = json.dumps(event()).encode()
        header = sign(body)

        with pytest.raises(AuthAiError) as caught:
            verify_resource_event(
                {"x-auth-service-signature": header}, body + b" ", SECRET, now=NOW
            )

        assert caught.value.code == "REQ_001"

    def test_refuses_a_wrong_secret(self) -> None:
        body = json.dumps(event()).encode()

        with pytest.raises(AuthAiError) as caught:
            verify_resource_event(
                {"x-auth-service-signature": sign(body, secret="other")},
                body,
                SECRET,
                now=NOW,
            )

        assert caught.value.code == "REQ_001"

    def test_refuses_a_stale_timestamp(self) -> None:
        body = json.dumps(event()).encode()

        with pytest.raises(AuthAiError) as caught:
            verify_resource_event(
                {"x-auth-service-signature": sign(body, timestamp=NOW - 3_600)},
                body,
                SECRET,
                now=NOW,
            )

        assert caught.value.code == "REQ_001"

    def test_refuses_a_missing_header(self) -> None:
        with pytest.raises(AuthAiError) as caught:
            verify_resource_event({}, b"{}", SECRET, now=int(time.time()))

        assert caught.value.code == "REQ_001"

    def test_refuses_an_unexpected_shape(self) -> None:
        body = json.dumps({"eventId": "x"}).encode()

        with pytest.raises(AuthAiError) as caught:
            verify_resource_event({"x-auth-service-signature": sign(body)}, body, SECRET, now=NOW)

        assert caught.value.code == "REQ_001"
