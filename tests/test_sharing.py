from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from auth_ai import Audience, AuthAiError, ResourceSharingClient
from auth_ai.http import JsonHttp
from tests.support.mock_idp import ISSUER, MockIdp, RecordedRequest, json_response

RESOURCE_ID = "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11"
GRANT_ID = "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
APP_ID = "1d2c3b4a-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
ORG_ID = "org-1"


def resource(**overrides: Any) -> dict[str, Any]:
    return {
        "id": RESOURCE_ID,
        "applicationId": APP_ID,
        "applicationSlug": "gine",
        "applicationName": "GINE",
        "scheme": "gine",
        "schemeDisplayName": "GINE project",
        "locator": "job-1",
        "uri": "gine://job-1",
        "displayName": "Firmware",
        "ownerType": "user",
        "ownerId": "user-1",
        "status": "validated",
        "listed": False,
        "validationRequestedAt": None,
        "validatedAt": "2026-11-20T10:00:00Z",
        "validationError": None,
        "createdAt": "2026-11-20T09:00:00Z",
        "updatedAt": "2026-11-20T10:00:00Z",
        **overrides,
    }


GRANT = {
    "id": GRANT_ID,
    "resourceId": RESOURCE_ID,
    "subjectType": "user",
    "subjectId": "user-2",
    "permission": "use",
    "expiresAt": None,
    "revokedAt": None,
    "createdBy": "user-1",
    "createdAt": "2026-11-20T10:00:00Z",
}


class CountingTokens:
    def __init__(self) -> None:
        self.keys: list[str] = []

    async def get_token(self, key: str) -> str:
        self.keys.append(key)
        return "user-token"

    def invalidate(self, key: str) -> None:
        self.keys.append(f"invalidate:{key}")


@pytest.fixture
def tokens() -> CountingTokens:
    return CountingTokens()


@pytest.fixture
async def sharing(idp: MockIdp, tokens: CountingTokens) -> AsyncIterator[ResourceSharingClient]:
    http = idp.http_client()
    json_http = JsonHttp(base_url=ISSUER, http=http, timeout_seconds=5, tokens=tokens)
    yield ResourceSharingClient(json_http)
    await http.aclose()


def last_request(idp: MockIdp) -> RecordedRequest:
    return idp.requests[-1]


class TestLists:
    async def test_lists_member_applications(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {
                "applications": [
                    {
                        "id": APP_ID,
                        "name": "GINE",
                        "slug": "gine",
                        "description": None,
                        "icon": None,
                        "canCreate": True,
                    }
                ]
            }
        )

        apps = await sharing.list_member_applications()

        assert apps[0].slug == "gine"
        assert apps[0].can_create is True
        assert last_request(idp).url.path == "/api/user/resource-applications"

    async def test_lists_organizations(self, idp: MockIdp, sharing: ResourceSharingClient) -> None:
        idp.api_handler = lambda _request: json_response(
            {
                "organizations": [
                    {
                        "id": ORG_ID,
                        "name": "CIRCLE",
                        "slug": "circle",
                        "logo": None,
                        "role": "member",
                        "createdAt": "2026-01-01T00:00:00Z",
                    }
                ]
            }
        )

        orgs = await sharing.list_organizations()

        assert orgs[0].id == ORG_ID
        assert last_request(idp).url.path == "/api/user/organizations"

    async def test_lists_owned_resources(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response({"resources": [resource()]})

        resources = await sharing.list_owned()

        assert resources[0].locator == "job-1"
        assert last_request(idp).url.path == "/api/user/resources"

    async def test_filters_accessible_resources(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {
                "resources": [
                    {
                        "resourceId": RESOURCE_ID,
                        "resourceUri": "gine://job-1",
                        "scheme": "gine",
                        "displayName": "Firmware",
                        "applicationId": APP_ID,
                        "applicationSlug": "gine",
                        "applicationName": "GINE",
                        "ownerType": "user",
                        "ownerId": "user-1",
                        "accessKind": "grant",
                        "grantSubjectType": "user",
                    }
                ]
            }
        )

        resources = await sharing.list_accessible(scheme="gine", application_id=APP_ID)

        assert resources[0].resource_uri == "gine://job-1"
        request = last_request(idp)
        assert request.url.path == "/api/user/accessible-resources"
        assert request.url.params["scheme"] == "gine"
        assert request.url.params["applicationId"] == APP_ID


class TestMutations:
    async def test_creates_a_resource_with_an_audience(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response({"resource": resource()}, 201)

        created = await sharing.create(
            application_id=APP_ID,
            scheme="gine",
            display_name="Firmware",
            locator="job-1",
            metadata={"jobId": "job-1"},
            audience=Audience.user(email="colleague@example.com"),
        )

        assert created.id == RESOURCE_ID
        request = last_request(idp)
        assert request.method == "POST"
        assert request.url.path == "/api/user/resources"
        assert request.json == {
            "applicationId": APP_ID,
            "scheme": "gine",
            "displayName": "Firmware",
            "locator": "job-1",
            "metadata": {"jobId": "job-1"},
            "audience": {"type": "user", "email": "colleague@example.com"},
        }

    async def test_updates_with_patch(self, idp: MockIdp, sharing: ResourceSharingClient) -> None:
        idp.api_handler = lambda _request: json_response(
            {"resource": resource(displayName="Renamed")}
        )

        updated = await sharing.update(RESOURCE_ID, display_name="Renamed", listed=True)

        assert updated.display_name == "Renamed"
        request = last_request(idp)
        assert request.method == "PATCH"
        assert request.json == {"displayName": "Renamed", "listed": True}

    async def test_deletes_a_resource(self, idp: MockIdp, sharing: ResourceSharingClient) -> None:
        idp.api_handler = lambda _request: json_response({"resource": resource(), "removed": True})

        deleted = await sharing.delete(RESOURCE_ID)

        assert deleted.removed is True
        assert last_request(idp).method == "DELETE"

    async def test_creates_a_user_grant_by_email(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response({"grant": GRANT}, 201)

        grant = await sharing.create_grant(
            RESOURCE_ID, subject_type="user", subject_email="user@example.com"
        )

        assert grant.id == GRANT_ID
        assert last_request(idp).json == {
            "subjectType": "user",
            "subjectEmail": "user@example.com",
        }

    async def test_creates_an_organization_grant(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"grant": {**GRANT, "subjectType": "organization", "subjectId": ORG_ID}}, 201
        )

        grant = await sharing.create_grant(
            RESOURCE_ID, subject_type="organization", subject_id=ORG_ID
        )

        assert grant.subject_type == "organization"
        assert last_request(idp).json == {
            "subjectType": "organization",
            "subjectId": ORG_ID,
        }

    async def test_revokes_a_grant_with_delete(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response({"grant": GRANT})

        await sharing.revoke_grant(RESOURCE_ID, GRANT_ID)

        request = last_request(idp)
        assert request.method == "DELETE"
        assert request.url.path == f"/api/user/resources/{RESOURCE_ID}/grants/{GRANT_ID}"


class TestValidation:
    async def test_refuses_a_non_uuid_id_before_any_request(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        with pytest.raises(AuthAiError) as caught:
            await sharing.get_resource("not-a-uuid")

        assert caught.value.code == "CFG_001"
        assert idp.requests == []

    async def test_refuses_two_user_subjects(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        with pytest.raises(AuthAiError) as caught:
            await sharing.create_grant(
                RESOURCE_ID,
                subject_type="user",
                subject_id="user-2",
                subject_email="user@example.com",
            )

        assert caught.value.code == "CFG_001"
        assert idp.requests == []

    async def test_refuses_an_expired_grant(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        with pytest.raises(AuthAiError) as caught:
            await sharing.create_grant(
                RESOURCE_ID,
                subject_type="user",
                subject_id="user-2",
                expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )

        assert caught.value.code == "CFG_001"
        assert idp.requests == []
