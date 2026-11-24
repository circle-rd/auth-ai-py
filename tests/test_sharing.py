from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
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
    "permission": "read",
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
                        "permission": "write",
                        "grantSubjectType": "user",
                    }
                ]
            }
        )

        resources = await sharing.list_accessible(scheme="gine", application_id=APP_ID)

        assert resources[0].resource_uri == "gine://job-1"
        assert resources[0].permission == "write"
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
        idp.api_handler = lambda _request: json_response({"resource": resource()})

        deleted = await sharing.delete(RESOURCE_ID)

        assert deleted.id == RESOURCE_ID
        request = last_request(idp)
        assert request.method == "DELETE"
        assert request.url.path == f"/api/user/resources/{RESOURCE_ID}"

    async def test_surfaces_the_refusal_while_the_relay_serves_the_model(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"error": {"code": "RES_019", "message": "served"}}, 409
        )

        with pytest.raises(AuthAiError) as caught:
            await sharing.delete(RESOURCE_ID)

        assert caught.value.details == {"status": 409, "apiCode": "RES_019"}

    async def test_creates_a_user_grant_by_email(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response({"grant": GRANT}, 201)

        grant = await sharing.create_grant(
            RESOURCE_ID, subject_type="user", subject_email="user@example.com"
        )

        assert grant.id == GRANT_ID
        assert grant.permission == "read"
        assert last_request(idp).json == {
            "subjectType": "user",
            "subjectEmail": "user@example.com",
        }

    async def test_sends_the_permission_only_when_given(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"grant": {**GRANT, "permission": "write"}}, 201
        )

        grant = await sharing.create_grant(
            RESOURCE_ID, subject_type="user", subject_id="user-2", permission="write"
        )

        assert grant.permission == "write"
        assert last_request(idp).json == {
            "subjectType": "user",
            "subjectId": "user-2",
            "permission": "write",
        }

    async def test_shares_with_an_application_by_slug(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"grant": {**GRANT, "subjectType": "application", "subjectId": "chat"}}, 201
        )

        await sharing.create_grant(RESOURCE_ID, subject_type="application", subject_id="chat")

        assert last_request(idp).json == {"subjectType": "application", "subjectId": "chat"}

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
        assert "permanent" not in request.url.params

    async def test_deletes_a_past_grant_for_good(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: httpx2.Response(204)

        await sharing.delete_grant(RESOURCE_ID, GRANT_ID)

        request = last_request(idp)
        assert request.method == "DELETE"
        assert request.url.path == f"/api/user/resources/{RESOURCE_ID}/grants/{GRANT_ID}"
        assert request.url.params["permanent"] == "true"

    async def test_surfaces_the_refusal_to_delete_an_active_grant(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"error": {"code": "RES_020", "message": "active"}}, 409
        )

        with pytest.raises(AuthAiError) as caught:
            await sharing.delete_grant(RESOURCE_ID, GRANT_ID)

        assert caught.value.details == {"status": 409, "apiCode": "RES_020"}

    async def test_changes_the_level_of_a_grant_without_revoking_it(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"grant": {**GRANT, "permission": "write"}}
        )

        grant = await sharing.update_grant(RESOURCE_ID, GRANT_ID, permission="write")

        assert grant.permission == "write"
        request = last_request(idp)
        assert request.method == "PATCH"
        assert request.url.path == f"/api/user/resources/{RESOURCE_ID}/grants/{GRANT_ID}"
        assert request.json == {"permission": "write"}

    async def test_shares_several_resources_with_an_application(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        results = [
            {"resourceId": RESOURCE_ID, "grantId": GRANT_ID, "code": None},
            {"resourceId": APP_ID, "grantId": None, "code": "RES_014"},
        ]
        idp.api_handler = lambda _request: json_response({"results": results})
        expires_at = datetime.now(UTC) + timedelta(days=1)

        outcome = await sharing.share_with_application(
            [RESOURCE_ID, APP_ID],
            application_slug="chat",
            permission="write",
            expires_at=expires_at,
        )

        assert [(r.resource_id, r.grant_id, r.code) for r in outcome] == [
            (RESOURCE_ID, GRANT_ID, None),
            (APP_ID, None, "RES_014"),
        ]
        request = last_request(idp)
        assert request.method == "POST"
        assert request.url.path == "/api/user/resource-shares"
        assert request.json == {
            "resourceIds": [RESOURCE_ID, APP_ID],
            "applicationSlug": "chat",
            "permission": "write",
            "expiresAt": expires_at.isoformat().replace("+00:00", "Z"),
        }


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

    @pytest.mark.parametrize("permission", ["admin", "use", ""])
    async def test_refuses_a_permission_outside_the_closed_set(
        self, idp: MockIdp, sharing: ResourceSharingClient, permission: str
    ) -> None:
        with pytest.raises(AuthAiError) as create:
            await sharing.create_grant(
                RESOURCE_ID,
                subject_type="user",
                subject_id="user-2",
                permission=permission,  # type: ignore[arg-type]
            )
        with pytest.raises(AuthAiError) as update:
            await sharing.update_grant(
                RESOURCE_ID,
                GRANT_ID,
                permission=permission,  # type: ignore[arg-type]
            )

        assert create.value.code == "CFG_001"
        assert update.value.code == "CFG_001"
        assert idp.requests == []

    async def test_refuses_an_application_grant_without_a_slug(
        self, idp: MockIdp, sharing: ResourceSharingClient
    ) -> None:
        with pytest.raises(AuthAiError) as caught:
            await sharing.create_grant(RESOURCE_ID, subject_type="application")

        assert caught.value.code == "CFG_001"
        assert idp.requests == []

    @pytest.mark.parametrize(
        ("resource_ids", "slug", "expires_at"),
        [
            ([], "chat", None),
            ([RESOURCE_ID] * 101, "chat", None),
            (["nope"], "chat", None),
            ([RESOURCE_ID], " ", None),
            ([RESOURCE_ID], "chat", datetime.now(UTC) - timedelta(minutes=1)),
        ],
    )
    async def test_refuses_an_invalid_bulk_share(
        self,
        idp: MockIdp,
        sharing: ResourceSharingClient,
        resource_ids: list[str],
        slug: str,
        expires_at: datetime | None,
    ) -> None:
        with pytest.raises(AuthAiError) as caught:
            await sharing.share_with_application(
                resource_ids, application_slug=slug, expires_at=expires_at
            )

        assert caught.value.code == "CFG_001"
        assert idp.requests == []
