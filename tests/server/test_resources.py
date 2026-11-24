from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest

from auth_ai import AuthAiError, AuthClient
from auth_ai.server import Allowed, Denied, MachineApi
from tests.support.mock_idp import MockIdp, RecordedRequest, json_response

RESOURCE_ID = "4b1f6f3e-5a6c-4d0e-9c53-0a4c6f0f7a11"

AUTHORIZE: dict[str, Any] = {
    "subject_id": "user-1",
    "actor_client_id": "acme-app",
    "resource_uri": "llm://acme/gpt-x",
    "audience": "https://llm.test",
}

ALLOW = {
    "decision": "allow",
    "decisionId": "eyJ2IjoxfQ.c2ln",
    "expiresAt": "2026-11-18T10:01:00.000Z",
    "resourceId": RESOURCE_ID,
    "resourceUri": "llm://acme/gpt-x",
    "applicationSlug": "acme",
    "ownerType": "application",
    "ownerId": "app-1",
    "accessKind": "grant",
    "permission": "read",
}

ITEM = {
    "resourceId": RESOURCE_ID,
    "resourceUri": "llm://acme/gpt-x",
    "scheme": "llm",
    "displayName": "gpt-x",
    "applicationId": "app-1",
    "applicationSlug": "acme",
    "applicationName": "Acme",
    "ownerType": "application",
    "ownerId": "app-1",
    "accessKind": "grant",
    "permission": "read",
    "grantSubjectType": "plan",
}

STATE = {
    "id": RESOURCE_ID,
    "uri": "acme://project-1",
    "status": "validated",
    "validationError": None,
}


@pytest.fixture
def api(idp: MockIdp, auth: AuthClient) -> MachineApi:
    idp.token_handler = lambda _request: json_response(
        {"access_token": "machine-1", "token_type": "Bearer", "expires_in": 3600}
    )
    idp.api_handler = lambda _request: json_response({})
    return MachineApi(auth)


def last_api_request(idp: MockIdp) -> RecordedRequest:
    requests = [r for r in idp.requests if r.url.path.startswith("/api/")]
    assert requests, "no API request was made"
    return requests[-1]


def assert_no_request(idp: MockIdp) -> None:
    assert idp.requests == []


class TestAuthorize:
    async def test_returns_the_admission_with_the_decision_data(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response(ALLOW)

        decision = await api.resources.authorize(
            **AUTHORIZE, permission="write", request_id="req-1", source="api"
        )

        assert isinstance(decision, Allowed)
        assert decision.decision_id == "eyJ2IjoxfQ.c2ln"
        assert decision.resource_id == RESOURCE_ID
        assert decision.application_slug == "acme"
        assert decision.owner_type == "application"
        assert decision.access_kind == "grant"
        assert decision.permission == "read"
        request = last_api_request(idp)
        assert request.method == "POST"
        assert request.url.path == "/api/internal/gateway/authorize"
        assert request.json == {
            "subjectId": "user-1",
            "actorClientId": "acme-app",
            "resourceUri": "llm://acme/gpt-x",
            "audience": "https://llm.test",
            "permission": "write",
            "requestId": "req-1",
            "source": "api",
        }
        assert idp.requests_to("/token")[0].form["scope"] == "resources:authorize"

    async def test_sends_only_the_fields_that_are_set(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response(ALLOW)

        await api.resources.authorize(subject_id="user-1", resource_uri="llm://a/b", audience="x")

        assert set(last_api_request(idp).json) == {"subjectId", "resourceUri", "audience"}

    async def test_accepts_an_admission_without_an_owner(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        shared = {k: v for k, v in ALLOW.items() if k != "ownerId"}
        idp.api_handler = lambda _request: json_response(shared)

        decision = await api.resources.authorize(**AUTHORIZE)

        assert isinstance(decision, Allowed)
        assert decision.owner_id is None

    async def test_refuses_an_admission_with_an_unknown_permission(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response({**ALLOW, "permission": "admin"})

        with pytest.raises(AuthAiError) as raised:
            await api.resources.authorize(**AUTHORIZE)

        assert raised.value.code == "API_002"

    async def test_returns_a_denial_without_any_reason(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response({"decision": "deny", "reason": "no_grant"})

        decision = await api.resources.authorize(**AUTHORIZE)

        assert isinstance(decision, Denied)
        assert decision.to_json() == {"decision": "deny"}

    @pytest.mark.parametrize(
        "answer", [{"decision": "maybe"}, {"decision": "allow"}, {}, {"decision": None}]
    )
    async def test_never_reads_an_unexpected_answer_as_an_admission(
        self, idp: MockIdp, api: MachineApi, answer: dict[str, object]
    ) -> None:
        idp.api_handler = lambda _request: json_response(answer)

        with pytest.raises(AuthAiError) as raised:
            await api.resources.authorize(**AUTHORIZE)

        assert raised.value.code == "API_002"

    async def test_flags_an_answer_that_is_not_json(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: httpx2.Response(200, content=b"<html>")

        with pytest.raises(AuthAiError) as raised:
            await api.resources.authorize(**AUTHORIZE)

        assert raised.value.code == "API_002"

    @pytest.mark.parametrize(
        "override",
        [
            {"subject_id": ""},
            {"actor_client_id": ""},
            {"permission": "admin"},
            {"resource_uri": "a:"},
            {"resource_uri": "llm://" + "a" * 510},
            {"audience": ""},
            {"source": "browser"},
            {"request_id": ""},
        ],
    )
    async def test_rejects_invalid_input_before_any_request(
        self, idp: MockIdp, api: MachineApi, override: dict[str, Any]
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await api.resources.authorize(**{**AUTHORIZE, **override})

        assert raised.value.code == "CFG_001"
        assert_no_request(idp)

    async def test_surfaces_a_missing_scope_as_an_api_error(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"error": {"code": "AUTH_011", "message": "Missing required scope"}}, 403
        )

        with pytest.raises(AuthAiError) as raised:
            await api.resources.authorize(**AUTHORIZE)

        assert raised.value.code == "API_001"
        assert raised.value.details == {"status": 403, "apiCode": "AUTH_011"}


class TestListAccessible:
    async def test_lists_what_a_user_may_use_optionally_by_scheme(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response({"resources": [ITEM]})

        resources = await api.resources.list_accessible("user/1")

        assert resources[0].resource_uri == "llm://acme/gpt-x"
        assert resources[0].grant_subject_type == "plan"
        assert resources[0].permission == "read"
        first = last_api_request(idp)
        assert first.url.path == "/api/internal/gateway/resources/accessible"
        assert first.url.params["subjectId"] == "user/1"
        assert "scheme" not in first.url.params

        await api.resources.list_accessible("user-1", scheme="llm")
        assert last_api_request(idp).url.params["scheme"] == "llm"
        assert idp.requests_to("/token")[0].form["scope"] == "resources:authorize"

    async def test_accepts_an_owned_resource_which_has_no_grant_subject(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        owned = {k: v for k, v in ITEM.items() if k != "grantSubjectType"}
        idp.api_handler = lambda _request: json_response(
            {"resources": [{**owned, "accessKind": "owner"}]}
        )

        [resource] = await api.resources.list_accessible("user-1")

        assert resource.access_kind == "owner"
        assert resource.grant_subject_type is None

    async def test_flags_an_unknown_access_kind(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response(
            {"resources": [{**ITEM, "accessKind": "admin"}]}
        )

        with pytest.raises(AuthAiError) as raised:
            await api.resources.list_accessible("user-1")

        assert raised.value.code == "API_002"

    @pytest.mark.parametrize(
        ("subject", "scheme"), [("", None), ("user-1", "LLM"), ("u", "llm://")]
    )
    async def test_rejects_invalid_input_before_any_request(
        self, idp: MockIdp, api: MachineApi, subject: str, scheme: str | None
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await api.resources.list_accessible(subject, scheme=scheme)

        assert raised.value.code == "CFG_001"
        assert_no_request(idp)


class TestValidate:
    async def test_reports_the_outcome_of_the_ownership_check(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response({"resource": STATE})

        state = await api.resources.validate(
            RESOURCE_ID, result="validated", evidence={"checkedBy": "acme-backend"}
        )

        assert state.status == "validated"
        assert state.validation_error is None
        request = last_api_request(idp)
        assert request.method == "POST"
        assert request.url.path == f"/api/internal/gateway/resources/{RESOURCE_ID}/validate"
        assert request.json == {"result": "validated", "evidence": {"checkedBy": "acme-backend"}}
        assert idp.requests_to("/token")[0].form["scope"] == "resources:validate"

    async def test_reports_a_failure_with_its_trimmed_reason(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {
                "resource": {
                    **STATE,
                    "status": "validation_failed",
                    "validationError": "not yours",
                }
            }
        )

        state = await api.resources.validate(
            RESOURCE_ID, result="validation_failed", reason="  not yours  "
        )

        assert state.status == "validation_failed"
        assert last_api_request(idp).json == {"result": "validation_failed", "reason": "not yours"}

    @pytest.mark.parametrize(
        ("resource_id", "kwargs"),
        [
            ("../../admin", {"result": "validated"}),
            (RESOURCE_ID, {"result": "approved"}),
            (RESOURCE_ID, {"result": "validation_failed", "reason": "x" * 501}),
        ],
    )
    async def test_rejects_invalid_input_before_any_request(
        self, idp: MockIdp, api: MachineApi, resource_id: str, kwargs: dict[str, Any]
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await api.resources.validate(resource_id, **kwargs)

        assert raised.value.code == "CFG_001"
        assert_no_request(idp)

    async def test_surfaces_a_refusal_from_a_client_that_is_not_the_validator(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {
                "error": {
                    "code": "AUTH_011",
                    "message": "Client is not the validator for this resource scheme",
                }
            },
            403,
        )

        with pytest.raises(AuthAiError) as raised:
            await api.resources.validate(RESOURCE_ID, result="validated")

        assert raised.value.details == {"status": 403, "apiCode": "AUTH_011"}


class TestInvalidate:
    async def test_disables_a_resource_whose_ownership_was_lost(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"resource": {**STATE, "status": "disabled", "validationError": "project-deleted"}}
        )

        state = await api.resources.invalidate(RESOURCE_ID, " project-deleted ")

        assert state.status == "disabled"
        request = last_api_request(idp)
        assert request.url.path == f"/api/internal/gateway/resources/{RESOURCE_ID}/invalidate"
        assert request.json == {"reason": "project-deleted"}
        assert idp.requests_to("/token")[0].form["scope"] == "resources:validate"

    @pytest.mark.parametrize(
        ("resource_id", "reason"),
        [(RESOURCE_ID, "   "), (RESOURCE_ID, "x" * 501), ("1/../2", "gone")],
    )
    async def test_rejects_invalid_input_before_any_request(
        self, idp: MockIdp, api: MachineApi, resource_id: str, reason: str
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await api.resources.invalidate(resource_id, reason)

        assert raised.value.code == "CFG_001"
        assert_no_request(idp)


EVENT_ID = "0123456789abcdef" * 4

RECEIPT = {
    "usage": {
        "id": "u-1",
        "resourceId": RESOURCE_ID,
        "requestId": EVENT_ID,
        "occurredAt": "2026-11-18T10:00:00.000Z",
    },
    "replayed": False,
}


def usage_record(**override: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "decision_id": "eyJ2IjoxfQ.c2ln",
        "started_at": datetime.now(UTC) - timedelta(seconds=2),
        "resource_id": RESOURCE_ID,
        "resource_uri": "llm://acme/gpt-x",
        "request_id": EVENT_ID,
        "occurred_at": datetime.now(UTC),
        "usage_source": "provider",
        "cost_usd": "0.0042",
        "prompt_tokens": 120,
        "completion_tokens": 30,
        "total_tokens": 150,
    }
    return {**record, **override}


class TestRecordUsage:
    async def test_sends_the_event_with_the_usage_scope(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response(RECEIPT, status=201)

        receipt = await api.resources.record_usage(**usage_record())

        assert receipt.replayed is False
        assert receipt.usage.id == "u-1"
        request = last_api_request(idp)
        assert request.url.path == "/api/internal/gateway/usage"
        assert request.json["usageSource"] == "provider"
        assert request.json["costUsd"] == "0.0042"
        assert request.json["promptTokens"] == 120
        assert request.json["requestId"] == EVENT_ID
        assert request.json["decisionId"] == "eyJ2IjoxfQ.c2ln"
        assert "subjectId" not in request.json
        assert "clientId" not in request.json
        assert request.json["startedAt"].endswith("Z")
        assert request.json["occurredAt"].endswith("Z")
        assert idp.requests_to("/token")[0].form["scope"] == "resources:usage:write"

    async def test_an_unsupported_provider_sends_explicit_nulls(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        idp.api_handler = lambda _request: json_response(RECEIPT, status=201)

        await api.resources.record_usage(
            **usage_record(
                usage_source="unsupported",
                cost_usd=None,
                prompt_tokens=None,
                completion_tokens=None,
                total_tokens=None,
            )
        )

        body = last_api_request(idp).json
        assert body["usageSource"] == "unsupported"
        for member in ("costUsd", "promptTokens", "completionTokens", "totalTokens"):
            assert body[member] is None

    async def test_no_longer_takes_the_person_or_the_client(
        self, idp: MockIdp, api: MachineApi
    ) -> None:
        with pytest.raises(TypeError):
            await api.resources.record_usage(**usage_record(subject_id="user-1"))
        with pytest.raises(TypeError):
            await api.resources.record_usage(**usage_record(client_id="gateway"))

        assert_no_request(idp)

    async def test_reports_a_replayed_event(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response({**RECEIPT, "replayed": True})

        assert (await api.resources.record_usage(**usage_record())).replayed is True

    @pytest.mark.parametrize(("status", "code"), [(403, "RES_011"), (409, "RES_012")])
    async def test_a_refusal_is_an_error(
        self, idp: MockIdp, api: MachineApi, status: int, code: str
    ) -> None:
        idp.api_handler = lambda _request: json_response(
            {"error": {"code": code, "message": "no"}}, status=status
        )

        with pytest.raises(AuthAiError) as raised:
            await api.resources.record_usage(**usage_record())

        assert raised.value.code == "API_001"

    async def test_flags_an_unexpected_answer(self, idp: MockIdp, api: MachineApi) -> None:
        idp.api_handler = lambda _request: json_response({"usage": "stored"}, status=201)

        with pytest.raises(AuthAiError) as raised:
            await api.resources.record_usage(**usage_record())

        assert raised.value.code == "API_002"

    @pytest.mark.parametrize(
        "override",
        [
            {"decision_id": ""},
            {"started_at": datetime.now()},
            {"resource_id": "not-a-uuid"},
            {"resource_uri": "x"},
            {"request_id": "short"},
            {"request_id": EVENT_ID.upper()},
            {"occurred_at": datetime.now(UTC) - timedelta(days=31)},
            {"occurred_at": datetime.now(UTC) + timedelta(minutes=10)},
            {"occurred_at": datetime.now()},
            {"cost_usd": None},
            {"cost_usd": "-1"},
            {"cost_usd": "1e3"},
            {"cost_usd": "007"},
            {"usage_source": "unsupported"},
            {"usage_source": "unsupported", "cost_usd": None},
            {"prompt_tokens": -1},
            {"usage_source": "other"},
        ],
    )
    async def test_refuses_an_invalid_record_before_any_request(
        self, idp: MockIdp, api: MachineApi, override: dict[str, Any]
    ) -> None:
        with pytest.raises(AuthAiError) as raised:
            await api.resources.record_usage(**usage_record(**override))

        assert raised.value.code == "CFG_001"
        assert_no_request(idp)
