from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from auth_ai import AuthClient
from tests.support.mock_idp import MockIdp, create_mock_idp, create_test_auth


@pytest.fixture
def idp() -> MockIdp:
    return create_mock_idp()


@pytest.fixture
async def auth(idp: MockIdp) -> AsyncIterator[AuthClient]:
    client = create_test_auth(idp)
    yield client
    await client.http.aclose()
