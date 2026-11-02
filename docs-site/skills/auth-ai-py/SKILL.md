---
name: auth-ai-py
description: "Use when: integrating, configuring or troubleshooting auth-ai (PyPI package `auth-ai`, imported as `auth_ai`), the Python SDK for asyncio backends that sign users in through a CIRCLE auth-service (backend-for-frontend OIDC sign-in with FastAPI, Starlette or framework-agnostic handlers, bearer token verification, back-channel logout, wallet, LiteLLM gateway, billing and consumption), or when an AuthAiError code such as SES_005, TOK_002 or GW_001 appears."
---

# CIRCLE auth-ai (Python)

Python SDK (`auth-ai` on PyPI, imported as `auth_ai`, MIT, Python >= 3.12, async only) for applications that rely on a CIRCLE auth-service identity provider. It is the Python port of the TypeScript SDK `@circle-rd/auth-ai` (documented at https://docs.circle-cyber.com/auth-ai/) and shares its wire contract: the BFF routes, the sealed login cookie, the cookie names and the error codes.

Full documentation: https://docs.circle-cyber.com/auth-ai-py/ . Every page is also served as markdown under `/raw/`, for example https://docs.circle-cyber.com/auth-ai-py/raw/docs/concepts/architecture.md ; the whole text is at https://docs.circle-cyber.com/auth-ai-py/llms-full.txt and a page index at https://docs.circle-cyber.com/auth-ai-py/llms.txt . The documentation also exposes an MCP server at https://docs.circle-cyber.com/auth-ai-py/mcp . Version 0.x: the API is not stable.

It is built for auth-service. It is not a client for arbitrary OIDC providers and not an identity provider. It has no debit API (the LiteLLM gateway debits the wallet), no Django or Flask adapter yet, no synchronous facade, and no frontend code: pair it with the TypeScript browser client and React/Vue bindings of `@circle-rd/auth-ai`.

## Getting started

```sh
pip install "auth-ai[fastapi]"   # or: uv add "auth-ai[fastapi]" / poetry add "auth-ai[fastapi]"
# extras: fastapi (>=0.115), starlette (>=0.46). Pre-releases: pip install --pre auth-ai
```

Modules (the import paths that exist):

| Module | Purpose |
| --- | --- |
| `auth_ai` | `AuthClient`, `AuthClientConfig`, `GrantManager`, `AiClient`, claims helpers, `format_euros`, `AuthAiError`/`ERR` |
| `auth_ai.web` | `AuthHandlers`, `MemorySessionStore`, `SessionStore`, `Session`, `WebRequest`, `WebResponse`, `safe_redirect_path` |
| `auth_ai.starlette` | `install_auth`, `require_auth`, `load_session` (needs the `fastapi` or `starlette` extra) |
| `auth_ai.server` | `BearerVerifier`, `require_scopes`, `protected_resource_metadata`, `BackchannelLogoutHandler`, `MachineApi` |

## Register the application in auth-service first

- Confidential application, redirect URI `<origin><base_path>/callback` (`base_path` defaults to `/auth`).
- Back-channel logout URI `<origin><base_path>/backchannel-logout` (HTTPS, reachable by auth-service) and/or end-session enabled: sign-in refuses an ID token without `sid`.
- **LiteLLM support** on when `gateway_url` is set.
- Machine scopes `billing:read`, `consumption:read`, `consumption:write` for the machine API (default for new confidential apps; a superadmin must set them on older apps).

## Minimal FastAPI backend

```python
import os
from typing import Annotated

from fastapi import Depends, FastAPI

from auth_ai import AuthClient, GrantManager, MemoryGrantStore
from auth_ai.starlette import install_auth, require_auth
from auth_ai.web import AuthHandlers, MemorySessionStore, Session


def required(name: str) -> str:
    # A missing secret must stop the process (None would make a public client).
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing environment variable {name}")
    return value


auth = AuthClient(
    {
        "issuer": "https://auth.example.com",  # HTTPS, no trailing slash
        "client_id": "my-app",
        "client_secret": required("AUTH_CLIENT_SECRET"),
        "redirect_uri": "https://app.example.com/auth/callback",
    }
)
grants = GrantManager(auth=auth, store=MemoryGrantStore())  # demo only
handlers = AuthHandlers(
    auth=auth,
    grants=grants,
    sessions=MemorySessionStore(),  # demo only
    secret=required("AUTH_COOKIE_SECRET"),  # >= 32 random characters
)

app = FastAPI()
install_auth(app, handlers)  # /auth/login /callback /me /logout /backchannel-logout
current_session = require_auth(handlers)


@app.get("/api/me")
async def me(session: Annotated[Session, Depends(current_session)]) -> str:
    return session.claims.sub
```

Close the client at shutdown with `await auth.aclose()` (or `async with AuthClient(...)`). Other frameworks: build a `WebRequest` on `handlers.origin` (never the `Host` header), call `await handlers.handle(request)` (a `WebResponse` or `None`), and send every header pair of the response, `Set-Cookie` included. See the "Other frameworks" page for an ASGI bridge (Litestar, Django under ASGI).

## Common tasks

- **Configuration** is `AuthClientConfig` (frozen pydantic; snake_case fields `issuer`, `client_id`, `client_secret`, `token_endpoint_auth_method`, `redirect_uri`, `post_logout_redirect_uri`, `scopes`, `resources`, `gateway_url`, `clock_tolerance_seconds`, `timeout_seconds`); an invalid value raises `AuthAiError` with code `CFG_001`.
- **Entitlements**: `has_role(claims, "admin")`, `has_permission(claims, "reports", "write")` (write implies read), `has_feature(claims, "beta")`, `get_feature(claims, "seats")`. Enforce on the server.
- **Wallet and gateway** (needs `gateway_url`): `user = AiClient(auth=auth, grants=grants).for_user(sub)`; `await user.wallet.get_account()` (amounts are `int` micro-euros: use `format_euros(balance)`; decide with `can_spend`); `await user.gateway.post_json("/v1/chat/completions", {"model": ..., "messages": [...], "metadata": {"session_id": ...}})`; OpenAI-compatible SDK: `AsyncOpenAI(base_url=gateway.openai_base_url, api_key="unused", http_client=gateway.create_http_client())` (you close the http client). `402` is `GW_001` (`is_insufficient_credit`), `429` is `GW_002`.
- **Billing and consumption** (backend only, needs `client_secret`): `machine = MachineApi(auth)`; `await machine.billing.get_subscription(sub)`, `.get_usage(sub)`, `.list_invoices(sub, limit=50, cursor=None)`; `await machine.consumption.report(sub, "exports", 1, idempotency_key="...")`, `.list_aggregates(sub)`, `.get_aggregate(sub, key)`.
- **Protect an API**: `BearerVerifier(auth, audience="https://api.example.com")`, then `token = await verifier.verify_header(request.headers.get("authorization"))` and `require_scopes(token, "roles")`; serve `protected_resource_metadata(auth, resource=...)` at `protected_resource_metadata_path(resource)` and answer 401/403 with `bearer_challenge(metadata_url, error=...)`.
- **Frontend**: not in this package. Use `createBrowserAuth()` and the React/Vue bindings of `@circle-rd/auth-ai`; the browser only holds an opaque session cookie.

## Production rules

- Implement `SessionStore`, `GrantStore` (encrypted refresh tokens) on your database (the `Memory*` classes are for demos and one process).
- With several replicas or workers, pass a distributed `GrantLock` (an async context manager `hold(grant_id)`) to `GrantManager` and a shared `ReplayStore` to `AuthHandlers(replay_store=...)`.
- Cookie secret >= 32 random characters from the environment; the SDK reads no environment variable itself.
- Set `on_error` and log `error.to_json()`; answer users with `error.to_public_json()` only. Do not log query strings (the callback carries the authorization code; uvicorn's access log prints them by default).
- Check `Origin` on your own state-changing routes.

## Troubleshooting by error code

| Code | Likely cause and fix |
| --- | --- |
| `CFG_001` | Invalid config: `issuer` with trailing slash or not HTTPS, `redirect_uri` path not `<base_path>/callback`, cookie secret < 32 chars, machine API without `client_secret`, `gateway_url` missing for `.gateway`. |
| `SES_005` | Every failed `/auth/callback` answers this; the real cause is passed to `on_error` (look for `SES_003`: ID token without `sid`, `OIDC_003`: wrong client secret, `SES_002`: expired or foreign handshake cookie). |
| `OIDC_001` | Discovery failed: check `issuer` is reachable. |
| `TOK_002` | No usable grant: the user must sign in again. |
| `TOK_004` | Missing scope: `details["missing"]` for `require_scopes`, `details["scope"]` for a machine scope a superadmin must grant. |
| `GW_001` | Wallet empty (402): send the user to `wallet.topup_url()`. |
| `GW_003` | Gateway refused credentials or resource (401/403): check LiteLLM support and the user's plan. |

More: https://docs.circle-cyber.com/auth-ai-py/docs/reference/error-codes
