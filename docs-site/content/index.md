---
seo:
  title: CIRCLE auth-ai (Python) — Python SDK for auth-service applications
  description: Python SDK for applications relying on a CIRCLE auth-service identity provider. Async backend-for-frontend OIDC sign-in, entitlements from claims, back-channel logout, bearer token verification, credit wallet, LiteLLM gateway client, billing and consumption.
---

:::u-page-hero{.circle-hero}
#title
CIRCLE auth-ai (Python)

#description
A Python SDK for applications that sign their users in through a [CIRCLE auth-service](https://docs.circle-cyber.com/auth-service/). Run the OIDC flow on your asyncio backend, keep tokens off the browser, read roles and plan features, and let users call LLMs through the LiteLLM gateway against their credit wallet. It is the Python port of the [TypeScript SDK](https://docs.circle-cyber.com/auth-ai/typescript/), with the same wire contract.

#links
::::u-button{to="/docs/getting-started/introduction" size="xl" trailing-icon="i-lucide-arrow-right" color="neutral"}
Get started
::::

::::u-button{to="https://docs.circle-cyber.com/auth-ai/typescript/" size="xl" variant="outline" color="neutral" icon="i-simple-icons-typescript"}
TypeScript SDK
::::

::::u-button{to="https://github.com/circle-rd/auth-ai-py" target="_blank" size="xl" variant="outline" color="neutral" icon="i-simple-icons-github"}
GitHub
::::
:::

:::u-page-section{.circle-section}
#title
What it does

#features
::::u-page-feature{icon="i-lucide-shield-check" title="Backend-for-frontend sign-in" description="Authorization code flow with PKCE on your server. The browser only holds an opaque, HttpOnly session cookie: access and refresh tokens never reach it."}
::::

::::u-page-feature{icon="i-lucide-key-round" title="Grants and per-audience tokens" description="One refresh-token chain per user, rotated under a lock, and short-lived access tokens minted per audience (RFC 8707) for your API, the gateway and auth-service."}
::::

::::u-page-feature{icon="i-lucide-users" title="Entitlements from claims" description="Roles, permissions, plan features and organisation are read from the ID token and renewed from the provider on a schedule. has_role, has_permission, has_feature and get_feature are typed helpers."}
::::

::::u-page-feature{icon="i-lucide-log-out" title="Back-channel logout" description="OIDC Back-Channel Logout verified and replay-protected: signing out of auth-service ends your local sessions and revokes the grant."}
::::

::::u-page-feature{icon="i-lucide-wallet" title="Credit wallet and LiteLLM gateway" description="Read the user's prepaid balance and spend, and call an OpenAI-compatible gateway with the user's own token through an httpx2 client. The gateway debits the wallet; your app never handles a debit."}
::::

::::u-page-feature{icon="i-lucide-receipt" title="Billing and consumption" description="From your backend with a machine token: read a user's subscription, metered usage and invoices, and report consumption with idempotency keys."}
::::

::::u-page-feature{icon="i-lucide-lock" title="Protect an API" description="Verify JWT bearer tokens for your own audience, require scopes, and publish RFC 9728 protected-resource metadata so MCP and OAuth clients can discover the provider."}
::::

::::u-page-feature{icon="i-lucide-layers" title="FastAPI, Starlette, any ASGI framework" description="An adapter for FastAPI and Starlette, and framework-agnostic WebRequest and WebResponse handlers you can bridge to any other framework."}
::::

::::u-page-feature{icon="i-lucide-code" title="Async and typed" description="Python 3.12 or later, built on httpx2 and pydantic, shipped with type information (py.typed). Pair it with the TypeScript browser client and the React and Vue bindings."}
::::

::::u-page-feature{icon="i-lucide-triangle-alert" title="Errors safe to show" description="Every failure is an AuthAiError with a stable code. Details stay in your logs; HTTP responses carry the code and a generic message only."}
::::
:::
