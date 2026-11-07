# Certification reference relying party

A polished OpenID Connect relying party used to run the OpenID Foundation client
certification plans for the Python SDK. It implements the authorization-code flow
with PKCE, UserInfo enrichment, RP-initiated logout with `state`, and back-channel
logout.

## Environment

- `PUBLIC_URL` — public origin, e.g. `https://test-py.circle-cyber.com`
- `AUTH_ISSUER` — `https://auth.circle-cyber.com`
- `AUTH_CLIENT_ID` / `AUTH_CLIENT_SECRET` — the registered static client
- `COOKIE_SECRET` — at least 32 characters
- `PORT` — defaults to `3000`

Register these URIs on the auth-service application:

- redirect URI: `<PUBLIC_URL>/auth/callback`
- post-logout URI: `<PUBLIC_URL>/auth/logout/callback`
- back-channel logout URI: `<PUBLIC_URL>/auth/backchannel-logout`

The client must use `client_secret_basic`, PKCE, and the scopes
`openid profile email roles permissions features offline_access`.

The OIDF mock OP currently omits the required `typ=logout+jwt` header from its
back-channel logout tokens. This reference app opts into accepting a missing `typ`
only for that conformance mismatch; the SDK default remains strict and rejects
missing or incorrect values.
