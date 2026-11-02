# Security policy

`auth-ai` sits on the sign-in path of the applications that use it, so we treat
vulnerability reports seriously.

## Supported versions

Only the latest published minor version receives security fixes. While the major
version is `0`, upgrade to the newest `0.x` release to get them.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub:
[Report a vulnerability](https://github.com/circle-rd/auth-ai-python/security/advisories/new).

Please include the affected version, the module involved (`auth_ai.web`,
`auth_ai.server`, `auth_ai.starlette`…), a minimal reproduction, and the impact you see.
We aim to acknowledge a report within 3 working days and to ship a fix, or a mitigation
plan, within 30 days. You will be credited in the advisory unless you prefer otherwise.

## Scope

In scope: authentication or authorization bypass, session fixation or theft, token
leakage (to a browser, a log, an error), open redirects, CSRF on the SDK's routes,
back-channel logout token acceptance flaws, replay, injection, and unsafe defaults.

Out of scope: weaknesses of the host application's own routes, of an in-memory store
used in production against the documentation, or of auth-service or LiteLLM themselves
(report those to their projects).

## Design guarantees you can rely on

- Access and refresh tokens never reach the browser in the backend-for-frontend setup.
- HTTP responses of the SDK carry an error code and a generic message only.
- Every failed sign-in callback answers the same `403`, whatever the cause.
- The gateway token is only sent to the gateway's origin.

Dependencies are audited on every pull request (`pip-audit`).
