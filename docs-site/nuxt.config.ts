export default defineNuxtConfig({
  extends: ["docus"],
  app: {
    baseURL: process.env.NUXT_APP_BASE_URL ?? "/auth-ai-py/",
  },
  site: {
    url: process.env.NUXT_SITE_URL ?? "https://docs.circle-cyber.com/auth-ai-py",
    name: "CIRCLE auth-ai (Python)",
  },
  robots: { robotsTxt: false },
  image: {
    provider: "passthrough",
    providers: {
      passthrough: { name: "passthrough", provider: "~/providers/passthrough" },
    },
  },
  meta: {
    title: "CIRCLE auth-ai (Python)",
    description:
      "Python SDK for applications relying on a CIRCLE auth-service identity provider: OIDC sign-in (backend-for-frontend), entitlements, billing, credit wallet and LiteLLM gateway.",
    ogHost: process.env.NUXT_SITE_URL ?? "https://docs.circle-cyber.com/auth-ai-py",
  },
  llms: {
    title: "CIRCLE auth-ai (Python)",
    description:
      "Python SDK (auth-ai on PyPI, imported as auth_ai) for applications relying on a CIRCLE auth-service identity provider: OIDC sign-in (backend-for-frontend), entitlements, billing, credit wallet and LiteLLM gateway.",
    full: {
      title: "CIRCLE auth-ai (Python) — Complete Documentation",
      description:
        "Complete documentation for auth-ai, the Python SDK for applications that sign users in through a CIRCLE auth-service. Covers the async OIDC client, the backend-for-frontend sign-in handlers with the Starlette and FastAPI adapter, bearer token verification, back-channel logout, the credit wallet, the LiteLLM gateway client, billing and consumption, configuration and the error code registry.",
    },
    sections: [
      {
        title: "Developer Resources",
        description: "Machine-readable entry points for this project.",
        links: [
          {
            title: "CIRCLE auth-ai (Python) on GitHub",
            description: "Source, issues and releases of the Python SDK.",
            href: "https://github.com/circle-rd/auth-ai-py",
          },
          {
            title: "CIRCLE auth-ai (TypeScript) documentation",
            description:
              "The TypeScript SDK this one is ported from, with the browser client and the React and Vue bindings.",
            href: "https://docs.circle-cyber.com/auth-ai/",
          },
          {
            title: "CIRCLE auth-service documentation",
            description:
              "The identity provider this SDK talks to: applications, claims, wallet, LiteLLM gateway.",
            href: "https://docs.circle-cyber.com/auth-service/",
          },
        ],
      },
    ],
    notes: [
      "This is the Python port of the TypeScript SDK @circle-rd/auth-ai (documented at https://docs.circle-cyber.com/auth-ai/). Both SDKs share the same wire contract: the backend-for-frontend routes, the sealed login cookie format, the cookie names and the error code registry.",
      "When to use CIRCLE auth-ai (Python): in an asyncio Python backend (FastAPI, Starlette, or another framework through a small adapter) that signs users in through a CIRCLE auth-service instance (OIDC authorization code with PKCE, backend-for-frontend) and, optionally, reads the user's credit wallet and calls the LiteLLM gateway on the user's behalf.",
      "CIRCLE auth-ai is built for auth-service (its claims and its wallet, billing and consumption REST routes): it is not a client for arbitrary OIDC providers, and it is not an identity provider. To run the provider, use the auth-service documentation at https://docs.circle-cyber.com/auth-service/.",
      "Tokens stay on the server: the browser only holds an opaque session cookie. The SDK has no debit API: the gateway debits the wallet after each call.",
      "The SDK is async only (httpx), requires Python 3.12 or later, and is a 0.x release whose public API is not stable yet. There is no Django or Flask adapter yet (the framework-agnostic handlers in auth_ai.web can be mounted anywhere) and no synchronous facade.",
      "The browser client and the React and Vue bindings are not part of this package: pair the Python backend with the TypeScript package @circle-rd/auth-ai, documented at https://docs.circle-cyber.com/auth-ai/.",
      "Reading this documentation as an agent: every page is also served as markdown under /raw/, for example https://docs.circle-cyber.com/auth-ai-py/raw/docs/concepts/architecture.md. The full text is at https://docs.circle-cyber.com/auth-ai-py/llms-full.txt and a page index at https://docs.circle-cyber.com/auth-ai-py/llms.txt.",
    ],
  },
});
