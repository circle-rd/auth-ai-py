export default defineAppConfig({
  seo: {
    title: "CIRCLE auth-ai (Python)",
    description:
      "Python SDK for applications relying on a CIRCLE auth-service identity provider: backend-for-frontend OIDC sign-in, entitlements, billing, credit wallet and LiteLLM gateway.",
  },
  header: {
    title: "CIRCLE auth-ai (Python)",
    logo: {
      light: "/logo-light.svg",
      dark: "/logo-dark.svg",
      alt: "CIRCLE",
    },
  },
  socials: {
    github: "https://github.com/circle-rd/auth-ai-python",
  },
  github: {
    url: "https://github.com/circle-rd/auth-ai-python",
    branch: "main",
    rootDir: "docs-site",
  },
});
