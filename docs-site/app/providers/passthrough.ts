// Nuxt UI hands images a src that already carries app.baseURL (/auth-ai-python/…),
// which the default IPX provider then prefixes again and fails to resolve in
// public/. The assets are already optimized, so serve them as-is.
export default () => ({
  getImage: (src: string) => ({ url: src }),
});
