# Stage 1 — build
FROM node:24-alpine AS builder
WORKDIR /app
RUN apk add --no-cache python3 make g++
ARG NUXT_APP_BASE_URL=/auth-ai/python/
ARG NUXT_SITE_URL=https://docs.circle-cyber.com/auth-ai/python
ENV NUXT_APP_BASE_URL=${NUXT_APP_BASE_URL}
ENV NUXT_SITE_URL=${NUXT_SITE_URL}
COPY package.json ./
RUN npm install
COPY . .
RUN npx nuxt build

# Stage 2 — runtime
FROM node:24-alpine
WORKDIR /app
COPY --from=builder /app/.output ./.output
ARG NUXT_APP_BASE_URL=/auth-ai/python/
ARG NUXT_SITE_URL=https://docs.circle-cyber.com/auth-ai/python
ENV HOST=0.0.0.0
ENV PORT=3000
ENV NODE_ENV=production
ENV NUXT_APP_BASE_URL=${NUXT_APP_BASE_URL}
ENV NUXT_SITE_URL=${NUXT_SITE_URL}
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO /dev/null http://127.0.0.1:3000/_health || exit 1
CMD ["node", ".output/server/index.mjs"]
