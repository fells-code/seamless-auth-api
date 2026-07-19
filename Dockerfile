# ---------- Build stage ----------
FROM node:24-slim AS builder
WORKDIR /app

RUN apt-get update && \
  apt-get install -y python3 make g++ && \
  rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

RUN npm prune --omit=dev

# ---------- Admin dashboard build stage ----------
# Fetches the admin dashboard SPA at a PINNED ref and builds the same-origin /console variant
# (base path /console) that this API serves at /console. The dashboard repo is public, but its
# npm package is not published (package.json is marked private), so it is fetched from git by tag.
# Bump SEAMLESS_ADMIN_DASHBOARD_REF
# to ship a new dashboard to tenants on the next auth-image release; never point a release build
# at a floating branch. The dedicated same-origin build (origin-derived API, /console base) is a
# coordinated dashboard PR; until it merges, point the ref at that PR's branch and this stage
# still builds a /console-based bundle via the --base override below.
FROM node:24-slim AS admin-dashboard
WORKDIR /dashboard

ARG SEAMLESS_ADMIN_DASHBOARD_REPO=https://github.com/fells-code/seamless-auth-admin-dashboard.git
ARG SEAMLESS_ADMIN_DASHBOARD_REF=v0.1.1

RUN apt-get update && \
  apt-get install -y git python3 make g++ && \
  rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${SEAMLESS_ADMIN_DASHBOARD_REF}" \
  "${SEAMLESS_ADMIN_DASHBOARD_REPO}" .
RUN npm ci
RUN npx vite build --base=/console/

# ---------- Runtime stage ----------
FROM node:24-slim AS runner
WORKDIR /app

RUN useradd -m appuser

COPY validateEnvs.sh /usr/local/bin/validateEnvs.sh
RUN chmod +x /usr/local/bin/validateEnvs.sh

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src/config ./src/config
COPY --from=builder /app/src/migrations ./src/migrations
COPY --from=builder /app/.sequelizerc ./.sequelizerc

# Admin dashboard SPA, served at /console when SERVE_ADMIN_DASHBOARD is not "false".
COPY --from=admin-dashboard /dashboard/dist ./admin-dashboard

RUN mkdir -p ./keys && \
  chown -R appuser:appuser /app

ENV NODE_ENV=production

EXPOSE 5312

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node dist/healthCheck.js

USER appuser

ENTRYPOINT ["/usr/local/bin/validateEnvs.sh"]