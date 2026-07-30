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
# Fetches the admin dashboard SPA at a PINNED ref and runs its own same-origin build
# (`build:console` sets VITE_BASE_PATH=/console/ and VITE_SAME_ORIGIN=true, so assets, the
# React Router basename, and the origin-derived API base all agree). This API then serves the
# result at /console. The dashboard repo is public, but its npm package is not published
# (package.json is marked private), so it is fetched from git. The pinned ref is a commit that
# includes the dashboard's same-origin build; bump SEAMLESS_ADMIN_DASHBOARD_REF (to a release
# tag once one is cut) to ship a new dashboard on the next auth-image release. Never point a
# release build at a floating branch.
FROM node:24-slim AS admin-dashboard
WORKDIR /dashboard

ARG SEAMLESS_ADMIN_DASHBOARD_REPO=https://github.com/fells-code/seamless-auth-admin-dashboard.git
# Pinned dashboard release tag. v0.2.0 is the first release with the same-origin /console build.
ARG SEAMLESS_ADMIN_DASHBOARD_REF=v0.4.0

RUN apt-get update && \
  apt-get install -y git python3 make g++ && \
  rm -rf /var/lib/apt/lists/*

# Full clone + checkout so the ref can be a tag, branch, or commit SHA.
RUN git clone "${SEAMLESS_ADMIN_DASHBOARD_REPO}" . && \
  git checkout "${SEAMLESS_ADMIN_DASHBOARD_REF}"
RUN npm ci
RUN npm run build:console

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