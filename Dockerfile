# ---------- Build stage ----------
FROM node:20-slim AS builder
WORKDIR /app

RUN apt-get update && \
  apt-get install -y python3 make g++ && \
  rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---------- Runtime stage ----------
FROM node:20-slim AS runner
WORKDIR /app

RUN useradd -m appuser

COPY validateEnvs.sh /usr/local/bin/validateEnvs.sh
RUN chmod +x /usr/local/bin/validateEnvs.sh

COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src/migrations ./src/migrations
COPY --from=builder /app/.sequelizerc ./.sequelizerc

RUN mkdir -p ./keys && \
  chown -R appuser:appuser /app

ENV NODE_ENV=production

EXPOSE 5312

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node dist/healthCheck.js

USER appuser

ENTRYPOINT ["/usr/local/bin/validateEnvs.sh"]
