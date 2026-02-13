#!/bin/sh
set -eu pipefail

required_vars="APP_NAME APP_ID APP_ORIGIN ISSUER AUTH_MODE DEMO DB_HOST DB_PORT DB_USER DB_PASSWORD DB_NAME DEFAULT_ROLES AVAILABLE_ROLES DB_LOGGING ACCESS_TOKEN_TTL REFRESH_TOKEN_TTL RATE_LIMIT DELAY_AFTER API_SERVICE_TOKEN JWKS_ACTIVE_KID RPID ORIGINS"

for var in $required_vars; do
  if [ -z "$(eval echo \$$var)" ]; then
    echo "Environment variable $var is not set"
    exit 1
  fi
done

echo "Generating JWKS keys"
npx tsx ./src/scripts/initKeys.ts
echo "JWKS keys ready"

echo "Running migrations..."
npx sequelize-cli db:migrate --debug

echo "Starting application"
exec npm run dev
