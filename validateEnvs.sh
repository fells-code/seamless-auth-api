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
if [ "${NODE_ENV:-development}" = "production" ]; then
  echo "Running in production mode"
  npx tsx ./dist/scripts/initKeys.ts
else
  echo "Running in development mode"
  npx tsx ./src/scripts/initKeys.ts
fi
echo "JWKS keys ready"

if ! PGPASSWORD=$DB_PASSWORD psql -h "$DB_HOST" -U "$DB_USER" -p "$DB_PORT" -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
  echo "Database does not exist. Creating..."
  npm run db:create
fi

echo "Running migrations..."
npx sequelize-cli db:migrate

if [ "${NODE_ENV:-development}" = "production" ]; then
  echo "Running in production mode"
  exec npm run start
else
  echo "Running in development mode"
  exec npm run dev
fi