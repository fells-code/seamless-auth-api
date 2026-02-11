#!/bin/sh
set -euo pipefail

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

echo "Waiting for database..."
until nc -z "$DB_HOST" "$DB_PORT"; do
  sleep 1
done

echo "Ensuring database exists..."
export PGPASSWORD="$DB_PASSWORD"

psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
  -tc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 \
  || psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
     -c "CREATE DATABASE \"$DB_NAME\""

echo "Running migrations..."
npx sequelize-cli db:migrate --debug

echo "Starting application"
exec npm run dev
