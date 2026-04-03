#!/bin/sh
set -eu pipefail

required_vars="APP_NAME APP_ID APP_ORIGINS ISSUER AUTH_MODE DB_HOST DB_PORT DB_USER DB_PASSWORD DB_NAME DEFAULT_ROLES AVAILABLE_ROLES DB_LOGGING ACCESS_TOKEN_TTL REFRESH_TOKEN_TTL RATE_LIMIT DELAY_AFTER API_SERVICE_TOKEN JWKS_ACTIVE_KID RPID ORIGINS"

for var in $required_vars; do
  if [ -z "$(eval echo \$$var)" ]; then
    echo "Environment variable $var is not set"
    exit 1
  fi
done

echo "Generating JWKS keys"
node ./dist/scripts/initKeys.js
echo "JWKS keys ready"

echo "Running migrations..."

if ! npx sequelize-cli db:migrate --debug; then
  echo "Initial migration failed. Attempting database creation..."

  if npm run db:create; then
    echo "Database created. Retrying migrations..."
    npx sequelize-cli db:migrate --debug
  else
    echo "Database creation failed"
    exit 1
  fi
fi

echo "Starting application"
if [ "${NODE_ENV:-development}" = "production" ]; then
  echo "Running in production mode"
  exec npm run start
else
  echo "Running in development mode"
  exec npm run dev
fi
