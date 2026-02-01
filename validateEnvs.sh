#!/bin/sh

required_vars="DB_OPERATOR DB_KEY DB_SCHEMA DB_URI APP_ORIGIN APP_NAME ACCESS_TOKEN_TTL REFRESH_TOKEN_TTL AWS_REGION SES_EMAIL ORIGINS RPID AUTH_MODE OWNER_EMAILS"

for var in $required_vars; do
  if [ -z "$(eval echo \$$var)" ]; then
    echo "Environment variable $var is not set!"
    env
    exit 1
  fi
done

echo "Generating JWKS keys"
if ! node dist/scripts/initKeys.js; then
  echo "Key creatione failed to run"
  exit 1
fi
echo "Done Creating JWKS keys"

echo "Running database migrations..."
npx sequelize-cli db:migrate

echo "Starting server..."
exec node dist/server.js
