#!/bin/sh
set -eu

require_var() {
  var_name="$1"
  var_value="$(eval "printf '%s' \"\${$var_name:-}\"")"

  if [ -z "$var_value" ]; then
    echo "Environment variable $var_name is not set"
    exit 1
  fi
}

warn() {
  echo "Warning: $1"
}

run_migrations() {
  if [ "${DB_LOGGING:-false}" = "true" ]; then
    npx sequelize-cli db:migrate --debug
  else
    npx sequelize-cli db:migrate
  fi
}

require_var APP_NAME
require_var APP_ID
require_var APP_ORIGINS
require_var ISSUER
require_var DEFAULT_ROLES
require_var AVAILABLE_ROLES
require_var DB_LOGGING
require_var ACCESS_TOKEN_TTL
require_var REFRESH_TOKEN_TTL
require_var RATE_LIMIT
require_var DELAY_AFTER
require_var RPID
require_var ORIGINS

if [ -n "${DATABASE_URL:-}" ]; then
  echo "Using DATABASE_URL for database connectivity"
else
  require_var DB_HOST
  require_var DB_PORT
  require_var DB_USER
  require_var DB_NAME
fi

require_var API_SERVICE_TOKEN

if [ "${SEAMLESS_BOOTSTRAP_ENABLED:-false}" = "true" ]; then
  require_var SEAMLESS_BOOTSTRAP_SECRET
fi

if [ "${NODE_ENV:-development}" = "production" ]; then
  require_var SEAMLESS_JWKS_ACTIVE_KID
  require_var JWKS_PUBLIC_KEYS

  active_kid="${SEAMLESS_JWKS_ACTIVE_KID}"
  private_key_var="SEAMLESS_JWKS_KEY_${active_kid}_PRIVATE"
  require_var "$private_key_var"
fi

aws_region="${MESSAGING_AWS_REGION:-${AWS_REGION:-${REGION:-}}}"
email_from="${MESSAGING_EMAIL_FROM:-${SES_EMAIL:-}}"
sms_provider="$(printf '%s' "${MESSAGING_SMS_PROVIDER:-${SMS_PROVIDER:-}}" | tr '[:upper:]' '[:lower:]')"
sms_from="${MESSAGING_SMS_FROM:-${TWILIO_PHONE_NUMBER:-}}"
twilio_account_sid="${MESSAGING_TWILIO_ACCOUNT_SID:-${TWILIO_ACCOUNT_SID:-}}"
twilio_auth_token="${MESSAGING_TWILIO_AUTH_TOKEN:-${TWILIO_AUTH_TOKEN:-}}"

if [ -n "$email_from" ] && [ -z "$aws_region" ]; then
  echo "Environment variable MESSAGING_AWS_REGION or AWS_REGION is required when MESSAGING_EMAIL_FROM is set"
  exit 1
fi

case "$sms_provider" in
  "")
    ;;
  aws)
    if [ -z "$aws_region" ]; then
      echo "Environment variable MESSAGING_AWS_REGION or AWS_REGION is required when MESSAGING_SMS_PROVIDER=aws"
      exit 1
    fi
    ;;
  twilio)
    if [ -z "$twilio_account_sid" ] || [ -z "$twilio_auth_token" ] || [ -z "$sms_from" ]; then
      echo "MESSAGING_TWILIO_ACCOUNT_SID, MESSAGING_TWILIO_AUTH_TOKEN, and MESSAGING_SMS_FROM are required when MESSAGING_SMS_PROVIDER=twilio"
      exit 1
    fi
    ;;
  *)
    echo "Unsupported MESSAGING_SMS_PROVIDER: $sms_provider"
    exit 1
    ;;
esac

if [ "${NODE_ENV:-development}" = "production" ] && [ -z "$email_from" ] && [ -z "$sms_provider" ]; then
  warn "Direct email/SMS delivery is not configured. This is fine when using external delivery mode via a SeamlessAuth server adapter."
fi

echo "Generating JWKS keys"
node ./dist/scripts/initKeys.js
echo "JWKS keys ready"

echo "Running migrations..."

if ! run_migrations; then
  echo "Initial migration failed. Attempting database creation..."

  if npm run db:create; then
    echo "Database created. Retrying migrations..."
    run_migrations
  else
    echo "Database creation failed"
    exit 1
  fi
fi

echo "Starting application"
exec npm run start
