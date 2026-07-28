---
'seamless-auth-api': minor
---

Support TLS to Postgres. `DB_SSL` (`true`/`false`, or an `sslmode` value such as `require` or
`verify-full`) and an `sslmode` query parameter on the connection string now set Sequelize's
`dialectOptions.ssl`, and `DB_SSL_CA` supplies a server CA bundle as inline PEM or a file path.
Certificate verification follows libpq semantics: `require` encrypts without verifying, `verify-ca`
and `verify-full` verify, and supplying a CA bundle turns verification on. `DB_SSL_REJECT_UNAUTHORIZED`
overrides it either way. TLS stays off by default.

`DB_URI` is now accepted as an alias for `DATABASE_URL`. Connection and TLS resolution is shared
between the running app and the startup migrations, so a connection string configured without the
discrete `DB_*` variables no longer breaks migrations.
