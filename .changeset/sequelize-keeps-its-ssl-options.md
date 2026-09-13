---
'seamless-auth-api': patch
---

Keep the TLS options when `DATABASE_URL` carries `sslmode`. `resolveSslOptions` turns `DB_SSL`,
or an `sslmode` on the connection string, into Sequelize's `dialectOptions.ssl`, but Sequelize
then read the same `sslmode` for itself and let pg-connection-string's reading of it replace
those options. A URL carrying the parameter had its certificate verified whatever `DB_SSL` or
`DB_SSL_REJECT_UNAUTHORIZED` said, which against Amazon RDS is a boot failure, and `DB_SSL=false`
could not turn TLS off for it. Sequelize is now constructed with `sslmode` taken out of the URL,
once `resolveSslOptions` has read it. Nothing changes on the discrete `DB_*` path, whose URL
never carries the parameter.
