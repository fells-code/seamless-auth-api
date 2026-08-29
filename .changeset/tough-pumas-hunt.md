---
'seamless-auth-api': patch
---

Resolve the high severity advisories in the dependency tree.

`npm audit fix` cleared six high severity findings, all transitive, with no
change to `package.json` and no change in behaviour. Two moderate advisories
remain from `sequelize`, whose only offered fix is a downgrade to version 3.
