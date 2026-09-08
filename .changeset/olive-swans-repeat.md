---
'seamless-auth-api': minor
---

Validate and document the window on `GET /admin/users`.

The route has always read `limit`, `offset` and `search`, but it declared no
query schema, so it was the one admin collection whose parameters were absent
from `openapi.json`. A generated client could not know they existed, and a
reader checking the document would conclude the endpoint took none. That is the
same wrong inference that led to organization paging being reported missing.

The parameters are now declared, so they appear in the generated contract
alongside the ones on `/admin/sessions`, `/admin/auth-events` and
`/admin/organizations`, and they are validated the same way: `limit` between 1
and 100 defaulting to 50, `offset` from 0, and `search` trimmed.

Two inputs that used to be accepted are now rejected with a `400`. A `limit`
above 100 was previously honoured in full, so a single call could ask for every
user in the deployment. A non-numeric `limit` reached Sequelize as `NaN` and
failed in the database rather than at the edge. An all-whitespace `search` built
a `%%` pattern that matched every row, so a filter that looked empty returned
the unfiltered list.

`seamless-cli` accepts `users list --limit 0` deliberately, meaning ask for
nothing, and that value is now a `400`. The flag needs a floor of 1, or to skip
the request when asked for zero rows.
