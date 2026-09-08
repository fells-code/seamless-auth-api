---
'seamless-auth-api': patch
---

OAuth provider edits log once, from the code that commits them.

The three handlers each logged their own line after `editProviders` returned, while the
comment explaining why interpolating a caller-supplied provider id into a log line is safe
sat above an unrelated type declaration. That comment is the recorded reasoning behind
three dismissed CodeQL `js/log-injection` alerts, so it has to be findable by whoever
changes the code it describes.

The line now lives in `editProviders`, next to the audit event, with the reasoning on it.
Its wording changes from `Created OAuth provider <id>` to `OAuth provider <id> created`,
since the verb is taken from the same audit record the event uses. Nothing else changes:
same level, same trigger, no response or contract effect.
