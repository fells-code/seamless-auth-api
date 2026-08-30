---
'seamless-auth-api': patch
---

Stop untrusted values reaching the log and the audit trail intact.

Log messages interpolate request paths, provider ids and similar caller-supplied
values through template strings across the codebase. A newline in one of those
let a caller forge a second log entry. Control characters are now escaped
centrally in the logger format, the single place every line already passes
through for redaction, rather than at each call site where one missed
interpolation reopens it.

`redactSensitiveValue` built its output on a plain object, so a `__proto__` key
in audit metadata hit the prototype setter instead of creating a property: the
key vanished from the redacted output unredacted, and replaced that object's
prototype with caller-supplied content. The output is now built on a null
prototype, so the key is recorded as ordinary data.

Dev signing key generation checked for a key file and then wrote one, so two
processes starting together could both generate and both write, leaving one
signing with a key that was neither on disk nor published in JWKS. Both paths
now create the file exclusively and adopt the winner's key on losing the race.

The slug trim matches a single leading or trailing dash rather than a run. The
preceding collapse leaves no two dashes adjacent, so a run cannot occur, and
matching one made the trim backtrack over an input of many dashes for a
repetition that was never there.
