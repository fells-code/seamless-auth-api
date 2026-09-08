---
'seamless-auth-api': patch
---

Creating two organizations with the same name at once now suffixes the slug instead of
answering `500`.

`buildUniqueSlug` ran before the transaction that creates the organization, so the check
it exists to perform was not serialised against a concurrent create. Two requests for
"Acme" both found `acme` free and both returned it; one insert committed and the other
violated the unique index on `organizations.slug`, which nothing handled, so the caller
saw `500 { "error": "Internal server error" }` where `acme-2` was the intended answer.

Resolving the slug inside the transaction would not have fixed it, because a slug that
does not exist yet has no row to lock, so the index is the only thing that actually
serialises this. The retry is therefore driven by the violation: a slug collision rolls
back, reads the now committed list and takes the next suffix, up to five times before the
error surfaces. Any other failure is unchanged.
