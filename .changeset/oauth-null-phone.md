---
'seamless-auth-api': patch
---

Fix OAuth signup writing a synthetic `oauth:<provider>:<subject>` string into the user's phone field. New OAuth users now have a null phone since the provider supplies no phone number.
