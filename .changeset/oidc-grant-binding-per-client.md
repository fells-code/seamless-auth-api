---
'seamless-auth-api': patch
---

Bind provider lookups and signatures to the grant for the asking client, even when one session has signed in to several clients. The check used to read one grant for the session and compare its client, so a session signed in to two apps could be refused for one of them.
