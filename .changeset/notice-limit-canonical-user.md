---
'seamless-auth-api': patch
---

The per-user limit on `POST /applications/account-notices` now folds the `userId` to lower case before counting (#553). Upper-case variants of one UUID no longer each get their own allowance of 10 notices an hour.
