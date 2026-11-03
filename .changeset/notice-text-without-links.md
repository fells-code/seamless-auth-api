---
'seamless-auth-api': patch
---

Application notice text can no longer carry its own links (#554). `POST /applications/account-notices` refuses with `400` a `text` that contains a URL, a `www.` address, a domain name or an email address, since mail and SMS clients turn all of them into links; `actionUrl`, checked against the application's origins, is the only link a notice carries. The `Sent by <application> through <instance>.` attribution is now the first line of the message, ahead of the text, rather than a footer the text could imitate. Adapters that render notices from external delivery receive the new layout in `text`.
