---
'seamless-auth-api': patch
---

Pull `follow-redirects` 1.16.1, which fixes GHSA-q3jh-wrc6-jgq8 and GHSA-8r9p-f939-6h3c (credential headers kept on a cross-origin redirect). It reaches the server through Twilio's HTTP client, used only for direct SMS delivery.
