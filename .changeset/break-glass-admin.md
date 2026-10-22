---
'seamless-auth-api': minor
---

Break-glass admin accounts that no sign-in policy can lock out (#401).

- New `BREAK_GLASS_EMAILS` (comma separated, matched case-insensitively). A listed account that holds a role satisfying `admin:write` is exempt from `login_methods`, `phishing_resistant_only`, `passkey_login_fallback_enabled` and `recovery_codes.enabled` for its own sign-in, and from `authenticator_policy` when it enrolls a passkey. A listed address without the role gets no exemption, and boot logs how many listed entries are not admin accounts.
- A break-glass account still needs a strong factor: a passkey, TOTP or a recovery code. Email OTP, SMS OTP, magic links and OAuth are refused for it (`403 login_method_disabled`) even where they are enabled for everyone else, and session issuance refuses them as a backstop. Lockout still applies to its TOTP.
- `/login` adds a break-glass account's passkey when `login_methods` leaves passkeys out, and lets one holding only TOTP or recovery codes continue where it would otherwise be answered as a decoy. Its `loginMethods` is otherwise shaped like any account's, so it can list methods the account is then refused.
- Every sign-in that relied on the exemption records a new `break_glass_sign_in` auth event with `severity: "high"` in its metadata and emails a notice to every admin account with a verified email.

See the Break-glass admin section of docs/admin-operations.md.
