---
'seamless-auth-api': minor
---

Auth policy changes are versioned, can be staged as a draft, and can be dry-run and rolled back.

- New routes under `/system-config/policy`: read the published version and draft, save or discard the draft, publish it, roll back to an earlier version, list versions, and dry-run a policy against recent sign-ins. Publish and rollback need `admin:write` and a fresh step-up, take `expectedVersion`, and answer `409 policy_version_conflict` when another version was published since.
- Every policy change is recorded in the new `policy_versions` table, including a whole-config `PATCH /system-config/admin` that changes a policy key (source `config_patch`). The first boot after upgrading records the policy in force as version 1 (source `bootstrap`). Run the migration before starting this release.
- The dry run reports, per account that signed in during the window, the sign-ins a candidate policy would refuse and whether the account would be locked out. It evaluates at most 10,000 accounts. Accounts in `BREAK_GLASS_EMAILS` are counted, never listed.
- New auth event types: `policy_draft_saved`, `policy_draft_discarded`, `policy_published`, `policy_rolled_back` and `policy_dry_run`.

The dry run also reports `authenticator_not_allowed` and `synced_passkey_blocked` for an account holding a passkey the candidate authenticator policy would not admit at enrollment. Those passkeys keep signing in, so such an entry counts no refused sign-in and is never `lockedOut`.
