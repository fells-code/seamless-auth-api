# ADR 0005: Webhooks, login hooks, custom claims and SIEM streaming

- **Status:** Accepted
- **Date:** 2026-11-07
- **Issues:** #417, #418, #419, #420, seamless-auth-types#146. Consumers follow in seamless-auth-oidc-provider#47, seamless-auth-server#269, seamless-auth-admin-dashboard#335 and #336, and seamless-cli#343.

## Context

Events are pull-only, and an app cannot change what a sign-in does or what a token carries without forking. Each of the four features makes the API call a URL an adopter chose, so they share one set of rules for reaching it.

What already exists to build on:

- `providerFetch` resolves DNS inside the socket's `lookup`, so the address checked is the address connected to. It refuses link-local addresses in every mode, decodes NAT64, 6to4 and IPv4-mapped forms, and never follows redirects.
- Every sign-in completes in `issueSessionAndRespond`, and every first-party token is minted in `mintAccessToken` (ADR 0004).
- `auth_events` is hash chained by a trigger, and the `seamless-auth-events/1` export carries the exact text hashed.
- TOTP seeds are AES-256-GCM encrypted under an env key.

## Decisions

### E1. Signatures follow Standard Webhooks

Webhooks and login hook calls are signed with the [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md) scheme: headers `webhook-id`, `webhook-timestamp` and `webhook-signature`, HMAC-SHA256 over `${id}.${timestamp}.${body}`, sent as `v1,<base64>`. Secrets are `whsec_` and base64 of 32 random bytes.

- Rotating keeps the old secret signing beside the new one for 24 hours, so the header carries two signatures and a receiver holding either verifies. Only two secrets ever sign.
- Receivers reject a timestamp more than 300 seconds from their clock and dedupe on `webhook-id`.
- Receivers in any language can use an existing verifier. Asymmetric `v1a` is left for later; it would be another signature in the same header.

### E2. Events come from the committed audit log

A dispatcher reads `auth_events` past a cursor (`event_dispatch_cursors`) by `seq` and turns matching rows into deliveries. An event is sent only once its row has committed, nothing is lost between happening and being queued, and the SIEM stream (#420) reads the same rows with the same hashes.

The chain trigger updates the chain head row on every insert and holds that lock until commit, so committed rows always form a gapless prefix of `seq`: the cursor cannot step past a row that is still to commit. On first run the cursor starts at the newest row, so turning webhooks on does not replay history. Replicas take turns through an advisory lock. Delivery workers claim due rows with `FOR UPDATE SKIP LOCKED` and lease them past the request timeout, so a replica that dies mid-send leaves the delivery due again shortly after. The loop polls once a second.

### E3. A small, versioned event catalog

| Webhook type                                          | From audit types                                                                               |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `user.created`                                        | `user_created`                                                                                 |
| `user.deleted`                                        | `user_deleted`                                                                                 |
| `user.signed_in`                                      | `session_created`                                                                              |
| `user.recovered`                                      | `account_recovery_completed`                                                                   |
| `session.revoked`                                     | `logout_success`, `admin_session_revoked`, `session_evicted`, `oidc_session_revoked`           |
| `credential.added`                                    | `registration_success` naming a passkey, `totp_enrollment_success`, `recovery_codes_generated` |
| `credential.removed`                                  | `credentials_deleted` naming a passkey, `totp_disabled`                                        |
| `organization.member_added` / `_updated` / `_removed` | `organization_member_*`                                                                        |

`webhook.test` is sent only by the test endpoint. The mapping is one table in `webhookCatalog.ts`, pinned by a test, so a new audit type reaches no receiver until it is added there.

```json
{
  "id": "delivery uuid, the same as webhook-id",
  "type": "user.signed_in",
  "version": 1,
  "timestamp": "when the event happened",
  "data": { "userId": "...", "sessionId": "...", "method": "passkey", "organizationId": null }
}
```

- `data` carries identifiers and the few fields a receiver acts on. `user.created` also carries the email or phone the account was made with, read from the user at dispatch. No IP address, user agent or free-form metadata: those go to the SIEM.
- Delivery is at least once and unordered.

### E4. Retries, dead letters and storage

- Success is a 2xx within 15 seconds. A redirect is a failure and is not followed.
- Attempts at 0 s, then 5 s, 5 min, 30 min, 2 h, 5 h, 10 h and 24 h after the previous one, with up to 10% jitter: eight attempts, dead just under 42 hours after the event. A longer `Retry-After` is honored, up to 24 hours.
- `410 Gone` disables the endpoint. So do three days in which every delivery failed. Both write `webhook_endpoint_disabled`.
- A delivery stores the exact body sent, so a retry or redelivery sends the same bytes. Responses are read for the status alone, and only the status and a coarse failure reason are kept. Deliveries are pruned after 30 days.
- Redeliver is one attempt now with the same `webhook-id` and body and a fresh timestamp and signature.
- A disabled endpoint still gets its deliveries, held with no attempt due, and a delivery already queued when its endpoint is disabled is held the same way. Turning the endpoint back on releases everything held, so it catches up on what happened while it was off instead of losing it. Deliveries are pruned after 30 days, so that is how far a catch-up reaches. A dead delivery stays dead; redeliver sends it. Decided by Brandon on 2026-11-07, after the webhooks guide found that events during a disable were never queued.

### E5. Login hooks

- `post_login` runs once the factor is proven and before the session exists. It may allow or deny. It cannot add claims.
- `pre_token` runs when a token is minted for a new session and on organization switch. It may add claims or deny. It is not called on refresh: its claims are kept on the session, so refresh never waits on an adopter's server.
- One hook per trigger. Timeout 2 seconds by default, 5 at most, one attempt.
- Failure mode per hook, `closed` by default. A timeout, a non-2xx, a body that does not parse, or claims over the budget fail the sign-in when closed and are ignored when open. Every invocation is audited.
- Break-glass sign-in and recovery sessions never call a hook, so a hook that is down cannot lock out the administrator who would fix it.
- The call carries the user, method, organization, OpenID client, IP and user agent, never a token, code or secret. `reason` in the answer is audited and not shown; `userMessage` (200 characters) is.

### E6. Custom claims

Sources, lowest precedence first: an instance role, an organization role (while that organization is active), an OpenID Provider client (provider tokens only), then the `pre_token` hook. Values are literal JSON up to depth 3, with names matching `^[a-z][a-z0-9_]{0,63}$`.

Reserved, refused when written and stripped (and audited) when a hook returns them: JWT registered claims, OpenID and OAuth protocol claims including `act` and `may_act`, Seamless's own claims, the OpenID standard identity claims (so no source can assert an email address the user never proved), and any name starting `seamless_` or `org_`. The list lives in `@seamless-auth/types/customClaim/reserved`, shared with the provider.

Each static set gets 1 KiB serialized, refused when written over it, and a hook over it has failed. In the token, custom claims share one 1 KiB budget with ADR 0004's permission claims (`permissions`, `org_roles`, `org_permissions`), serialized together, so the adapter cookie holds the worst case. Brandon chose this rule on 2026-11-07:

1. If the permission claims and the merged custom claims fit together, the token carries both.
2. Otherwise permissions give way first, since a guard has a live fallback for them and custom claims have none: the three are replaced with `"permissions_omitted": true` and the custom claims stay, if the custom claims and the marker fit.
3. Only when they do not fit even beside the marker are all custom claims dropped, and the mint writes `custom_claims_omitted`. The token then carries just the marker.
4. Nothing is ever trimmed partially. Recovery tokens carry neither.

Among roles of one kind, sets apply in role-name order, so the last name alphabetically wins a claim two of them set. It is deterministic and does not depend on the order roles were granted in, which an administrator cannot see. The console shows which role wins when two set the same claim. Brandon decided this on 2026-11-07.

### E7. SIEM streaming

- OTLP/HTTP with JSON encoding to `<endpoint>/v1/logs`, and syslog (RFC 5424) over TLS (RFC 5425) with octet counting. Plain TCP only outside production, never UDP.
- Every record carries the event's `seamless-auth-events/1` line, with `seq`, `prevHash`, `hash` and `payload`, so the chain verifies downstream as an export does.
- Each sink has its own cursor and retries until its destination takes the events, backing off to one minute. There is no dead letter: a sink falls behind and reports its lag.
- Credentials are never stored. A sink names env vars ending `_AUDIT_SINK_SECRET`, the same pattern OAuth providers use.

### E8. Every callout follows the same reachability rules

`calloutTransport.ts` serves webhooks, hooks and sinks:

- `https` only in production, no userinfo, never the API's own issuer host.
- DNS resolves inside the socket's `lookup`, and every address a name resolves to must be allowed, which defeats rebinding.
- Link-local, unspecified, multicast and broadcast addresses are never reachable, in any mode, for any host.
- Other private and loopback addresses are refused in production unless the host is listed in `CALLOUT_PRIVATE_HOSTS`. It is an env var, so nothing written through the API can widen it, and it is separate from `OAUTH_PROVIDER_PRIVATE_HOSTS`, so allowing an internal hook service does not also allow it as an identity provider.
- Redirects are never followed. Responses are capped at 64 KiB. The deadline covers the whole request, so a destination that trickles bytes cannot hold a sign-in open.
- URLs are checked when written and again at connect time.
- Failures are reported as `refused`, `timed_out`, `connection_failed`, `http_status`, `invalid_response` or `too_large`, never with the resolved address or the socket's error text, so the delivery log cannot be used to map the internal network.

### E9. Signing secrets are encrypted at rest

They must be read back to sign, so they cannot be hashed. They are AES-256-GCM encrypted under `CALLOUT_SECRET_ENCRYPTION_KEY`, which production requires once a webhook or hook exists, and creating one is refused without it. A secret is shown once, on create and on rotate.

## Found while building

- `login_success` is written when `/login` resolves which methods an identifier may use, before any factor is proven, so it cannot be the source of `user.signed_in`. No event recorded that a session was created. `issueSessionAndRespond` now writes `session_created`, with the method and organization.
- Deleting a passkey (`DELETE /users/credentials`) wrote no audit event. It now writes `credentials_deleted` naming the passkey. Reproducing test first.
- Passkey registration and account registration both write `registration_success`. The passkey path now names the credential in metadata, which is how the catalog tells them apart.
- `organization_member_updated` recorded only what was added and removed. It now records the roles after the change too, which the webhook carries.
- Login hooks (#419):
  - A denied sign-in answers 403 `login_denied`, with the hook's `userMessage` as `message`. A hook that fails closed answers 503 `login_hook_unavailable`, since the user did nothing wrong and can retry.
  - `issueSessionAndRespond` now answers the refusal itself and resolves false, because most sign-in controllers turn a thrown error into a 500. Callers stop there, so a refused sign-in records no last login.
  - Hooks run before the concurrent session limit, so a refused sign-in cannot evict a session the user already had.
  - A `pre_token` claim with a name outside the claim alphabet, or nested past depth 3, fails the hook rather than being dropped. Only reserved names are stripped. Claims over the budget fail as `too_large`.
  - The session that completes a new account's address verification calls hooks like any other sign-in. It is a full session, not a recovery one.
  - A session exchange copies the parent's `pre_token` claims to the child, for both grants, since the claims describe the user rather than the factor.
  - When a mint finds the user has left the session's organization, the session's hook claims are cleared with the organization, since the hook decided them for it.
  - `client` in the call is always null for now: no first-party sign-in knows which OpenID Provider client it is for. The provider can fill it in seamless-auth-oidc-provider#47.
  - A test call sends a placeholder user and no request details, and is not recorded as an invocation.
- Custom claims (#417):
  - Roles of one kind apply in role-name order (E6), rather than the order they are held in. Brandon confirmed this on 2026-11-07.
  - Separate 1 KiB budgets for permissions and custom claims did not fit the server adapter's session cookie: 5670 bytes against 4096 at both, with only about 136 bytes of custom claims fitting beside a full permission set. Brandon chose the shared budget and the order in E6 on 2026-11-07. At the shared budget the worst-case cookie measures 3868 bytes.
  - A set can only be written for a role or client that exists, and retiring the role or deleting the client deletes its set.
  - `z.json()` in the shared claim schemas overflows the OpenAPI generator, so the API's route schemas wrap them and document a claim value as any JSON.
- Provider tokens (seamless-auth-oidc-provider#47):
  - Brandon chose the scope names on 2026-11-07: `permissions` releases `roles`, `permissions`, `org_id`, `org_roles` and `org_permissions` (or `permissions_omitted`), and `custom_claims` releases every custom claim the API resolves for the user and the client. They apply to ID tokens, userinfo, and a user's access token for a resource when the grant holds the scope. `seamless` still releases `roles` and `org_id` alone.
  - The API computes the claims for the session and client (`GET /oidc/accounts/:id`), with the client's set after the role sets and before the session's hook claims and the shared budget applied, and `/oidc/sign` computes them again and signs only an exact match. The edge never reads custom claim tables.
  - `org_id` in a provider token is now the session's active organization, as in a first-party token, rather than the user's oldest membership.
  - A role or membership can change between the edge's read and its sign. `/oidc/sign` answers that, and any other account claim that does not match, with `claims_mismatch`, a new refusal code, and the edge reads the account again and retries once. A second mismatch fails the token request with `server_error`. Brandon chose this on 2026-11-07.
  - The budget is applied to everything the account has, whatever the scopes, so a client that asks only for `permissions` can see `permissions_omitted` because of custom claims it did not ask for.

## Consequences

- No `system_config` key is added: every setting is a table behind admin routes with step-up on every write, so the CLI's writable keys do not change.
- Webhooks are at least once and unordered, which the guide (seamless-auth-docs#153) states, along with the retry schedule and dead letters.
- `pre_token` claims are as fresh as the session, not the token. The Auth0 mapping in seamless-auth-docs#154 has to say so.
