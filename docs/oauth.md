# OAuth Login

Seamless Auth API can use external OAuth/OIDC-style providers for login while still issuing the final Seamless Auth access and refresh session.

Provider access tokens are used only during callback handling to fetch profile data. They are not stored, logged, returned to clients, or included in auth event responses.

## Enable OAuth

1. Add `oauth` to `LOGIN_METHODS`.
2. Configure one or more providers in `oauth_providers` system config or the `OAUTH_PROVIDERS` environment variable.
3. Store provider client secrets in environment variables referenced by `clientSecretEnv`. The name must
   end in `_CLIENT_SECRET` (for example `GOOGLE_CLIENT_SECRET`), so provider configuration cannot name any
   other secret the server holds.
4. In production, provider URLs must use `https` and resolve to public addresses, and the server does not
   follow redirects from them. For an on-premises IdP, list its host in `OAUTH_PROVIDER_PRIVATE_HOSTS`.
   Link-local addresses are refused even when listed.
5. Set `OAUTH_STATE_SECRET` in production, or ensure `SEAMLESS_SERVICE_TOKEN` is stable and secret so it
   can be used as the OAuth state-signing fallback.

Example provider:

```json
{
  "id": "google",
  "name": "Google",
  "enabled": true,
  "clientId": "google-oauth-client-id",
  "clientSecretEnv": "GOOGLE_CLIENT_SECRET",
  "authorizationUrl": "https://accounts.google.com/o/oauth2/v2/auth",
  "tokenUrl": "https://oauth2.googleapis.com/token",
  "userInfoUrl": "https://openidconnect.googleapis.com/v1/userinfo",
  "scopes": ["openid", "email", "profile"],
  "redirectUri": "https://app.example.com/oauth/callback",
  "redirectUris": ["https://app.example.com/oauth/callback"],
  "subjectJsonPath": "sub",
  "emailJsonPath": "email",
  "emailVerifiedJsonPath": "email_verified",
  "nameJsonPath": "name",
  "allowSignup": true,
  "accountLinking": "email",
  "requireEmailVerified": true
}
```

## Browser Flow

1. `GET /oauth/providers`
2. `POST /oauth/:providerId/start`. Keep the returned `binding` with the pending sign-in (for
   example in `sessionStorage`, or in memory in a native app). Never send it to the provider.
3. Redirect browser to returned `authorizationUrl`.
4. Provider redirects back to your configured callback URL with `code` and `state`.
5. `POST /oauth/:providerId/callback` with `code`, `state` and the `binding` from step 2.
6. Seamless Auth validates state and its binding, exchanges the code, fetches userinfo, resolves the local user, and issues a Seamless Auth session.

OAuth is a non-passkey factor, so the passkey rules bind here as they do on every other
continuation. When the resolved account has to sign in with a passkey (phishing-resistant-only
mode, or the account holds a passkey and `passkey_login_fallback_enabled` is off), the callback
answers 403 `login_method_disabled`, records `oauth_login_failed` with reason `passkey_required`,
and issues no session.

The `binding` ties the `state` to the client that started the sign-in. The state travels through
the provider and the address bar, so without it anyone holding a state and its code could finish
the sign-in in another browser and sign that browser in to their own account (login CSRF). A
callback with a missing or different binding is refused with 400 `Invalid OAuth state`, and the
`oauth_login_failed` auth event records `state_binding_missing` or `state_binding_mismatch`. The
`@seamless-auth/client`, `@seamless-auth/react` and `@seamless-auth/react-native` SDKs keep and
send it for you; server adapters pass it through unchanged.

While upgrading clients that predate the binding, `OAUTH_ALLOW_UNBOUND_STATE=true` accepts a
callback that carries none. It reopens login CSRF for as long as it is set, logs a warning at boot,
and is removed in v0.20. A binding that is sent is always checked.

## Redirect Policy

For production providers, configure `redirectUris` as exact callback URLs. When a provider has a redirect allowlist, requested redirect URIs must exactly match it.

Providers without `redirectUris` fall back to configured trusted origins. Exact provider allowlists are preferred for production.

### Admin console callback

When the admin console runs OAuth, its callback is `<origin>/console/oauth/callback`, because the dashboard applies its router basename (`/console`) to the redirect. That is a different path from a typical web app's `/oauth/callback`, and a different host when the console is served or proxied from the API origin. Because `redirectUris` is matched exactly, this URL must be listed explicitly in each provider's `redirectUris`, and it must also be registered as an authorized redirect URI with the identity provider itself. If it is missing here, `POST /oauth/:providerId/start` returns 400 before any redirect; if it is missing at the provider, the consent screen rejects with `redirect_uri_mismatch`. See the admin dashboard prerequisites in [docs/configuration.md](./configuration.md#admin-dashboard-optional).

## Account Linking

`accountLinking` controls whether a provider identity can attach to an existing local user by email:

- `email`: existing users may be linked by email when policy allows.
- `disabled`: only existing provider identities can continue.

Use `requireEmailVerified: true` for providers that expose a reliable email verification claim.

## OIDC Notes

When provider scopes include `openid`, Seamless Auth includes a nonce bound into signed state. OAuth
start also includes PKCE challenge parameters by default, and the callback derives the matching
verifier server-side from the signed state. Set `pkce: false` only for providers that cannot accept
PKCE parameters.

Callback state is consumed in-process after first use and expires after a short window. In a
multi-instance deployment, keep OAuth callback traffic sticky to the same API instance or add shared
state storage before relying on replay detection across instances.

OAuth callback responses return the normal Seamless Auth JSON token payload. Provider tokens remain
server-side and must not be forwarded to browser clients.
