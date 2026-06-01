# OAuth Login

Seamless Auth API can use external OAuth/OIDC-style providers for login while still issuing the final Seamless Auth access and refresh session.

Provider access tokens are used only during callback handling to fetch profile data. They are not stored, logged, returned to clients, or included in auth event responses.

## Enable OAuth

1. Add `oauth` to `LOGIN_METHODS`.
2. Configure one or more providers in `oauth_providers` system config or the `OAUTH_PROVIDERS` environment variable.
3. Store provider client secrets in environment variables referenced by `clientSecretEnv`.
4. Set `OAUTH_STATE_SECRET` in production, or ensure `API_SERVICE_TOKEN` is stable and secret so it
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
2. `POST /oauth/:providerId/start`
3. Redirect browser to returned `authorizationUrl`.
4. Provider redirects back to your configured callback URL with `code` and `state`.
5. `POST /oauth/:providerId/callback`
6. Seamless Auth validates state, exchanges the code, fetches userinfo, resolves the local user, and issues a Seamless Auth session.

## Redirect Policy

For production providers, configure `redirectUris` as exact callback URLs. When a provider has a redirect allowlist, requested redirect URIs must exactly match it.

Providers without `redirectUris` fall back to configured trusted origins. Exact provider allowlists are preferred for production.

## Account Linking

`accountLinking` controls whether a provider identity can attach to an existing local user by email:

- `email`: existing users may be linked by email when policy allows.
- `disabled`: only existing provider identities can continue.

Use `requireEmailVerified: true` for providers that expose a reliable email verification claim.

## OIDC Notes

When provider scopes include `openid`, Seamless Auth includes a nonce bound into signed state. PKCE support depends on provider and client flow requirements; keep provider callback handling server-side and avoid exposing provider tokens to browsers.

OAuth callback responses return the normal Seamless Auth JSON token payload. Provider tokens remain
server-side and must not be forwarded to browser clients.
