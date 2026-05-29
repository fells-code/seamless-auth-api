# WebAuthn PRF

WebAuthn PRF lets compatible passkeys derive browser-local key material during registration or assertion. Seamless Auth API supports PRF-capable passkey primitives without receiving PRF output.

PRF output must stay in the browser caller. Do not send it to Seamless Auth API or to application APIs unless your application has a separate, explicit design for local key material handling.

## Registration

Normal passkey registration does not require PRF. Callers can request PRF-capable credential creation when their application needs local key material later.

The server can include WebAuthn `extensions.prf` creation options and persist whether the credential is suitable for PRF use. Registration remains backwards compatible for non-PRF passkeys.

## Login and Assertion

Callers can request PRF during assertion with a caller-provided salt. The browser reads:

```ts
credential.getClientExtensionResults().prf?.results?.first;
```

The assertion response sent to Seamless Auth must not include PRF output. The server verifies the WebAuthn assertion normally and stores only credential metadata.

## Step-up Authentication

PRF can also be requested during WebAuthn step-up. This lets applications require fresh user verification while deriving local key material in the browser.

The React SDK exposes headless helpers for this flow. The shape intended for local key consumers is:

```ts
{
  credentialId: string;
  output: Uint8Array;
}
```

## Salt Handling

PRF salts may be application-provided and may be stored by downstream apps when needed. Treat salts as sensitive in logs because they can identify key-derivation contexts.

## Browser Support

Browser and authenticator support is not universal. Applications should check support before requiring PRF and provide a fallback for passkeys that authenticate successfully without returning PRF output.

## Security Notes

- Authentication proves identity and user presence.
- PRF output is local key material.
- PRF output is never logged, stored, sent to Seamless Auth API, or returned by server responses.
- Do not include PRF output in error telemetry, analytics, auth events, or delivery payloads.
