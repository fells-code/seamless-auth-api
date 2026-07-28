# Extending Seamless Auth API

This guide covers the supported extension points: message delivery and where custom behavior
belongs. It also states what is intentionally not extensible, so you do not build against seams
that are meant to stay closed.

## Message delivery (OTP and magic links)

OTP and magic-link flows can deliver messages in two ways.

### Direct delivery

The API sends email/SMS itself through provider adapters wired in
[`src/config/directMessaging.ts`](../src/config/directMessaging.ts) and driven by
[`src/services/messagingService.ts`](../src/services/messagingService.ts). Providers are
configured with environment variables (see the messaging section of
[configuration.md](./configuration.md)):

- **Email:** AWS SES (`MESSAGING_EMAIL_FROM`, `MESSAGING_AWS_REGION`).
- **SMS:** AWS SNS or Twilio (`MESSAGING_SMS_PROVIDER`, plus provider credentials).

To add a provider, implement the transport contract from `@seamless-auth/messaging` (an
`EmailTransport` / `SmsTransport` with a `send(...)` method) and wire it in
`directMessaging.ts` behind a `MESSAGING_SMS_PROVIDER` (or email) value. `validateEnvs.sh`
enforces that the required variables for the selected provider are present at boot, so add the
matching checks there when you introduce a new provider value.

### External delivery

A trusted caller can take over delivery entirely by sending the header
`x-seamless-auth-delivery-mode: external`. Instead of sending the message, the API returns a
delivery payload (recipient + token, and a URL for magic links) so the caller sends it through
its own channel. See [`src/lib/externalDelivery.ts`](../src/lib/externalDelivery.ts).

- External delivery requires a valid `x-seamless-service-token` from a trusted server adapter
  in every environment.
- For local development without a service token, set `ALLOW_UNCREDENTIALED_DELIVERY_SECRETS=true`.
  The flag is ignored when `NODE_ENV=production`.

This is how a server adapter integrates its own email/SMS stack without the API baking in a
provider. See the delivery payload shapes in
[`src/schemas/generic.responses.ts`](../src/schemas/generic.responses.ts) (`AuthDeliverySchema`)
and the end-to-end example in [direct-http-quickstart.md](./direct-http-quickstart.md).

## Adding an endpoint

Routes are auto-discovered: every `src/routes/*.routes.ts` file is loaded at startup. A new
endpoint is registered with `defineRoute` (via the `createRouter` wrapper), which wires the
Express handler, validates the request against Zod `schemas`, validates the JSON response, and
generates the OpenAPI metadata from the same schemas. Trace existing behavior
**route → controller → service → model** and follow that layering:

- Put logic in a controller/service, not the route file.
- Declare `schemas` (request + response) so validation and docs stay aligned.
- If the route needs auth, use the `auth` option (`ephemeral` | `access`) so security metadata
  is emitted; add `middleware` for admin checks or rate limits.
- Run `npm run generate:api` and commit the result. `openapi.json` and `src/generated/api.ts` are
  generated from the route definitions, and a test fails when they drift.

## Token claims and auth behavior

Token signing lives in [`src/lib/token.ts`](../src/lib/token.ts) (access, refresh, ephemeral) and
session issuance in [`src/services/sessionService.ts`](../src/services/sessionService.ts). Claims
are part of the contract that the verifier SDKs depend on, so changing them is a **coordinated,
contract-affecting change**, not a drop-in customization. If you need custom claims, treat it as a
contract change: see the ripple protocol in [ecosystem.md](./ecosystem.md).

## What is intentionally not extensible

- **Token format and transport.** The API issues Bearer/JSON tokens and never sets cookies.
  Cookie handling belongs in a trusted server adapter, not here.
- **Crypto primitives.** Signing algorithm (RS256), refresh-token hashing, and constant-time
  comparisons are fixed on purpose; do not swap them per deployment.
- **The response contract.** Response schemas intentionally strip undocumented fields. Add fields
  through the schema, not by returning extra keys.
