# @nimbus-key/authorization-server-authorize

Private server-side package for Nimbus-T Login and Facility Access. It is
designed for trusted partner backends and must never be imported into browser
code. The package ships native ESM JavaScript plus TypeScript declarations.

The package supports two independent actions — a partner backend uses
whichever one(s) its registered Nimbus integration is configured for:

- **`application.login`** (existing) — see "Login" below.
- **`facility.access.authorize`** — see
  "Authorize" below.

Both share the same underlying machinery:

- creates cryptographically random state, PKCE and idempotency values;
- exchanges the short-lived authorization code exactly once;
- asks Nimbus to verify the proof and independently validates its ES256
  signature and bound claims against the published JWKS;
- returns the stable Nimbus subject (`sub`) so the partner can map it to its
  own user/operation and create its own secure session/local result.

It does not expose Dynamic Key internals and does not put the client secret,
authorization code, code verifier, PIN or signed proof in a browser URL or log.

## Private installation

```sh
npm config set @nimbus-key:registry https://registry.nimbus-id.com/
npm install --save-exact @nimbus-key/authorization-server-authorize@1.0.0-beta.1
```

Registry installation authentication is separate from runtime credentials.
The partner backend uses the application Client ID and Client Secret issued in
Nimbus Dashboard only when calling the Nimbus server-side API.

## Login: minimal server flow

```js
import { createAuthorizationServer } from "@nimbus-key/authorization-server-authorize";

const nimbus = createAuthorizationServer({
  gatewayUrl: process.env.NIMBUS_GATEWAY_URL,
  clientId: process.env.NIMBUS_CLIENT_ID,
  clientSecret: process.env.NIMBUS_CLIENT_SECRET,
  redirectUri: process.env.NIMBUS_REDIRECT_URI,
  proofAudience: process.env.NIMBUS_PROOF_AUDIENCE,
  partnerOrigin: process.env.PARTNER_ORIGIN,
  issuer: process.env.NIMBUS_AUTHORIZATION_ISSUER,
});

// GET /login: store transaction in a server-side session, then redirect the
// complete browser window to authorizationUrl.
const started = await nimbus.startLogin({ requestedResource: "Partner dashboard" });
request.session.nimbusLogin = started.transaction;
response.redirect(303, started.authorizationUrl);

// GET /oauth/nimbus/callback: the callback contains code + state only.
const result = await nimbus.completeLogin({
  code: request.query.code,
  state: request.query.state,
  transaction: request.session.nimbusLogin,
});

// Map result.principal.sub to a local account, rotate the partner session ID,
// delete the one-time transaction, and redirect to result.returnTo.
```

Store the transaction only in a protected server-side session. Never serialize
its `codeVerifier` into browser storage or a client-readable cookie.

## Authorize: minimal server flow

Same `createAuthorizationServer(...)` instance and config shape as Login
(`redirectUri`/`proofAudience` must be the exact values registered for this
integration's `facility.access.authorize` callback, which are typically
different from the Login callback if a partner registers both).

`payload` is arbitrary, partner-defined business data for the specific
operation being authorized (this package does not validate its business
shape — that is the partner's own responsibility, matching how `payload` for
Login is only `loginRequestId`/`requestedResource`). Because that payload
varies per request, the SDK computes a payload hash locally when starting the
request and verifies the approved proof is bound to that *exact* hash before
returning a result — a tampered or substituted payload is rejected even if
every other part of the proof is otherwise valid.

```js
// GET/POST /facility-access: store transaction in a server-side session,
// then redirect the complete browser window to authorizationUrl.
const started = await nimbus.startAuthorize({
  payload: { visitorName, facilityName, authorizedArea, validFrom, validUntil },
  reason: "Scheduled visit",
});
request.session.nimbusAuthorize = started.transaction;
response.redirect(303, started.authorizationUrl);

// GET /oauth/nimbus/facility-access/callback: code + state only.
const result = await nimbus.completeAuthorize({
  code: request.query.code,
  state: request.query.state,
  transaction: request.session.nimbusAuthorize,
});

// Execute the partner's own local operation only after this resolves, using
// result.principal.sub, result.decisionId as the (application-level) unique
// guard against re-executing the same decision, and delete the one-time
// transaction.
```

`cancelAuthorize({ challengeId })` and `getAuthorizeStatus({ challengeId })`
mirror `cancelLogin`/`getLoginStatus`. As with Login, a status response alone
is never authorization evidence and must not by itself execute the operation.
