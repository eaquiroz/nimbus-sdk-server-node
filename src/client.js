import {
  NimbusAuthorizationError,
  NimbusConfigurationError,
  NimbusProofError,
} from "./errors.js";
import {
  assertMatchingState,
  canonicalPayloadHash,
  createPkce,
  randomOpaqueValue,
  verifyCompactProof,
} from "./security.js";

const LOGIN_ACTION = "application.login";
// Added alongside Login, without changing any existing Login behavior —
// see the third-party facility-access reference integration this mirrors
// (Havengate's application.js/security.js payloadHashFor), which is the
// proven-working shape Gateway/Key Management already accept.
const AUTHORIZE_ACTION = "facility.access.authorize";
const AUTHORIZE_HASH_INPUT_VERSION = 1;

// Authorize payloads are arbitrary, company-defined business data (unlike
// Login's fixed small shape), so the proof must be bound to the EXACT
// payload/context/externalReferenceId that was originally sent — otherwise a
// tampered or mismatched payload could ride along with an otherwise-valid
// approval. This mirrors the reference integration's payloadHashFor exactly
// (same hashInputVersion/action/payloadSchemaVersion/materialContext
// fields and sorted-key JSON), since Gateway verifies this same hash
// server-side and expects this precise shape.
const authorizePayloadHash = ({ payload, context, externalReferenceId }) => canonicalPayloadHash({
  hashInputVersion: AUTHORIZE_HASH_INPUT_VERSION,
  action: AUTHORIZE_ACTION,
  payloadSchemaVersion: 1,
  payload,
  materialContext: context?.reason ? { reason: context.reason } : {},
  externalReferenceId,
});
const trimTrailingSlashes = (value) => String(value).replace(/\/+$/, "");
const required = (value, name) => {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized) throw new NimbusConfigurationError(`${name} is required.`);
  return normalized;
};

const parseJson = async (response) => {
  try {
    return await response.json();
  } catch {
    throw new NimbusAuthorizationError("Nimbus returned an invalid JSON response.", {
      code: "NIMBUS_RESPONSE_INVALID",
      status: response.status,
    });
  }
};

export const createAuthorizationServer = ({
  gatewayUrl,
  clientId,
  clientSecret,
  redirectUri,
  proofAudience,
  partnerOrigin,
  environment = "development",
  issuer = "https://authorize.nimbus-id.com",
  jwksUrl,
  requestTimeoutMs = 5000,
  fetchImpl = globalThis.fetch,
  now = () => Date.now(),
} = {}) => {
  const config = {
    gatewayUrl: trimTrailingSlashes(required(gatewayUrl, "gatewayUrl")),
    clientId: required(clientId, "clientId"),
    clientSecret: required(clientSecret, "clientSecret"),
    redirectUri: required(redirectUri, "redirectUri"),
    proofAudience: required(proofAudience, "proofAudience"),
    partnerOrigin: required(partnerOrigin, "partnerOrigin"),
    environment: required(environment, "environment"),
    issuer: trimTrailingSlashes(required(issuer, "issuer")),
  };
  config.jwksUrl = jwksUrl
    ? required(jwksUrl, "jwksUrl")
    : `${config.gatewayUrl}/.well-known/jwks.json`;
  if (typeof fetchImpl !== "function") throw new NimbusConfigurationError("A fetch implementation is required.");
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 250 || requestTimeoutMs > 30000) {
    throw new NimbusConfigurationError("requestTimeoutMs must be between 250 and 30000.");
  }

  const credentials = `Basic ${Buffer.from(`${config.clientId}:${config.clientSecret}`, "utf8").toString("base64")}`;
  const endpoint = (path) => `${config.gatewayUrl}/api/human-authorization/v2${path}`;
  const request = async (url, init = {}) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
    try {
      let response;
      try {
        response = await fetchImpl(url, { ...init, signal: controller.signal });
      } catch (cause) {
        throw new NimbusAuthorizationError(
          cause?.name === "AbortError" ? "Nimbus request timed out." : "Nimbus is unavailable.",
          { code: cause?.name === "AbortError" ? "NIMBUS_TIMEOUT" : "NIMBUS_UNAVAILABLE", cause },
        );
      }
      const body = await parseJson(response);
      if (!response.ok) {
        throw new NimbusAuthorizationError(
          response.status >= 500
            ? "Nimbus is temporarily unavailable."
            : (typeof body?.message === "string" && body.message ? body.message : "Nimbus rejected the request."),
          {
            code: typeof body?.code === "string" ? body.code : "NIMBUS_REQUEST_REJECTED",
            status: response.status,
          },
        );
      }
      return body;
    } finally {
      clearTimeout(timeout);
    }
  };
  const partnerHeaders = (extra = {}) => ({
    Accept: "application/json",
    Authorization: credentials,
    "Content-Type": "application/json",
    "X-Nimbus-Environment": config.environment,
    Origin: config.partnerOrigin,
    ...extra,
  });

  return Object.freeze({
    async startLogin({
      loginRequestId = `login_${randomOpaqueValue(24)}`,
      requestedResource,
      reason,
      returnTo = "/",
      expiresInSeconds,
      state = randomOpaqueValue(32),
      idempotencyKey = randomOpaqueValue(32),
    } = {}) {
      const pkce = createPkce();
      const payload = { loginRequestId: required(loginRequestId, "loginRequestId") };
      if (requestedResource !== undefined && String(requestedResource).trim()) {
        payload.requestedResource = String(requestedResource).trim();
      }
      const body = {
        action: LOGIN_ACTION,
        payloadSchemaVersion: 1,
        payload,
        // Human Authorization keeps a common partner reference outside the
        // action-specific payload for hashing, idempotency and audit. Login
        // uses the same opaque request identifier in both places so the
        // partner cannot accidentally bind two different operations.
        externalReferenceId: payload.loginRequestId,
        redirectUri: config.redirectUri,
        state,
        codeChallenge: pkce.codeChallenge,
        codeChallengeMethod: pkce.codeChallengeMethod,
      };
      if (reason !== undefined && String(reason).trim()) body.context = { reason: String(reason).trim() };
      if (expiresInSeconds !== undefined) body.expiresInSeconds = expiresInSeconds;
      const result = await request(endpoint("/challenges"), {
        method: "POST",
        headers: partnerHeaders({ "Idempotency-Key": idempotencyKey }),
        body: JSON.stringify(body),
      });
      if (!result?.authorizationUrl || !result?.challengeId || !result?.requestId) {
        throw new NimbusAuthorizationError("Nimbus did not return a complete Login Authorization challenge.", {
          code: "NIMBUS_CHALLENGE_RESPONSE_INVALID",
        });
      }
      return {
        authorizationUrl: result.authorizationUrl,
        challengeId: result.challengeId,
        requestId: result.requestId,
        expiresAt: result.expiresAt,
        replayed: result.replayed === true,
        transaction: {
          state,
          codeVerifier: pkce.codeVerifier,
          challengeId: result.challengeId,
          requestId: result.requestId,
          redirectUri: config.redirectUri,
          returnTo: typeof returnTo === "string" && returnTo.startsWith("/") ? returnTo : "/",
          createdAt: new Date(now()).toISOString(),
        },
      };
    },

    async completeLogin({ code, state, transaction } = {}) {
      if (!transaction || typeof transaction !== "object") {
        throw new NimbusConfigurationError("A server-side Login Authorization transaction is required.");
      }
      assertMatchingState(state, transaction.state);
      const exchange = await request(endpoint("/authorizations/exchange"), {
        method: "POST",
        headers: partnerHeaders(),
        body: JSON.stringify({
          code: required(code, "code"),
          codeVerifier: required(transaction.codeVerifier, "transaction.codeVerifier"),
          redirectUri: config.redirectUri,
        }),
      });
      if (exchange?.outcome !== "approved" || !exchange?.proof || !exchange?.decisionId || !exchange?.challengeId) {
        throw new NimbusProofError("Nimbus did not return a complete approved authorization result.");
      }
      if (exchange.challengeId !== transaction.challengeId) {
        throw new NimbusProofError("The authorization code belongs to a different transaction.", "NIMBUS_PROOF_TRANSACTION_MISMATCH");
      }

      const onlineVerification = await request(endpoint("/proofs/verify"), {
        method: "POST",
        headers: partnerHeaders(),
        body: JSON.stringify({ proof: exchange.proof }),
      });
      if (onlineVerification?.valid !== true
          || onlineVerification?.decisionId !== exchange.decisionId
          || onlineVerification?.challengeId !== exchange.challengeId) {
        throw new NimbusProofError("Nimbus rejected the authorization proof.");
      }
      const jwks = await request(config.jwksUrl, { headers: { Accept: "application/json" } });
      const { header, claims } = verifyCompactProof({
        proof: exchange.proof,
        jwks,
        expected: {
          issuer: config.issuer,
          audience: config.proofAudience,
          action: LOGIN_ACTION,
          challengeId: transaction.challengeId,
          clientId: config.clientId,
        },
        now,
      });
      if (claims.decisionId !== exchange.decisionId) {
        throw new NimbusProofError("The proof decision does not match the exchanged authorization.", "NIMBUS_PROOF_TRANSACTION_MISMATCH");
      }
      return {
        outcome: "approved",
        principal: { sub: claims.sub },
        decisionId: claims.decisionId,
        challengeId: claims.challengeId,
        action: claims.action,
        authenticatedAt: new Date(claims.auth_time * 1000).toISOString(),
        expiresAt: new Date(claims.exp * 1000).toISOString(),
        authenticationMethods: [...claims.authenticationMethods],
        keyId: header.kid,
        returnTo: typeof transaction.returnTo === "string" && transaction.returnTo.startsWith("/")
          ? transaction.returnTo
          : "/",
      };
    },

    async cancelLogin({ challengeId } = {}) {
      return request(endpoint(`/challenges/${encodeURIComponent(required(challengeId, "challengeId"))}/cancel`), {
        method: "POST",
        headers: partnerHeaders(),
        body: "{}",
      });
    },

    async getLoginStatus({ challengeId } = {}) {
      return request(endpoint(`/challenges/${encodeURIComponent(required(challengeId, "challengeId"))}`), {
        headers: partnerHeaders(),
      });
    },

    // --- facility.access.authorize (added alongside Login above; the four
    // methods below never touch any Login state/behavior) ---

    async startAuthorize({
      payload,
      reason,
      externalReferenceId = `authorize_${randomOpaqueValue(24)}`,
      returnTo = "/",
      expiresInSeconds,
      state = randomOpaqueValue(32),
      idempotencyKey = randomOpaqueValue(32),
    } = {}) {
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        throw new NimbusConfigurationError("payload is required and must be a JSON object.");
      }
      const normalizedExternalReferenceId = required(externalReferenceId, "externalReferenceId");
      const context = reason !== undefined && String(reason).trim() ? { reason: String(reason).trim() } : {};
      // Computed and kept in the transaction before the network call, so the
      // approved proof can later be bound to this exact payload/context —
      // never trust a payload hash the browser or callback might supply.
      const payloadHash = authorizePayloadHash({ payload, context, externalReferenceId: normalizedExternalReferenceId });
      const pkce = createPkce();
      const body = {
        action: AUTHORIZE_ACTION,
        payloadSchemaVersion: 1,
        payload,
        externalReferenceId: normalizedExternalReferenceId,
        redirectUri: config.redirectUri,
        state,
        codeChallenge: pkce.codeChallenge,
        codeChallengeMethod: pkce.codeChallengeMethod,
      };
      if (Object.keys(context).length) body.context = context;
      if (expiresInSeconds !== undefined) body.expiresInSeconds = expiresInSeconds;
      const result = await request(endpoint("/challenges"), {
        method: "POST",
        headers: partnerHeaders({ "Idempotency-Key": idempotencyKey }),
        body: JSON.stringify(body),
      });
      if (!result?.authorizationUrl || !result?.challengeId || !result?.requestId) {
        throw new NimbusAuthorizationError("Nimbus did not return a complete Authorize challenge.", {
          code: "NIMBUS_CHALLENGE_RESPONSE_INVALID",
        });
      }
      return {
        authorizationUrl: result.authorizationUrl,
        challengeId: result.challengeId,
        requestId: result.requestId,
        expiresAt: result.expiresAt,
        replayed: result.replayed === true,
        transaction: {
          state,
          codeVerifier: pkce.codeVerifier,
          challengeId: result.challengeId,
          requestId: result.requestId,
          redirectUri: config.redirectUri,
          payloadHash,
          returnTo: typeof returnTo === "string" && returnTo.startsWith("/") ? returnTo : "/",
          createdAt: new Date(now()).toISOString(),
        },
      };
    },

    async completeAuthorize({ code, state, transaction } = {}) {
      if (!transaction || typeof transaction !== "object") {
        throw new NimbusConfigurationError("A server-side Authorize transaction is required.");
      }
      assertMatchingState(state, transaction.state);
      const exchange = await request(endpoint("/authorizations/exchange"), {
        method: "POST",
        headers: partnerHeaders(),
        body: JSON.stringify({
          code: required(code, "code"),
          codeVerifier: required(transaction.codeVerifier, "transaction.codeVerifier"),
          redirectUri: config.redirectUri,
        }),
      });
      if (exchange?.outcome !== "approved" || !exchange?.proof || !exchange?.decisionId || !exchange?.challengeId) {
        throw new NimbusProofError("Nimbus did not return a complete approved authorization result.");
      }
      if (exchange.challengeId !== transaction.challengeId) {
        throw new NimbusProofError("The authorization code belongs to a different transaction.", "NIMBUS_PROOF_TRANSACTION_MISMATCH");
      }

      const onlineVerification = await request(endpoint("/proofs/verify"), {
        method: "POST",
        headers: partnerHeaders(),
        body: JSON.stringify({ proof: exchange.proof }),
      });
      if (onlineVerification?.valid !== true
          || onlineVerification?.decisionId !== exchange.decisionId
          || onlineVerification?.challengeId !== exchange.challengeId) {
        throw new NimbusProofError("Nimbus rejected the authorization proof.");
      }
      const jwks = await request(config.jwksUrl, { headers: { Accept: "application/json" } });
      const { header, claims } = verifyCompactProof({
        proof: exchange.proof,
        jwks,
        expected: {
          issuer: config.issuer,
          audience: config.proofAudience,
          action: AUTHORIZE_ACTION,
          challengeId: transaction.challengeId,
          clientId: config.clientId,
        },
        now,
      });
      if (claims.decisionId !== exchange.decisionId) {
        throw new NimbusProofError("The proof decision does not match the exchanged authorization.", "NIMBUS_PROOF_TRANSACTION_MISMATCH");
      }
      // See the payloadHash comment on startAuthorize — bind the approved
      // proof to the exact original payload, not just the action/challenge.
      if (claims.payloadHash !== transaction.payloadHash) {
        throw new NimbusProofError("The proof payload hash does not match the original Authorize request.", "NIMBUS_PROOF_TRANSACTION_MISMATCH");
      }
      return {
        outcome: "approved",
        principal: { sub: claims.sub },
        decisionId: claims.decisionId,
        challengeId: claims.challengeId,
        action: claims.action,
        authenticatedAt: new Date(claims.auth_time * 1000).toISOString(),
        expiresAt: new Date(claims.exp * 1000).toISOString(),
        authenticationMethods: [...claims.authenticationMethods],
        keyId: header.kid,
        returnTo: typeof transaction.returnTo === "string" && transaction.returnTo.startsWith("/")
          ? transaction.returnTo
          : "/",
      };
    },

    async cancelAuthorize({ challengeId } = {}) {
      return request(endpoint(`/challenges/${encodeURIComponent(required(challengeId, "challengeId"))}/cancel`), {
        method: "POST",
        headers: partnerHeaders(),
        body: "{}",
      });
    },

    async getAuthorizeStatus({ challengeId } = {}) {
      return request(endpoint(`/challenges/${encodeURIComponent(required(challengeId, "challengeId"))}`), {
        headers: partnerHeaders(),
      });
    },
  });
};
