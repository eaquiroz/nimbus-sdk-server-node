import crypto from "node:crypto";
import { NimbusProofError, NimbusStateError } from "./errors.js";

export const randomOpaqueValue = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");
export const sha256Base64Url = (value) => crypto.createHash("sha256").update(String(value), "utf8").digest("base64url");

// Deterministic key ordering for canonical hashing — recursively sorts object
// keys (and maps arrays) so the same logical object always serializes to the
// same JSON string. Used to bind a proof to the exact request payload it was
// issued for (Authorize's business-specific payload varies per request,
// unlike Login's fixed small shape). Matches the existing MVP convention
// (sorted-key JSON, not full RFC 8785/JCS) already proven against Gateway.
export const sortJsonKeys = (value) => {
  if (Array.isArray(value)) return value.map(sortJsonKeys);
  if (value && typeof value === "object") {
    return Object.keys(value).sort().reduce((result, key) => ({ ...result, [key]: sortJsonKeys(value[key]) }), {});
  }
  return value;
};

// Generic canonical-hash primitive: sha256 of the sorted-key JSON of
// `hashInput`, base64url-encoded. Action-specific callers build their own
// hashInput shape (see AUTHORIZE_ACTION in client.js) and pass it here.
export const canonicalPayloadHash = (hashInput) => sha256Base64Url(JSON.stringify(sortJsonKeys(hashInput)));

export const createPkce = () => {
  const codeVerifier = randomOpaqueValue(48);
  return {
    codeVerifier,
    codeChallenge: sha256Base64Url(codeVerifier),
    codeChallengeMethod: "S256",
  };
};

export const assertMatchingState = (actual, expected) => {
  const left = Buffer.from(String(actual || ""), "utf8");
  const right = Buffer.from(String(expected || ""), "utf8");
  if (!left.length || left.length !== right.length || !crypto.timingSafeEqual(left, right)) {
    throw new NimbusStateError();
  }
};

const decodeJsonPart = (part, label) => {
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    throw new NimbusProofError(`The proof ${label} is malformed.`, "NIMBUS_PROOF_MALFORMED");
  }
};

const nonEmpty = (value) => typeof value === "string" && value.trim().length > 0;

export const decodeCompactProof = (proof) => {
  const parts = String(proof || "").split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw new NimbusProofError("The proof is not a compact JWS.", "NIMBUS_PROOF_MALFORMED");
  }
  return {
    parts,
    header: decodeJsonPart(parts[0], "header"),
    claims: decodeJsonPart(parts[1], "payload"),
  };
};

export const verifyCompactProof = ({
  proof,
  jwks,
  expected,
  now = () => Date.now(),
  clockToleranceSeconds = 30,
}) => {
  const { parts, header, claims } = decodeCompactProof(proof);
  if (header.alg !== "ES256" || header.typ !== "nimbus-ha+jwt" || !nonEmpty(header.kid)) {
    throw new NimbusProofError("The proof header is invalid.", "NIMBUS_PROOF_HEADER_INVALID");
  }
  const jwk = Array.isArray(jwks?.keys) ? jwks.keys.find((candidate) => candidate?.kid === header.kid) : null;
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256"
      || (jwk.use && jwk.use !== "sig") || (jwk.alg && jwk.alg !== "ES256")) {
    throw new NimbusProofError("The proof signing key is not trusted.", "NIMBUS_PROOF_KEY_INVALID");
  }

  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
  } catch (cause) {
    throw new NimbusProofError("The proof signing key cannot be used.", "NIMBUS_PROOF_KEY_INVALID", { cause });
  }
  const signatureValid = crypto.verify(
    "sha256",
    Buffer.from(`${parts[0]}.${parts[1]}`, "utf8"),
    { key: publicKey, dsaEncoding: "ieee-p1363" },
    Buffer.from(parts[2], "base64url"),
  );
  if (!signatureValid) {
    throw new NimbusProofError("The proof signature is invalid.", "NIMBUS_PROOF_SIGNATURE_INVALID");
  }

  const current = Math.floor(now() / 1000);
  const tolerance = Number(clockToleranceSeconds);
  if (claims.iss !== expected.issuer
      || claims.aud !== expected.audience
      || claims.outcome !== "approved"
      || claims.action !== expected.action
      || claims.challengeId !== expected.challengeId
      || claims.clientId !== expected.clientId
      || !nonEmpty(claims.sub)
      || !nonEmpty(claims.decisionId)
      || claims.jti !== claims.decisionId
      || !nonEmpty(claims.payloadHash)
      || !Number.isInteger(claims.iat)
      || !Number.isInteger(claims.exp)
      || claims.iat > current + tolerance
      || claims.exp <= current - tolerance
      || claims.exp <= claims.iat) {
    throw new NimbusProofError("The proof claims do not match this Login Authorization transaction.", "NIMBUS_PROOF_CLAIMS_INVALID");
  }
  if (!Array.isArray(claims.authenticationMethods) || !claims.authenticationMethods.includes("nimbus_key")) {
    throw new NimbusProofError("The proof does not contain Nimbus-Key authentication evidence.", "NIMBUS_PROOF_METHOD_INVALID");
  }
  return { header, claims };
};
