export interface NimbusAuthorizationServerOptions {
  gatewayUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  proofAudience: string;
  partnerOrigin: string;
  environment?: string;
  issuer?: string;
  jwksUrl?: string;
  requestTimeoutMs?: number;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export interface NimbusLoginTransaction {
  state: string;
  codeVerifier: string;
  challengeId: string;
  requestId: string;
  redirectUri: string;
  returnTo: string;
  createdAt: string;
}

export interface StartNimbusLoginOptions {
  loginRequestId?: string;
  requestedResource?: string;
  reason?: string;
  returnTo?: string;
  expiresInSeconds?: number;
  state?: string;
  idempotencyKey?: string;
}

export interface StartNimbusLoginResult {
  authorizationUrl: string;
  challengeId: string;
  requestId: string;
  expiresAt?: string;
  replayed: boolean;
  transaction: NimbusLoginTransaction;
}

export interface CompleteNimbusLoginOptions {
  code: string;
  state: string;
  transaction: NimbusLoginTransaction;
}

export interface NimbusLoginPrincipal {
  sub: string;
}

export interface CompleteNimbusLoginResult {
  outcome: "approved";
  principal: NimbusLoginPrincipal;
  decisionId: string;
  challengeId: string;
  action: "application.login";
  authenticatedAt: string;
  expiresAt: string;
  authenticationMethods: string[];
  keyId: string;
  returnTo: string;
}

export interface CancelNimbusLoginResult {
  [key: string]: unknown;
}

export interface NimbusLoginStatus {
  [key: string]: unknown;
}

// --- facility.access.authorize (added alongside Login above; none of the
// Login types above were changed) ---

export interface NimbusAuthorizeTransaction {
  state: string;
  codeVerifier: string;
  challengeId: string;
  requestId: string;
  redirectUri: string;
  payloadHash: string;
  returnTo: string;
  createdAt: string;
}

export interface StartNimbusAuthorizeOptions {
  /** Arbitrary, partner-defined business data for this operation. Not validated by this package. */
  payload: Record<string, unknown>;
  reason?: string;
  externalReferenceId?: string;
  returnTo?: string;
  expiresInSeconds?: number;
  state?: string;
  idempotencyKey?: string;
}

export interface StartNimbusAuthorizeResult {
  authorizationUrl: string;
  challengeId: string;
  requestId: string;
  expiresAt?: string;
  replayed: boolean;
  transaction: NimbusAuthorizeTransaction;
}

export interface CompleteNimbusAuthorizeOptions {
  code: string;
  state: string;
  transaction: NimbusAuthorizeTransaction;
}

export interface CompleteNimbusAuthorizeResult {
  outcome: "approved";
  principal: NimbusLoginPrincipal;
  decisionId: string;
  challengeId: string;
  action: "facility.access.authorize";
  authenticatedAt: string;
  expiresAt: string;
  authenticationMethods: string[];
  keyId: string;
  returnTo: string;
}

export interface CancelNimbusAuthorizeResult {
  [key: string]: unknown;
}

export interface NimbusAuthorizeStatus {
  [key: string]: unknown;
}

export interface NimbusAuthorizationServer {
  startLogin(options?: StartNimbusLoginOptions): Promise<StartNimbusLoginResult>;
  completeLogin(options: CompleteNimbusLoginOptions): Promise<CompleteNimbusLoginResult>;
  cancelLogin(options: { challengeId: string }): Promise<CancelNimbusLoginResult>;
  getLoginStatus(options: { challengeId: string }): Promise<NimbusLoginStatus>;
  startAuthorize(options: StartNimbusAuthorizeOptions): Promise<StartNimbusAuthorizeResult>;
  completeAuthorize(options: CompleteNimbusAuthorizeOptions): Promise<CompleteNimbusAuthorizeResult>;
  cancelAuthorize(options: { challengeId: string }): Promise<CancelNimbusAuthorizeResult>;
  getAuthorizeStatus(options: { challengeId: string }): Promise<NimbusAuthorizeStatus>;
}

export function createAuthorizationServer(
  options: NimbusAuthorizationServerOptions,
): NimbusAuthorizationServer;

export class NimbusAuthorizationError extends Error {
  code: string;
  status: number;
  constructor(
    message: string,
    options?: { code?: string; status?: number; cause?: unknown },
  );
}

export class NimbusConfigurationError extends NimbusAuthorizationError {
  constructor(message: string);
}

export class NimbusStateError extends NimbusAuthorizationError {
  constructor();
}

export class NimbusProofError extends NimbusAuthorizationError {
  constructor(message: string, code?: string, options?: { cause?: unknown });
}
