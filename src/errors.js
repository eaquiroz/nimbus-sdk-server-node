export class NimbusAuthorizationError extends Error {
  constructor(message, { code = "NIMBUS_AUTHORIZATION_ERROR", status = 0, cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = "NimbusAuthorizationError";
    this.code = code;
    this.status = status;
  }
}

export class NimbusConfigurationError extends NimbusAuthorizationError {
  constructor(message) {
    super(message, { code: "NIMBUS_CONFIGURATION_INVALID" });
    this.name = "NimbusConfigurationError";
  }
}

export class NimbusStateError extends NimbusAuthorizationError {
  constructor() {
    super("The Login Authorization state does not match the server transaction.", {
      code: "NIMBUS_STATE_INVALID",
    });
    this.name = "NimbusStateError";
  }
}

export class NimbusProofError extends NimbusAuthorizationError {
  constructor(message, code = "NIMBUS_PROOF_INVALID", options = {}) {
    super(message, { code, cause: options.cause });
    this.name = "NimbusProofError";
  }
}
