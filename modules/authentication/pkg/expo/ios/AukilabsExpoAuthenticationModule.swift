import ExpoModulesCore

public class AukilabsExpoAuthenticationModule: Module {
  // Single client instance
  private var client: AuthenticationClient?

  public func definition() -> ModuleDefinition {
    Name("AukilabsExpoAuthentication")

    // Define event names that can be sent to JavaScript
    Events("onRefreshFailed", "onDomainAccessDenied")

    // MARK: - Client Management

    /**
     * Create a new authentication client with only configuration
     * Credentials will be provided later when calling authenticate/authenticateWith
     */
    AsyncFunction("createClient") { (configDict: [String: String]) in
      // Parse config
      guard let apiUrl = configDict["apiUrl"],
            let refreshUrl = configDict["refreshUrl"],
            let ddsUrl = configDict["ddsUrl"],
            let clientIdStr = configDict["clientId"] else {
        throw AuthenticationError.authenticationFailed(reason: "Missing config parameters", retryable: false)
      }

      let refreshThresholdMs: UInt64
      if let refreshThreshold = configDict["refreshThresholdMs"], let threshold = UInt64(refreshThreshold) {
        refreshThresholdMs = threshold
      } else {
        refreshThresholdMs = 5 * 60 * 1000 // 5 minutes default
      }

      let config = Config(apiUrl: apiUrl, refreshUrl: refreshUrl, ddsUrl: ddsUrl, clientId: clientIdStr, refreshThresholdMs: refreshThresholdMs)

      let newClient = AuthenticationClient(config: config)

      // Set up refresh failed callback to send events to JavaScript
      newClient.refreshFailedCallback = { [weak self] info in
        self?.sendEvent("onRefreshFailed", [
          "tokenType": info.tokenType,
          "reason": info.reason,
          "requiresReauth": info.requiresReauth
        ])
      }

      // Set up domain access denied callback to send events to JavaScript
      newClient.domainAccessDeniedCallback = { [weak self] info in
        self?.sendEvent("onDomainAccessDenied", [
          "domainId": info.domainId,
          "reason": info.reason,
          "statusCode": info.statusCode
        ])
      }

      self.client = newClient
    }

    /**
     * Create a client from saved state
     */
    AsyncFunction("createClientFromState") { (stateJson: String, configDict: [String: String]) in
      guard let apiUrl = configDict["apiUrl"],
            let refreshUrl = configDict["refreshUrl"],
            let ddsUrl = configDict["ddsUrl"],
            let clientIdStr = configDict["clientId"] else {
        throw AuthenticationError.authenticationFailed(reason: "Missing config parameters", retryable: false)
      }

      let refreshThresholdMs: UInt64
      if let refreshThreshold = configDict["refreshThresholdMs"], let threshold = UInt64(refreshThreshold) {
        refreshThresholdMs = threshold
      } else {
        refreshThresholdMs = 5 * 60 * 1000 // 5 minutes default
      }

      let config = Config(apiUrl: apiUrl, refreshUrl: refreshUrl, ddsUrl: ddsUrl, clientId: clientIdStr, refreshThresholdMs: refreshThresholdMs)

      let newClient = try AuthenticationClient.fromState(stateJson: stateJson, config: config)

      // Set up refresh failed callback to send events to JavaScript
      newClient.refreshFailedCallback = { [weak self] info in
        self?.sendEvent("onRefreshFailed", [
          "tokenType": info.tokenType,
          "reason": info.reason,
          "requiresReauth": info.requiresReauth
        ])
      }

      // Set up domain access denied callback to send events to JavaScript
      newClient.domainAccessDeniedCallback = { [weak self] info in
        self?.sendEvent("onDomainAccessDenied", [
          "domainId": info.domainId,
          "reason": info.reason,
          "statusCode": info.statusCode
        ])
      }

      self.client = newClient
    }

    /**
     * Release the client instance
     */
    Function("releaseClient") {
      self.client = nil
    }

    // MARK: - Credential Management

    /**
     * Set or update credentials without authenticating
     */
    Function("setCredentials") { (credentialsDict: [String: Any]) in
      guard let client = self.client else {
        throw AuthenticationError.authenticationFailed(reason: "Client not initialized", retryable: false)
      }

      let credentials = try self.parseCredentials(credentialsDict)
      client.setCredentials(credentials)
    }

    // MARK: - Authentication

    /**
     * Authenticate with provided credentials (will clear existing tokens and authenticate as new user)
     */
    AsyncFunction("authenticate") { (credentialsDict: [String: Any]) -> [String: Any] in
      guard let client = self.client else {
        throw AuthenticationError.authenticationFailed(reason: "Client not initialized", retryable: false)
      }

      let credentials = try self.parseCredentials(credentialsDict)
      let token = try await client.authenticateWith(credentials: credentials)
      return [
        "token": token.token,
        "refreshToken": token.refreshToken,
        "expiresAt": token.expiresAt
      ]
    }

    /**
     * Switch to a different user by providing new credentials
     * This is an alias for authenticate() that makes the intent clearer
     */
    AsyncFunction("switchUser") { (credentialsDict: [String: Any]) -> [String: Any] in
      guard let client = self.client else {
        throw AuthenticationError.authenticationFailed(reason: "Client not initialized", retryable: false)
      }

      let credentials = try self.parseCredentials(credentialsDict)
      let token = try await client.switchUser(credentials: credentials)
      return [
        "token": token.token,
        "refreshToken": token.refreshToken,
        "expiresAt": token.expiresAt
      ]
    }

    /**
     * Authenticate to discovery service
     */
    AsyncFunction("authenticateDiscovery") { () -> [String: Any] in
      guard let client = self.client else {
        throw AuthenticationError.authenticationFailed(reason: "Client not initialized", retryable: false)
      }

      let token = try await client.authenticateDiscovery()
      return [
        "token": token.token,
        "expiresAt": token.expiresAt
      ]
    }

    /**
     * Get domain access (handles full auth chain automatically)
     */
    AsyncFunction("getDomainAccess") { (domainId: String) -> [String: Any] in
      guard let client = self.client else {
        throw AuthenticationError.authenticationFailed(reason: "Client not initialized", retryable: false)
      }

      let access = try await client.getDomainAccess(domainId: domainId)
      return self.domainAccessToDict(access)
    }

    // MARK: - State Queries

    /**
     * Check if authenticated
     */
    Function("isAuthenticated") { () -> Bool in
      guard let client = self.client else {
        return false
      }
      return client.isAuthenticated()
    }

    /**
     * Get network token
     */
    Function("getNetworkToken") { () -> [String: Any]? in
      guard let client = self.client,
            let token = client.getNetworkToken() else {
        return nil
      }
      return [
        "token": token.token,
        "refreshToken": token.refreshToken,
        "expiresAt": token.expiresAt
      ]
    }

    /**
     * Get discovery token
     */
    Function("getDiscoveryToken") { () -> [String: Any]? in
      guard let client = self.client,
            let token = client.getDiscoveryToken() else {
        return nil
      }
      return [
        "token": token.token,
        "expiresAt": token.expiresAt
      ]
    }

    /**
     * Get cached domain access
     */
    Function("getCachedDomainAccess") { (domainId: String) -> [String: Any]? in
      guard let client = self.client,
            let access = client.getCachedDomainAccess(domainId: domainId) else {
        return nil
      }
      return self.domainAccessToDict(access)
    }

    /**
     * Save state to JSON
     */
    Function("saveState") { () -> String in
      guard let client = self.client else {
        throw AuthenticationError.authenticationFailed(reason: "Client not initialized", retryable: false)
      }
      return client.saveState()
    }

    /**
     * Force re-authentication
     */
    Function("forceReauth") {
      guard let client = self.client else {
        throw AuthenticationError.authenticationFailed(reason: "Client not initialized", retryable: false)
      }
      client.forceReauth()
    }

    /**
     * Validate state
     */
    Function("validateState") {
      guard let client = self.client else {
        throw AuthenticationError.authenticationFailed(reason: "Client not initialized", retryable: false)
      }
      client.validateState()
    }
  }

  // MARK: - Helper Methods

  private func parseCredentials(_ credentialsDict: [String: Any]) throws -> Credentials {
    guard let credType = credentialsDict["type"] as? String else {
      throw AuthenticationError.authenticationFailed(reason: "Missing credential type", retryable: false)
    }

    switch credType {
    case "email":
      guard let email = credentialsDict["email"] as? String,
            let password = credentialsDict["password"] as? String else {
        throw AuthenticationError.authenticationFailed(reason: "Missing email or password", retryable: false)
      }
      return Credentials.emailPassword(email: email, password: password)

    case "appKey":
      guard let appKey = credentialsDict["appKey"] as? String,
            let appSecret = credentialsDict["appSecret"] as? String else {
        throw AuthenticationError.authenticationFailed(reason: "Missing appKey or appSecret", retryable: false)
      }
      return Credentials.appKey(appKey: appKey, appSecret: appSecret)

    case "opaque":
      guard let token = credentialsDict["token"] as? String,
            let expiryMs = credentialsDict["expiryMs"] as? UInt64 else {
        throw AuthenticationError.authenticationFailed(reason: "Missing token or expiryMs", retryable: false)
      }
      let refreshToken = credentialsDict["refreshToken"] as? String
      let refreshTokenExpiryMs = credentialsDict["refreshTokenExpiryMs"] as? UInt64
      let oidcClientId = credentialsDict["oidcClientId"] as? String
      return Credentials.opaque(token: token, refreshToken: refreshToken, expiryMs: expiryMs, refreshTokenExpiryMs: refreshTokenExpiryMs, oidcClientId: oidcClientId)

    default:
      throw AuthenticationError.authenticationFailed(reason: "Unknown credential type", retryable: false)
    }
  }

  private func domainAccessToDict(_ access: DomainAccess) -> [String: Any] {
    return [
      "id": access.id,
      "name": access.name,
      "organizationId": access.organizationId,
      "domainServerId": access.domainServerId,
      "accessToken": access.accessToken,
      "expiresAt": access.expiresAt,
      "ownerWalletAddress": access.ownerWalletAddress,
      "domainServer": [
        "id": access.domainServer.id,
        "organizationId": access.domainServer.organizationId,
        "name": access.domainServer.name,
        "url": access.domainServer.url,
        "version": access.domainServer.version,
        "status": access.domainServer.status,
        "mode": access.domainServer.mode,
        "variants": access.domainServer.variants,
        "ip": access.domainServer.ip,
        "latitude": access.domainServer.latitude,
        "longitude": access.domainServer.longitude,
        "cloudRegion": access.domainServer.cloudRegion
      ]
    ]
  }
}
