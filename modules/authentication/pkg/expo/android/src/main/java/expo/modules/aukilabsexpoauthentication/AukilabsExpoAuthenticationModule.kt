package expo.modules.aukilabsexpoauthentication

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import uniffi.authentication.*

class AukilabsExpoAuthenticationModule : Module() {
  // Single client instance
  private var client: AuthenticationClientWrapper? = null

  override fun definition() = ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module
    Name("AukilabsExpoAuthentication")

    // Define event names that can be sent to JavaScript
    Events("onRefreshFailed", "onDomainAccessDenied")

    // MARK: - Client Management

    /**
     * Create a new authentication client with only configuration
     * Credentials will be provided later when calling authenticate/authenticateWith
     */
    AsyncFunction("createClient") { configDict: Map<String, Any> ->
      // Parse config
      val apiUrl = configDict["apiUrl"] as? String
        ?: throw AuthenticationError.AuthenticationFailed("Missing apiUrl", false)
      val refreshUrl = configDict["refreshUrl"] as? String
        ?: throw AuthenticationError.AuthenticationFailed("Missing refreshUrl", false)
      val ddsUrl = configDict["ddsUrl"] as? String
        ?: throw AuthenticationError.AuthenticationFailed("Missing ddsUrl", false)
      val clientIdStr = configDict["clientId"] as? String
        ?: throw AuthenticationError.AuthenticationFailed("Missing clientId", false)

      val refreshThresholdMs = when (val threshold = configDict["refreshThresholdMs"]) {
        is Number -> threshold.toLong().toULong()
        is String -> threshold.toULongOrNull() ?: (5 * 60 * 1000).toULong()
        else -> (5 * 60 * 1000).toULong() // 5 minutes default
      }

      val config = NativeConfig(
        apiUrl = apiUrl,
        refreshUrl = refreshUrl,
        ddsUrl = ddsUrl,
        clientId = clientIdStr,
        refreshThresholdMs = refreshThresholdMs
      )

      val newClient = AuthenticationClientWrapper.create(config)

      // Set up refresh failed callback to send events to JavaScript
      newClient.refreshFailedCallback = { info ->
        sendEvent("onRefreshFailed", mapOf(
          "tokenType" to info.tokenType,
          "reason" to info.reason,
          "requiresReauth" to info.requiresReauth
        ))
      }

      // Set up domain access denied callback to send events to JavaScript
      newClient.domainAccessDeniedCallback = { info ->
        sendEvent("onDomainAccessDenied", mapOf(
          "domainId" to info.domainId,
          "reason" to info.reason,
          "statusCode" to info.statusCode
        ))
      }

      client = newClient
    }

    /**
     * Create a client from saved state
     */
    AsyncFunction("createClientFromState") { stateJson: String, configDict: Map<String, Any> ->
      val apiUrl = configDict["apiUrl"] as? String
        ?: throw AuthenticationError.AuthenticationFailed("Missing apiUrl", false)
      val refreshUrl = configDict["refreshUrl"] as? String
        ?: throw AuthenticationError.AuthenticationFailed("Missing refreshUrl", false)
      val ddsUrl = configDict["ddsUrl"] as? String
        ?: throw AuthenticationError.AuthenticationFailed("Missing ddsUrl", false)
      val clientIdStr = configDict["clientId"] as? String
        ?: throw AuthenticationError.AuthenticationFailed("Missing clientId", false)

      val refreshThresholdMs = when (val threshold = configDict["refreshThresholdMs"]) {
        is Number -> threshold.toLong().toULong()
        is String -> threshold.toULongOrNull() ?: (5 * 60 * 1000).toULong()
        else -> (5 * 60 * 1000).toULong()
      }

      val config = NativeConfig(
        apiUrl = apiUrl,
        refreshUrl = refreshUrl,
        ddsUrl = ddsUrl,
        clientId = clientIdStr,
        refreshThresholdMs = refreshThresholdMs
      )

      val newClient = AuthenticationClientWrapper.fromState(stateJson, config)

      // Set up refresh failed callback
      newClient.refreshFailedCallback = { info ->
        sendEvent("onRefreshFailed", mapOf(
          "tokenType" to info.tokenType,
          "reason" to info.reason,
          "requiresReauth" to info.requiresReauth
        ))
      }

      // Set up domain access denied callback
      newClient.domainAccessDeniedCallback = { info ->
        sendEvent("onDomainAccessDenied", mapOf(
          "domainId" to info.domainId,
          "reason" to info.reason,
          "statusCode" to info.statusCode
        ))
      }

      client = newClient
    }

    /**
     * Release the client instance
     */
    Function("releaseClient") {
      client = null
    }

    // MARK: - Credential Management

    /**
     * Set or update credentials without authenticating
     */
    Function("setCredentials") { credentialsDict: Map<String, Any> ->
      val currentClient = client
        ?: throw AuthenticationError.AuthenticationFailed("Client not initialized", false)

      val credentials = parseCredentials(credentialsDict)
      currentClient.setCredentials(credentials)
    }

    // MARK: - Authentication

    /**
     * Authenticate with provided credentials (will clear existing tokens and authenticate as new user)
     */
    AsyncFunction("authenticate") { credentialsDict: Map<String, Any> ->
      val currentClient = client
        ?: throw AuthenticationError.AuthenticationFailed("Client not initialized", false)

      val credentials = parseCredentials(credentialsDict)
      val token = kotlinx.coroutines.runBlocking {
        currentClient.authenticateWith(credentials)
      }
      mapOf(
        "token" to token.token,
        "refreshToken" to token.refreshToken,
        "expiresAt" to token.expiresAt.toLong()
      )
    }

    /**
     * Switch to a different user by providing new credentials
     * This is an alias for authenticate() that makes the intent clearer
     */
    AsyncFunction("switchUser") { credentialsDict: Map<String, Any> ->
      val currentClient = client
        ?: throw AuthenticationError.AuthenticationFailed("Client not initialized", false)

      val credentials = parseCredentials(credentialsDict)
      val token = kotlinx.coroutines.runBlocking {
        currentClient.switchUser(credentials)
      }
      mapOf(
        "token" to token.token,
        "refreshToken" to token.refreshToken,
        "expiresAt" to token.expiresAt.toLong()
      )
    }

    /**
     * Authenticate to discovery service
     */
    AsyncFunction("authenticateDiscovery") {
      val currentClient = client
        ?: throw AuthenticationError.AuthenticationFailed("Client not initialized", false)

      val token = kotlinx.coroutines.runBlocking {
        currentClient.authenticateDiscovery()
      }
      mapOf(
        "token" to token.token,
        "expiresAt" to token.expiresAt.toLong()
      )
    }

    /**
     * Get domain access (handles full auth chain automatically)
     */
    AsyncFunction("getDomainAccess") { domainId: String ->
      val currentClient = client
        ?: throw AuthenticationError.AuthenticationFailed("Client not initialized", false)

      val access = kotlinx.coroutines.runBlocking {
        currentClient.getDomainAccess(domainId)
      }
      domainAccessToMap(access)
    }

    // MARK: - State Queries

    /**
     * Check if authenticated
     */
    Function("isAuthenticated") {
      client?.isAuthenticated() ?: false
    }

    /**
     * Get network token
     */
    Function("getNetworkToken") {
      val currentClient = client
      val token = currentClient?.getNetworkToken()
      token?.let {
        mapOf(
          "token" to it.token,
          "refreshToken" to it.refreshToken,
          "expiresAt" to it.expiresAt.toLong()
        )
      }
    }

    /**
     * Get discovery token
     */
    Function("getDiscoveryToken") {
      val currentClient = client
      val token = currentClient?.getDiscoveryToken()
      token?.let {
        mapOf(
          "token" to it.token,
          "expiresAt" to it.expiresAt.toLong()
        )
      }
    }

    /**
     * Get cached domain access
     */
    Function("getCachedDomainAccess") { domainId: String ->
      val currentClient = client
      val access = currentClient?.getCachedDomainAccess(domainId)
      access?.let { domainAccessToMap(it) }
    }

    /**
     * Save state to JSON
     */
    Function("saveState") {
      val currentClient = client
        ?: throw AuthenticationError.AuthenticationFailed("Client not initialized", false)
      currentClient.saveState()
    }

    /**
     * Force re-authentication
     */
    Function("forceReauth") {
      val currentClient = client
        ?: throw AuthenticationError.AuthenticationFailed("Client not initialized", false)
      currentClient.forceReauth()
    }

    /**
     * Validate state
     */
    Function("validateState") {
      val currentClient = client
        ?: throw AuthenticationError.AuthenticationFailed("Client not initialized", false)
      currentClient.validateState()
    }
  }

  // MARK: - Helper Methods

  private fun parseCredentials(credentialsDict: Map<String, Any>): NativeCredentials {
    val credType = credentialsDict["type"] as? String
      ?: throw AuthenticationError.AuthenticationFailed("Missing credential type", false)

    return when (credType) {
      "email" -> {
        val email = credentialsDict["email"] as? String
          ?: throw AuthenticationError.AuthenticationFailed("Missing email", false)
        val password = credentialsDict["password"] as? String
          ?: throw AuthenticationError.AuthenticationFailed("Missing password", false)
        NativeCredentials.EmailPassword(email, password)
      }

      "appKey" -> {
        val appKey = credentialsDict["appKey"] as? String
          ?: throw AuthenticationError.AuthenticationFailed("Missing appKey", false)
        val appSecret = credentialsDict["appSecret"] as? String
          ?: throw AuthenticationError.AuthenticationFailed("Missing appSecret", false)
        NativeCredentials.AppKey(appKey, appSecret)
      }

      "opaque" -> {
        val token = credentialsDict["token"] as? String
          ?: throw AuthenticationError.AuthenticationFailed("Missing token", false)
        val expiryMs = when (val expiry = credentialsDict["expiryMs"]) {
          is Number -> expiry.toLong().toULong()
          is String -> expiry.toULongOrNull()
            ?: throw AuthenticationError.AuthenticationFailed("Invalid expiryMs", false)
          else -> throw AuthenticationError.AuthenticationFailed("Missing expiryMs", false)
        }
        val refreshToken = credentialsDict["refreshToken"] as? String
        val refreshTokenExpiryMs = when (val expiry = credentialsDict["refreshTokenExpiryMs"]) {
          is Number -> expiry.toLong().toULong()
          is String -> expiry.toULongOrNull()
          null -> null
          else -> throw AuthenticationError.AuthenticationFailed("Invalid refreshTokenExpiryMs", false)
        }
        val oidcClientId = credentialsDict["oidcClientId"] as? String
        NativeCredentials.Opaque(token, refreshToken, expiryMs, refreshTokenExpiryMs, oidcClientId)
      }

      else -> throw AuthenticationError.AuthenticationFailed("Unknown credential type: $credType", false)
    }
  }

  private fun domainAccessToMap(access: NativeDomainAccess): Map<String, Any> {
    return mapOf(
      "id" to access.id,
      "name" to access.name,
      "organizationId" to access.organizationId,
      "domainServerId" to access.domainServerId,
      "accessToken" to access.accessToken,
      "expiresAt" to access.expiresAt.toLong(),
      "ownerWalletAddress" to access.ownerWalletAddress,
      "domainServer" to mapOf(
        "id" to access.domainServer.id,
        "organizationId" to access.domainServer.organizationId,
        "name" to access.domainServer.name,
        "url" to access.domainServer.url,
        "version" to access.domainServer.version,
        "status" to access.domainServer.status,
        "mode" to access.domainServer.mode,
        "variants" to access.domainServer.variants,
        "ip" to access.domainServer.ip,
        "latitude" to access.domainServer.latitude,
        "longitude" to access.domainServer.longitude,
        "cloudRegion" to access.domainServer.cloudRegion
      )
    )
  }
}
