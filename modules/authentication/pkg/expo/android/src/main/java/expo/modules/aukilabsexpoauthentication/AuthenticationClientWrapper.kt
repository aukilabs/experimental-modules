package expo.modules.aukilabsexpoauthentication

import uniffi.authentication.*
import kotlinx.coroutines.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * Token information
 */
data class Token(
    val token: String,
    val refreshToken: String,
    val expiresAt: ULong
)

/**
 * Token refresh failure information
 */
data class RefreshFailureInfo(
    val tokenType: String,  // "network" or "discovery"
    val reason: String,
    val requiresReauth: Boolean
)

/**
 * Domain access denied information
 */
data class DomainAccessDeniedInfo(
    val domainId: String,
    val reason: String,
    val statusCode: Int
)

/**
 * Authentication errors
 */
sealed class AuthenticationError : Exception() {
    data class AuthenticationFailed(val reason: String, val retryable: Boolean) : AuthenticationError() {
        override val message: String get() = "Authentication failed: $reason"
    }
    data class DomainAccessDenied(val reason: String) : AuthenticationError() {
        override val message: String get() = "Domain access denied: $reason"
    }
    data class NetworkError(val msg: String) : AuthenticationError() {
        override val message: String get() = "Network error: $msg"
    }
    object NoResponse : AuthenticationError() {
        override val message: String get() = "No response from server"
    }
    object MaxIterationsExceeded : AuthenticationError() {
        override val message: String get() = "Maximum iterations exceeded"
    }
}

/**
 * Kotlin wrapper for the Auki Authentication client
 * Provides a high-level async API similar to the Swift/JavaScript client
 */
class AuthenticationClientWrapper(private val client: NativeClient) {
    var refreshFailedCallback: ((RefreshFailureInfo) -> Unit)? = null
    var domainAccessDeniedCallback: ((DomainAccessDeniedInfo) -> Unit)? = null

    companion object {
        /**
         * Create a new authentication client with only configuration
         */
        fun create(config: NativeConfig): AuthenticationClientWrapper {
            val client = NativeClient(config)
            return AuthenticationClientWrapper(client)
        }

        /**
         * Create a client from saved state
         */
        fun fromState(stateJson: String, config: NativeConfig): AuthenticationClientWrapper {
            val client = NativeClient.fromState(stateJson, config)
            return AuthenticationClientWrapper(client)
        }
    }

    /**
     * Set credentials
     */
    fun setCredentials(credentials: NativeCredentials) {
        client.setCredentials(credentials)
    }

    /**
     * Authenticate with specific credentials
     */
    suspend fun authenticateWith(credentials: NativeCredentials): Token = withContext(Dispatchers.IO) {
        val now = currentTimeMs()
        val actionsJson = client.authenticateWith(credentials, now)
        val actions = parseActions(actionsJson)

        val events = executeActions(actions)

        for (event in events) {
            when (event) {
                is Event.NetworkAuthSuccess -> {
                    val networkToken = getNetworkToken()
                    if (networkToken != null) {
                        return@withContext networkToken
                    } else {
                        throw AuthenticationError.AuthenticationFailed(
                            "Failed to retrieve network token after successful authentication",
                            false
                        )
                    }
                }
                is Event.NetworkAuthFailed -> {
                    throw AuthenticationError.AuthenticationFailed(event.reason, event.retryPossible)
                }
                else -> {} // Continue checking other events
            }
        }

        // For AppKey and Opaque credentials, there are no HTTP actions/events
        // The token is set directly in the core. Check if we have a valid token now.
        if (actions.isEmpty()) {
            val networkToken = getNetworkToken()
            if (networkToken != null) {
                return@withContext networkToken
            }
        }

        throw AuthenticationError.NoResponse
    }

    /**
     * Switch to a different user
     */
    suspend fun switchUser(credentials: NativeCredentials): Token {
        return authenticateWith(credentials)
    }

    /**
     * Authenticate to discovery service
     */
    suspend fun authenticateDiscovery(): Token = withContext(Dispatchers.IO) {
        val now = currentTimeMs()
        val actionsJson = client.authenticateDiscovery(now)
        val actions = parseActions(actionsJson)

        val events = executeActions(actions)

        for (event in events) {
            when (event) {
                is Event.DiscoveryAuthSuccess -> {
                    return@withContext Token(event.token, "", event.expiresAt)
                }
                is Event.DiscoveryAuthFailed -> {
                    throw AuthenticationError.AuthenticationFailed(event.reason, false)
                }
                else -> {} // Continue checking other events
            }
        }

        throw AuthenticationError.NoResponse
    }

    /**
     * Get domain access (handles full auth chain automatically)
     */
    suspend fun getDomainAccess(domainId: String): NativeDomainAccess = withContext(Dispatchers.IO) {
        val maxIterations = 10

        repeat(maxIterations) {
            val now = currentTimeMs()
            val actionsJson = client.getDomainAccess(domainId, now)
            val actions = parseActions(actionsJson)

            // If no actions, check for cached access
            if (actions.isEmpty()) {
                val cachedJson = client.domainAccess(domainId)
                if (cachedJson != null) {
                    return@withContext parseDomainAccess(cachedJson)
                }
                // If we're authenticated (e.g., Opaque/AppKey credentials were just set),
                // continue the loop to let the core progress to the next step
                if (isAuthenticated()) {
                    return@repeat
                }
                // No cached access, no actions, and not authenticated means we need credentials
                throw AuthenticationError.AuthenticationFailed(
                    "Authentication required. Please sign in again.",
                    false
                )
            }

            val events = executeActions(actions)

            // Check for failures
            for (event in events) {
                when (event) {
                    is Event.NetworkAuthFailed -> {
                        throw AuthenticationError.AuthenticationFailed(event.reason, event.retryPossible)
                    }
                    is Event.DiscoveryAuthFailed -> {
                        throw AuthenticationError.AuthenticationFailed("Discovery: ${event.reason}", false)
                    }
                    is Event.DomainAccessDenied -> {
                        throw AuthenticationError.DomainAccessDenied(event.reason)
                    }
                    is Event.AuthenticationRequired -> {
                        throw AuthenticationError.AuthenticationFailed(
                            "Authentication required. Please sign in again.",
                            false
                        )
                    }
                    else -> {} // Continue checking
                }
            }

            // Check for success
            for (event in events) {
                if (event is Event.DomainAccessGranted) {
                    return@withContext event.access
                }
            }
        }

        throw AuthenticationError.MaxIterationsExceeded
    }

    /**
     * Execute actions returned by the client
     */
    private suspend fun executeActions(actions: List<Action>): List<Event> = withContext(Dispatchers.IO) {
        val events = mutableListOf<Event>()

        for (action in actions) {
            when (action) {
                is Action.HttpRequest -> {
                    try {
                        val url = URL(action.url)
                        val connection = url.openConnection() as HttpURLConnection
                        connection.requestMethod = action.method

                        // Set headers
                        for ((key, value) in action.headers) {
                            connection.setRequestProperty(key, value)
                        }

                        // Set body if present
                        action.body?.let { body ->
                            connection.doOutput = true
                            connection.outputStream.use { os ->
                                os.write(body.toByteArray())
                            }
                        }

                        val responseCode = connection.responseCode
                        val responseText = if (responseCode in 200..299) {
                            connection.inputStream.bufferedReader().use { it.readText() }
                        } else {
                            connection.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
                        }

                        val eventsJson = client.handleResponse(responseCode.toUShort(), responseText)
                        val responseEvents = parseEvents(eventsJson)
                        events.addAll(responseEvents)

                        // Check for events and trigger callbacks
                        for (event in responseEvents) {
                            when (event) {
                                is Event.NetworkTokenRefreshFailed -> {
                                    refreshFailedCallback?.invoke(
                                        RefreshFailureInfo(
                                            "network",
                                            event.reason,
                                            event.requiresReauth
                                        )
                                    )
                                }
                                is Event.DiscoveryAuthFailed -> {
                                    refreshFailedCallback?.invoke(
                                        RefreshFailureInfo(
                                            "discovery",
                                            event.reason,
                                            true
                                        )
                                    )
                                }
                                is Event.DomainAccessDenied -> {
                                    domainAccessDeniedCallback?.invoke(
                                        DomainAccessDeniedInfo(
                                            event.domainId,
                                            event.reason,
                                            extractStatusCode(event.reason)
                                        )
                                    )
                                }
                                else -> {} // No callback needed
                            }
                        }
                    } catch (e: IOException) {
                        throw AuthenticationError.NetworkError(e.message ?: "Unknown network error")
                    }
                }
                is Action.Wait -> {
                    delay(action.durationMs.toLong())
                }
            }
        }

        events
    }

    /**
     * Check if authenticated
     */
    fun isAuthenticated(): Boolean {
        return client.isAuthenticated(currentTimeMs())
    }

    /**
     * Get network token
     */
    fun getNetworkToken(): Token? {
        val json = client.networkToken() ?: return null
        // Parse JSON to Token - simplified, assumes JSON format
        // In production, use proper JSON parsing
        return parseToken(json)
    }

    /**
     * Get discovery token
     */
    fun getDiscoveryToken(): Token? {
        val json = client.discoveryToken() ?: return null
        return parseToken(json)
    }

    /**
     * Get cached domain access
     */
    fun getCachedDomainAccess(domainId: String): NativeDomainAccess? {
        val json = client.domainAccess(domainId) ?: return null
        return parseDomainAccess(json)
    }

    /**
     * Save state
     */
    fun saveState(): String {
        return client.saveState()
    }

    /**
     * Force reauth
     */
    fun forceReauth() {
        client.forceReauth()
    }

    /**
     * Validate state
     */
    fun validateState() {
        client.validateState(currentTimeMs())
    }

    // Helper functions for parsing JSON responses

    private fun parseActions(json: String): List<Action> {
        val jsonArray = Json.parseToJsonElement(json).jsonArray
        return jsonArray.map { element ->
            val obj = element.jsonObject
            val actionType = obj["type"]?.jsonPrimitive?.content
            when (actionType) {
                "HttpRequest" -> {
                    Action.HttpRequest(
                        url = obj["url"]?.jsonPrimitive?.content ?: "",
                        method = obj["method"]?.jsonPrimitive?.content ?: "",
                        headers = obj["headers"]?.jsonObject?.mapValues { it.value.jsonPrimitive.content } ?: emptyMap(),
                        body = obj["body"]?.jsonPrimitive?.contentOrNull
                    )
                }
                "Wait" -> {
                    Action.Wait(obj["duration_ms"]?.jsonPrimitive?.content?.toULong() ?: 0u)
                }
                else -> throw IllegalArgumentException("Unknown action type: $actionType")
            }
        }
    }

    private fun parseEvents(json: String): List<Event> {
        val jsonArray = Json.parseToJsonElement(json).jsonArray
        return jsonArray.map { element ->
            val obj = element.jsonObject
            val eventType = obj["type"]?.jsonPrimitive?.content
            when (eventType) {
                "NetworkAuthSuccess" -> Event.NetworkAuthSuccess(
                    obj["token"]?.jsonPrimitive?.content ?: "",
                    obj["expires_at"]?.jsonPrimitive?.content?.toULong() ?: 0u
                )
                "NetworkAuthFailed" -> Event.NetworkAuthFailed(
                    obj["reason"]?.jsonPrimitive?.content ?: "",
                    obj["retry_possible"]?.jsonPrimitive?.boolean ?: false
                )
                "NetworkTokenRefreshed" -> Event.NetworkTokenRefreshed(
                    obj["token"]?.jsonPrimitive?.content ?: "",
                    obj["expires_at"]?.jsonPrimitive?.content?.toULong() ?: 0u
                )
                "NetworkTokenRefreshFailed" -> Event.NetworkTokenRefreshFailed(
                    obj["reason"]?.jsonPrimitive?.content ?: "",
                    obj["requires_reauth"]?.jsonPrimitive?.boolean ?: false
                )
                "DiscoveryAuthSuccess" -> Event.DiscoveryAuthSuccess(
                    obj["token"]?.jsonPrimitive?.content ?: "",
                    obj["expires_at"]?.jsonPrimitive?.content?.toULong() ?: 0u
                )
                "DiscoveryAuthFailed" -> Event.DiscoveryAuthFailed(
                    obj["reason"]?.jsonPrimitive?.content ?: ""
                )
                "DomainAccessGranted" -> Event.DomainAccessGranted(
                    parseDomainAccessFromJson(obj["access"]?.jsonObject ?: JsonObject(emptyMap()))
                )
                "DomainAccessDenied" -> Event.DomainAccessDenied(
                    obj["domain_id"]?.jsonPrimitive?.content ?: "",
                    obj["reason"]?.jsonPrimitive?.content ?: ""
                )
                "AuthenticationRequired" -> Event.AuthenticationRequired
                "TokensInvalidated" -> Event.TokensInvalidated
                else -> throw IllegalArgumentException("Unknown event type: $eventType")
            }
        }
    }

    private fun parseToken(json: String): Token? {
        return try {
            val obj = Json.parseToJsonElement(json).jsonObject
            Token(
                token = obj["token"]?.jsonPrimitive?.content ?: return null,
                refreshToken = obj["refresh_token"]?.jsonPrimitive?.content ?: "",
                expiresAt = obj["expires_at"]?.jsonPrimitive?.content?.toULong() ?: 0u
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun parseDomainAccess(json: String): NativeDomainAccess {
        val obj = Json.parseToJsonElement(json).jsonObject
        return parseDomainAccessFromJson(obj)
    }

    private fun parseDomainAccessFromJson(obj: JsonObject): NativeDomainAccess {
        val serverObj = obj["domain_server"]?.jsonObject ?: JsonObject(emptyMap())
        return NativeDomainAccess(
            id = obj["id"]?.jsonPrimitive?.content ?: "",
            name = obj["name"]?.jsonPrimitive?.content ?: "",
            organizationId = obj["organization_id"]?.jsonPrimitive?.content ?: "",
            domainServerId = obj["domain_server_id"]?.jsonPrimitive?.content ?: "",
            accessToken = obj["access_token"]?.jsonPrimitive?.content ?: "",
            expiresAt = obj["expires_at"]?.jsonPrimitive?.content?.toULong() ?: 0u,
            ownerWalletAddress = obj["owner_wallet_address"]?.jsonPrimitive?.content ?: "",
            domainServer = NativeDomainServer(
                id = serverObj["id"]?.jsonPrimitive?.content ?: "",
                organizationId = serverObj["organization_id"]?.jsonPrimitive?.content ?: "",
                name = serverObj["name"]?.jsonPrimitive?.content ?: "",
                url = serverObj["url"]?.jsonPrimitive?.content ?: "",
                version = serverObj["version"]?.jsonPrimitive?.content ?: "",
                status = serverObj["status"]?.jsonPrimitive?.content ?: "",
                mode = serverObj["mode"]?.jsonPrimitive?.content ?: "",
                variants = serverObj["variants"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList(),
                ip = serverObj["ip"]?.jsonPrimitive?.content ?: "",
                latitude = serverObj["latitude"]?.jsonPrimitive?.doubleOrNull ?: 0.0,
                longitude = serverObj["longitude"]?.jsonPrimitive?.doubleOrNull ?: 0.0,
                cloudRegion = serverObj["cloud_region"]?.jsonPrimitive?.content ?: ""
            )
        )
    }

    private fun extractStatusCode(reason: String): Int {
        val regex = Regex("HTTP (\\d+):")
        val matchResult = regex.find(reason)
        return matchResult?.groupValues?.get(1)?.toIntOrNull() ?: 0
    }
}

// Sealed class for Actions
sealed class Action {
    data class HttpRequest(
        val url: String,
        val method: String,
        val headers: Map<String, String>,
        val body: String?
    ) : Action()

    data class Wait(val durationMs: ULong) : Action()
}

// Sealed class for Events
sealed class Event {
    data class NetworkAuthSuccess(val token: String, val expiresAt: ULong) : Event()
    data class NetworkAuthFailed(val reason: String, val retryPossible: Boolean) : Event()
    data class NetworkTokenRefreshed(val token: String, val expiresAt: ULong) : Event()
    data class NetworkTokenRefreshFailed(val reason: String, val requiresReauth: Boolean) : Event()
    data class DiscoveryAuthSuccess(val token: String, val expiresAt: ULong) : Event()
    data class DiscoveryAuthFailed(val reason: String) : Event()
    data class DomainAccessGranted(val access: NativeDomainAccess) : Event()
    data class DomainAccessDenied(val domainId: String, val reason: String) : Event()
    object AuthenticationRequired : Event()
    object TokensInvalidated : Event()
}
