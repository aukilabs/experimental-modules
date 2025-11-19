import Foundation
import ExpoModulesCore

// Type aliases for UniFFI-generated types (from authentication.swift compiled alongside this file)
public typealias Client = NativeClient
public typealias Config = NativeConfig
public typealias Credentials = NativeCredentials
public typealias DomainAccess = NativeDomainAccess
public typealias DomainServer = NativeDomainServer


/**
 * Token information
 */
public struct Token: Codable {
    public let token: String
    public let refreshToken: String
    public let expiresAt: UInt64

    enum CodingKeys: String, CodingKey {
        case token
        case refreshToken = "refresh_token"
        case expiresAt = "expires_at"
    }
}

/**
 * Codable representations for JSON decoding
 * These mirror the Rust types but support Codable
 */
private struct DomainServerJSON: Codable {
    let id: String
    let organizationId: String
    let name: String
    let url: String
    let version: String
    let status: String
    let mode: String
    let variants: [String]
    let ip: String
    let latitude: Double
    let longitude: Double
    let cloudRegion: String

    enum CodingKeys: String, CodingKey {
        case id, name, url, version, status, mode, variants, ip, latitude, longitude
        case organizationId = "organization_id"
        case cloudRegion = "cloud_region"
    }

    func toNative() -> DomainServer {
        return NativeDomainServer(
            id: id,
            organizationId: organizationId,
            name: name,
            url: url,
            version: version,
            status: status,
            mode: mode,
            variants: variants,
            ip: ip,
            latitude: latitude,
            longitude: longitude,
            cloudRegion: cloudRegion
        )
    }
}

private struct DomainAccessJSON: Codable {
    let id: String
    let name: String
    let organizationId: String
    let domainServerId: String
    let accessToken: String
    let expiresAt: UInt64
    let domainServer: DomainServerJSON
    let ownerWalletAddress: String

    enum CodingKeys: String, CodingKey {
        case id, name
        case organizationId = "organization_id"
        case domainServerId = "domain_server_id"
        case accessToken = "access_token"
        case expiresAt = "expires_at"
        case domainServer = "domain_server"
        case ownerWalletAddress = "owner_wallet_address"
    }

    func toNative() -> DomainAccess {
        return NativeDomainAccess(
            id: id,
            name: name,
            organizationId: organizationId,
            domainServerId: domainServerId,
            accessToken: accessToken,
            expiresAt: expiresAt,
            domainServer: domainServer.toNative(),
            ownerWalletAddress: ownerWalletAddress
        )
    }
}

/**
 * Actions that the client may return for execution
 */
public enum Action: Codable {
    case httpRequest(url: String, method: String, headers: [String: String], body: String?)
    case wait(durationMs: UInt64)

    enum CodingKeys: String, CodingKey {
        case type
    }

    public init(from decoder: Decoder) throws {
        enum ActionKeys: String, CodingKey {
            case type, url, method, headers, body, duration_ms
        }

        let container = try decoder.container(keyedBy: ActionKeys.self)
        let type = try container.decode(String.self, forKey: .type)

        switch type {
        case "HttpRequest":
            self = .httpRequest(
                url: try container.decode(String.self, forKey: .url),
                method: try container.decode(String.self, forKey: .method),
                headers: try container.decode([String: String].self, forKey: .headers),
                body: try container.decodeIfPresent(String.self, forKey: .body)
            )
        case "Wait":
            self = .wait(durationMs: try container.decode(UInt64.self, forKey: .duration_ms))
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: container, debugDescription: "Unknown action type: \(type)")
        }
    }

    public func encode(to encoder: Encoder) throws {
        // Not needed for our use case
    }
}

/**
 * Events emitted by the client after processing responses
 */
public enum Event: Codable {
    case networkAuthSuccess(token: String, expiresAt: UInt64)
    case networkAuthFailed(reason: String, retryPossible: Bool)
    case networkTokenRefreshed(token: String, expiresAt: UInt64)
    case networkTokenRefreshFailed(reason: String, requiresReauth: Bool)
    case discoveryAuthSuccess(token: String, expiresAt: UInt64)
    case discoveryAuthFailed(reason: String)
    case domainAccessGranted(access: DomainAccess)
    case domainAccessDenied(domainId: String, reason: String)
    case authenticationRequired
    case tokensInvalidated

    enum CodingKeys: String, CodingKey {
        case type
    }

    public init(from decoder: Decoder) throws {
        enum EventKeys: String, CodingKey {
            case type, token, expires_at, reason, retry_possible, requires_reauth
            case domain_id, domain_access, domain
        }

        let container = try decoder.container(keyedBy: EventKeys.self)
        let type = try container.decode(String.self, forKey: .type)

        switch type {
        case "NetworkAuthSuccess":
            self = .networkAuthSuccess(
                token: try container.decode(String.self, forKey: .token),
                expiresAt: try container.decode(UInt64.self, forKey: .expires_at)
            )
        case "NetworkAuthFailed":
            self = .networkAuthFailed(
                reason: try container.decode(String.self, forKey: .reason),
                retryPossible: try container.decode(Bool.self, forKey: .retry_possible)
            )
        case "NetworkTokenRefreshed":
            self = .networkTokenRefreshed(
                token: try container.decode(String.self, forKey: .token),
                expiresAt: try container.decode(UInt64.self, forKey: .expires_at)
            )
        case "NetworkTokenRefreshFailed":
            self = .networkTokenRefreshFailed(
                reason: try container.decode(String.self, forKey: .reason),
                requiresReauth: try container.decode(Bool.self, forKey: .requires_reauth)
            )
        case "DiscoveryAuthSuccess":
            self = .discoveryAuthSuccess(
                token: try container.decode(String.self, forKey: .token),
                expiresAt: try container.decode(UInt64.self, forKey: .expires_at)
            )
        case "DiscoveryAuthFailed":
            self = .discoveryAuthFailed(
                reason: try container.decode(String.self, forKey: .reason)
            )
        case "DomainAccessGranted":
            let accessJSON = try container.decode(DomainAccessJSON.self, forKey: .domain)
            self = .domainAccessGranted(
                access: accessJSON.toNative()
            )
        case "DomainAccessDenied":
            self = .domainAccessDenied(
                domainId: try container.decode(String.self, forKey: .domain_id),
                reason: try container.decode(String.self, forKey: .reason)
            )
        case "AuthenticationRequired":
            self = .authenticationRequired
        case "TokensInvalidated":
            self = .tokensInvalidated
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: container, debugDescription: "Unknown event type: \(type)")
        }
    }

    public func encode(to encoder: Encoder) throws {
        // Not needed for our use case
    }
}

// Helper for decoding heterogeneous JSON
private struct AnyCodable: Codable {
    let value: Any

    init(_ value: Any) {
        self.value = value
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let int = try? container.decode(Int.self) {
            value = int
        } else if let uint = try? container.decode(UInt64.self) {
            value = uint
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let string = try? container.decode(String.self) {
            value = string
        } else if let array = try? container.decode([AnyCodable].self) {
            value = array.map { $0.value }
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            value = dict.mapValues { $0.value }
        } else {
            value = NSNull()
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case let bool as Bool:
            try container.encode(bool)
        case let int as Int:
            try container.encode(int)
        case let uint as UInt64:
            try container.encode(uint)
        case let double as Double:
            try container.encode(double)
        case let string as String:
            try container.encode(string)
        default:
            try container.encodeNil()
        }
    }

    var stringValue: String? { value as? String }
    var intValue: Int? { value as? Int }
    var uint64Value: UInt64? { value as? UInt64 }
    var boolValue: Bool? { value as? Bool }
    var dictValue: Any? { value as? [String: Any] }
}

/**
 * Token refresh failure information
 */
public struct RefreshFailureInfo {
    public let tokenType: String  // "network" or "discovery"
    public let reason: String
    public let requiresReauth: Bool
}

/**
 * Domain access denied information
 */
public struct DomainAccessDeniedInfo {
    public let domainId: String
    public let reason: String
    public let statusCode: Int
}

/**
 * Swift wrapper for the Auki Authentication client
 * Provides a high-level async API similar to the JavaScript client
 */
public class AuthenticationClient: @unchecked Sendable {
    private let client: Client
    public var refreshFailedCallback: ((RefreshFailureInfo) -> Void)?
    public var domainAccessDeniedCallback: ((DomainAccessDeniedInfo) -> Void)?

    /// Create a new authentication client with only configuration
    /// Credentials are provided later when calling authenticateWith()
    public init(config: Config) {
        self.client = Client(config: config)
    }

    /// Create a client from saved state
    public static func fromState(stateJson: String, config: Config) throws -> AuthenticationClient {
        let client = try Client.fromState(stateJson: stateJson, config: config)
        return AuthenticationClient(client: client)
    }

    private init(client: Client) {
        self.client = client
    }

    /// Set credentials (useful after restoring from state or to change credentials)
    public func setCredentials(_ credentials: Credentials) {
        self.client.setCredentials(credentials: credentials)
    }

    /**
     * Helper to parse JSON string to [Action]
     */
    private func parseActions(_ json: String) throws -> [Action] {
        print("[AuthenticationClient] Parsing actions JSON: \(json)")
        guard let data = json.data(using: .utf8) else {
            throw AuthenticationError.networkError("Failed to convert JSON string to data")
        }
        do {
            let actions = try JSONDecoder().decode([Action].self, from: data)
            print("[AuthenticationClient] Successfully parsed \(actions.count) actions")
            return actions
        } catch {
            print("[AuthenticationClient] Failed to parse actions: \(error)")
            throw AuthenticationError.networkError("Failed to parse actions: \(error.localizedDescription)")
        }
    }

    /**
     * Helper to parse JSON string to [Event]
     */
    private func parseEvents(_ json: String) throws -> [Event] {
        guard let data = json.data(using: .utf8) else {
            throw AuthenticationError.networkError("Failed to convert JSON string to data")
        }
        return try JSONDecoder().decode([Event].self, from: data)
    }

    /**
     * Authenticate with specific credentials
     * This will clear all existing tokens and authenticate as a new user
     */
    public func authenticateWith(credentials: Credentials) async throws -> Token {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let now = currentTimeMs()
                    let actionsJson = try self.client.authenticateWith(credentials: credentials, nowMs: now)
                    let actions = try self.parseActions(actionsJson)

                    Task {
                        do {
                            let events = try await self.executeActions(actions: actions)

                            for event in events {
                                switch event {
                                case .networkAuthSuccess(_, _):
                                    // Get the full network token including refresh token from client state
                                    if let networkToken = self.getNetworkToken() {
                                        continuation.resume(returning: networkToken)
                                    } else {
                                        continuation.resume(throwing: AuthenticationError.authenticationFailed(
                                            reason: "Failed to retrieve network token after successful authentication",
                                            retryable: false
                                        ))
                                    }
                                    return
                                case .networkAuthFailed(let reason, let retryPossible):
                                    continuation.resume(throwing: AuthenticationError.authenticationFailed(
                                        reason: reason,
                                        retryable: retryPossible
                                    ))
                                    return
                                default:
                                    break
                                }
                            }

                            // For AppKey and Opaque credentials, there are no HTTP actions/events
                            // The token is set directly in the core. Check if we have a valid token now.
                            if actions.isEmpty {
                                if let networkToken = self.getNetworkToken() {
                                    continuation.resume(returning: networkToken)
                                    return
                                }
                            }

                            continuation.resume(throwing: AuthenticationError.noResponse)
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    }
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /**
     * Switch to a different user by providing new credentials
     * This is an alias for authenticateWith() that makes the intent clearer
     */
    public func switchUser(credentials: Credentials) async throws -> Token {
        return try await authenticateWith(credentials: credentials)
    }

    /**
     * Authenticate to the Auki network using stored credentials
     */
    public func authenticate() async throws -> Token {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let now = currentTimeMs()
                    let actionsJson = try self.client.authenticate(nowMs: now)
                    let actions = try self.parseActions(actionsJson)

                    Task {
                        do {
                            let events = try await self.executeActions(actions: actions)

                            for event in events {
                                switch event {
                                case .networkAuthSuccess(let token, let expiresAt):
                                    continuation.resume(returning: Token(token: token, refreshToken: "", expiresAt: expiresAt))
                                    return
                                case .networkAuthFailed(let reason, let retryPossible):
                                    continuation.resume(throwing: AuthenticationError.authenticationFailed(
                                        reason: reason,
                                        retryable: retryPossible
                                    ))
                                    return
                                default:
                                    break
                                }
                            }

                            continuation.resume(throwing: AuthenticationError.noResponse)
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    }
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /**
     * Authenticate to the Discovery service
     */
    public func authenticateDiscovery() async throws -> Token {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let now = currentTimeMs()
                    let actionsJson = try self.client.authenticateDiscovery(nowMs: now)
                    let actions = try self.parseActions(actionsJson)

                    Task {
                        do {
                            let events = try await self.executeActions(actions: actions)

                            for event in events {
                                switch event {
                                case .discoveryAuthSuccess(let token, let expiresAt):
                                    continuation.resume(returning: Token(token: token, refreshToken: "", expiresAt: expiresAt))
                                    return
                                case .discoveryAuthFailed(let reason):
                                    continuation.resume(throwing: AuthenticationError.authenticationFailed(
                                        reason: reason,
                                        retryable: false
                                    ))
                                    return
                                default:
                                    break
                                }
                            }

                            continuation.resume(throwing: AuthenticationError.noResponse)
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    }
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /**
     * Get access to a specific domain
     * Automatically handles the full authentication chain if needed
     */
    public func getDomainAccess(domainId: String) async throws -> DomainAccess {
        print("[AuthenticationClient] Getting domain access for domain ID: '\(domainId)'")
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                Task {
                    do {
                        let maxIterations = 10

                        for _ in 0..<maxIterations {
                            let now = currentTimeMs()
                            let actionsJson = try self.client.getDomainAccess(domainId: domainId, nowMs: now)
                            let actions = try self.parseActions(actionsJson)

                            // If no actions, check for cached access
                            if actions.isEmpty {
                                if let cachedJson = try self.client.domainAccess(domainId: domainId),
                                   let data = cachedJson.data(using: .utf8) {
                                    let cachedJSON = try JSONDecoder().decode(DomainAccessJSON.self, from: data)
                                    continuation.resume(returning: cachedJSON.toNative())
                                    return
                                }
                                // If we're authenticated (e.g., Opaque/AppKey credentials were just set),
                                // continue the loop to let the core progress to the next step
                                if self.isAuthenticated() {
                                    continue
                                }
                                // No cached access, no actions, and not authenticated means we need credentials
                                // (tokens are expired and we have no refresh token or credentials to re-authenticate)
                                continuation.resume(throwing: AuthenticationError.authenticationFailed(
                                    reason: "Authentication required. Please sign in again.",
                                    retryable: false
                                ))
                                return
                            }

                            let events = try await self.executeActions(actions: actions)

                            // Check for failures
                            for event in events {
                                switch event {
                                case .networkAuthFailed(let reason, let retryPossible):
                                    continuation.resume(throwing: AuthenticationError.authenticationFailed(
                                        reason: reason,
                                        retryable: retryPossible
                                    ))
                                    return
                                case .discoveryAuthFailed(let reason):
                                    continuation.resume(throwing: AuthenticationError.authenticationFailed(
                                        reason: "Discovery: \(reason)",
                                        retryable: false
                                    ))
                                    return
                                case .domainAccessDenied(let _, let reason):
                                    continuation.resume(throwing: AuthenticationError.domainAccessDenied(reason: reason))
                                    return
                                case .authenticationRequired:
                                    // Stop iteration and throw error - user needs to sign in again
                                    continuation.resume(throwing: AuthenticationError.authenticationFailed(
                                        reason: "Authentication required. Please sign in again.",
                                        retryable: false
                                    ))
                                    return
                                default:
                                    break
                                }
                            }

                            // Check for success
                            for event in events {
                                if case .domainAccessGranted(let access) = event {
                                    continuation.resume(returning: access)
                                    return
                                }
                            }
                        }

                        continuation.resume(throwing: AuthenticationError.maxIterationsExceeded)
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        }
    }

    /**
     * Execute actions returned by the client
     */
    private func executeActions(actions: [Action]) async throws -> [Event] {
        var events: [Event] = []

        for action in actions {
            switch action {
            case .httpRequest(let url, let method, let headers, let body):
                do {
                    print("[AuthenticationClient] HTTP Request: \(method) \(url)")
                    if let body = body {
                        print("[AuthenticationClient] Request body: \(body)")
                    }

                    var request = URLRequest(url: URL(string: url)!)
                    request.httpMethod = method

                    for (key, value) in headers {
                        request.setValue(value, forHTTPHeaderField: key)
                    }

                    if let body = body {
                        request.httpBody = body.data(using: String.Encoding.utf8)
                    }

                    let (data, response) = try await URLSession.shared.data(for: request)
                    let httpResponse = response as! HTTPURLResponse
                    let responseText = String(data: data, encoding: .utf8) ?? ""

                    print("[AuthenticationClient] HTTP Response: \(httpResponse.statusCode)")
                    print("[AuthenticationClient] Response body: \(responseText)")

                    let eventsJson = try client.handleResponse(
                        status: UInt16(httpResponse.statusCode),
                        body: responseText
                    )
                    print("[AuthenticationClient] Events JSON: \(eventsJson)")
                    let responseEvents = try self.parseEvents(eventsJson)
                    events.append(contentsOf: responseEvents)

                    // Check for events and trigger callbacks
                    for event in responseEvents {
                        switch event {
                        case .networkTokenRefreshFailed(let reason, let requiresReauth):
                            if let callback = refreshFailedCallback {
                                callback(RefreshFailureInfo(
                                    tokenType: "network",
                                    reason: reason,
                                    requiresReauth: requiresReauth
                                ))
                            }
                        case .discoveryAuthFailed(let reason):
                            if let callback = refreshFailedCallback {
                                callback(RefreshFailureInfo(
                                    tokenType: "discovery",
                                    reason: reason,
                                    requiresReauth: true
                                ))
                            }
                        case .domainAccessDenied(let domainId, let reason):
                            if let callback = domainAccessDeniedCallback {
                                // Extract status code from reason (format: "HTTP XXX: ...")
                                let statusCode = extractStatusCode(from: reason)
                                callback(DomainAccessDeniedInfo(
                                    domainId: domainId,
                                    reason: reason,
                                    statusCode: statusCode
                                ))
                            }
                        default:
                            break
                        }
                    }
                } catch {
                    throw AuthenticationError.networkError(error.localizedDescription)
                }

            case .wait(let durationMs):
                try await Task.sleep(nanoseconds: UInt64(durationMs) * 1_000_000)
            }
        }

        return events
    }

    /**
     * Check if the client is authenticated
     */
    public func isAuthenticated() -> Bool {
        return client.isAuthenticated(nowMs: currentTimeMs())
    }

    /**
     * Get the network token if available
     */
    public func getNetworkToken() -> Token? {
        guard let json = try? client.networkToken(),
              let data = json.data(using: .utf8) else {
            return nil
        }
        return try? JSONDecoder().decode(Token.self, from: data)
    }

    /**
     * Get the discovery token if available
     */
    public func getDiscoveryToken() -> Token? {
        guard let json = try? client.discoveryToken(),
              let data = json.data(using: .utf8) else {
            return nil
        }
        return try? JSONDecoder().decode(Token.self, from: data)
    }

    /**
     * Get cached domain access
     */
    public func getCachedDomainAccess(domainId: String) -> DomainAccess? {
        guard let json = try? client.domainAccess(domainId: domainId),
              let data = json.data(using: .utf8),
              let accessJSON = try? JSONDecoder().decode(DomainAccessJSON.self, from: data) else {
            return nil
        }
        return accessJSON.toNative()
    }

    /**
     * Save state to JSON
     */
    public func saveState() -> String {
        return try! client.saveState()
    }

    /**
     * Force re-authentication
     */
    public func forceReauth() {
        _ = try! client.forceReauth()
    }

    /**
     * Validate state after loading
     */
    public func validateState() {
        _ = try! client.validateState(nowMs: currentTimeMs())
    }

    /**
     * Extract HTTP status code from error reason string
     * Format: "HTTP XXX: ..."
     */
    private func extractStatusCode(from reason: String) -> Int {
        if let range = reason.range(of: "HTTP (\\d+):", options: .regularExpression),
           let statusStr = reason[range].split(separator: " ").dropFirst().first?.dropLast(),
           let status = Int(statusStr) {
            return status
        }
        return 0
    }
}

/**
 * Authentication errors
 */
public enum AuthenticationError: Error, LocalizedError {
    case authenticationFailed(reason: String, retryable: Bool)
    case domainAccessDenied(reason: String)
    case networkError(String)
    case noResponse
    case noCachedAccess
    case maxIterationsExceeded

    public var errorDescription: String? {
        switch self {
        case .authenticationFailed(let reason, _):
            return "Authentication failed: \(reason)"
        case .domainAccessDenied(let reason):
            return "Domain access denied: \(reason)"
        case .networkError(let message):
            return "Network error: \(message)"
        case .noResponse:
            return "No response from server"
        case .noCachedAccess:
            return "No cached access available"
        case .maxIterationsExceeded:
            return "Maximum iterations exceeded"
        }
    }
}
